package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"caphouse"
	"caphouse/components"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var dsn string
	var database string
	var batchSize int
	var flushInterval time.Duration
	var mode string
	var filePath string
	var capture string
	var sensor string
	var debug bool
	var ifaceName string
	var bpf string
	var snaplen int
	var promisc bool
	var timeout time.Duration
	var duration time.Duration

	cmd := &cobra.Command{
		Use:   "caphouse",
		Short: "Store and export classic PCAPs in ClickHouse",
		Example: `  caphouse --mode=read --dsn="clickhouse://user:pass@localhost:9000/default" --file capture.pcap
  caphouse --mode=write --dsn="clickhouse://user:pass@localhost:9000/default" --capture <uuid> --file out.pcap
  tcpdump -i en0 -w - | caphouse --mode=read --dsn="clickhouse://user:pass@localhost:9000/default" --sensor test --capture new
  caphouse --mode=write --dsn="clickhouse://user:pass@localhost:9000/default" --capture <uuid> | tcpreplay --intf1=en0 -`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			if mode == "" {
				mode = "read"
			}

			effectiveDSN := firstNonEmpty(dsn, os.Getenv("CAPHOUSE_DSN"))
			if effectiveDSN == "" {
				return errors.New("dsn is required (flag --dsn or env CAPHOUSE_DSN)")
			}
			effectiveDB := firstNonEmpty(database, os.Getenv("CAPHOUSE_DB"), os.Getenv("CAPHOUSE_DATABASE"))
			effectiveSensor := firstNonEmpty(sensor, os.Getenv("CAPHOUSE_SENSOR"))

			client, err := newClient(ctx, effectiveDSN, effectiveDB, batchSize, flushInterval, debug)
			if err != nil {
				return err
			}
			defer client.Close()

			switch mode {
			case "read":
				if effectiveSensor == "" {
					return errors.New("sensor is required (flag --sensor or env CAPHOUSE_SENSOR)")
				}
				if err := client.InitSchema(ctx); err != nil {
					return err
				}

				captureID, isNew, err := parseCaptureID(capture, true)
				if err != nil {
					return err
				}

				if ifaceName != "" {
					if filePath != "" && filePath != "-" {
						return errors.New("--iface cannot be combined with --file for read")
					}
					if err := ingestFromInterface(ctx, client, captureID, effectiveSensor, ifaceName, bpf, snaplen, promisc, timeout, duration); err != nil {
						return err
					}
					if isNew {
						fmt.Fprintf(cmd.OutOrStdout(), "capture_id=%s\n", captureID)
					}
					return nil
				}

				src := io.Reader(os.Stdin)
				if filePath != "" && filePath != "-" {
					f, err := os.Open(filePath)
					if err != nil {
						return fmt.Errorf("open pcap: %w", err)
					}
					defer f.Close()
					src = f
				}

				id, err := ingestPCAPStream(ctx, client, src, captureID, effectiveSensor)
				if err != nil {
					return err
				}
				if isNew {
					fmt.Fprintf(cmd.OutOrStdout(), "capture_id=%s\n", id)
				}
				return nil

			case "write":
				captureID, _, err := parseCaptureID(capture, false)
				if err != nil {
					return err
				}

				rc, err := client.ExportCapture(ctx, captureID)
				if err != nil {
					return err
				}
				defer rc.Close()

				out := io.Writer(cmd.OutOrStdout())
				if filePath != "" && filePath != "-" {
					f, err := os.Create(filePath)
					if err != nil {
						return fmt.Errorf("create output: %w", err)
					}
					defer f.Close()
					out = f
				}

				_, err = io.Copy(out, rc)
				return err
			default:
				return fmt.Errorf("unknown mode %q", mode)
			}
		},
	}

	cmd.Flags().StringVar(&dsn, "dsn", "", "clickhouse DSN or host:port (or CAPHOUSE_DSN, required)")
	cmd.Flags().StringVar(&database, "db", "", "clickhouse database (or CAPHOUSE_DB/CAPHOUSE_DATABASE)")
	cmd.Flags().IntVar(&batchSize, "batch-size", 0, "packets per batch insert")
	cmd.Flags().DurationVar(&flushInterval, "flush-interval", 0, "batch flush interval")
	cmd.Flags().BoolVar(&debug, "debug", false, "enable ClickHouse driver debug logging")

	cmd.Flags().StringVar(&mode, "mode", "read", "mode: read or write")
	cmd.Flags().StringVar(&filePath, "file", "-", "file path for read/write, or - for stdin/stdout")
	cmd.Flags().StringVar(&capture, "capture", "", "capture UUID or 'new' for read; required for write")
	cmd.Flags().StringVar(&sensor, "sensor", "", "sensor identifier (or CAPHOUSE_SENSOR) for read")

	cmd.Flags().StringVar(&ifaceName, "iface", "", "optional interface name for live capture")
	cmd.Flags().StringVar(&bpf, "bpf", "", "optional BPF filter for live capture")
	cmd.Flags().IntVar(&snaplen, "snaplen", 65535, "capture snaplen for live capture")
	cmd.Flags().BoolVar(&promisc, "promisc", false, "enable promiscuous mode for live capture")
	cmd.Flags().DurationVar(&timeout, "timeout", time.Second, "read timeout for live capture")
	cmd.Flags().DurationVar(&duration, "duration", 0, "duration for live capture (0 = until interrupted)")

	cmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		if err == nil {
			return nil
		}
		_ = cmd.Usage()
		return err
	})

	return cmd
}

func ingestPCAPStream(ctx context.Context, client *caphouse.Client, r io.Reader, captureID uuid.UUID, sensor string) (uuid.UUID, error) {
	br := bufio.NewReader(r)
	header := make([]byte, 24)
	if _, err := io.ReadFull(br, header); err != nil {
		return uuid.Nil, fmt.Errorf("read pcap header: %w", err)
	}

	meta, err := caphouse.ParseGlobalHeader(header)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse pcap header: %w", err)
	}
	meta.CaptureID = captureID
	meta.SensorID = sensor
	meta.CreatedAt = time.Now()
	meta.GlobalHeaderRaw = header
	meta.CodecVersion = components.CodecVersionV1
	meta.CodecProfile = components.CodecProfileV1

	capID, err := client.CreateCapture(ctx, meta)
	if err != nil {
		return uuid.Nil, err
	}

	reader, err := pcapgo.NewReader(io.MultiReader(bytes.NewReader(header), br))
	if err != nil {
		return uuid.Nil, fmt.Errorf("pcap reader: %w", err)
	}

	var packetID uint64
	for {
		data, ci, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return uuid.Nil, fmt.Errorf("read packet: %w", err)
		}

		packet := caphouse.Packet{
			CaptureID: capID,
			PacketID:  packetID,
			Timestamp: ci.Timestamp,
			InclLen:   uint32(ci.CaptureLength),
			OrigLen:   uint32(ci.Length),
			Frame:     data,
		}
		if err := client.IngestPacket(ctx, meta.LinkType, packet); err != nil {
			return uuid.Nil, err
		}
		packetID++
	}

	if err := client.Flush(ctx); err != nil {
		return uuid.Nil, err
	}

	return capID, nil
}

func ingestFromInterface(ctx context.Context, client *caphouse.Client, captureID uuid.UUID, sensor string, ifaceName string, bpf string, snaplen int, promisc bool, timeout time.Duration, duration time.Duration) error {
	handle, err := pcap.OpenLive(ifaceName, int32(snaplen), promisc, timeout)
	if err != nil {
		return fmt.Errorf("open interface: %w", err)
	}
	defer handle.Close()

	if bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			return fmt.Errorf("apply bpf: %w", err)
		}
	}

	meta := caphouse.CaptureMeta{
		CaptureID:      captureID,
		SensorID:       sensor,
		CreatedAt:      time.Now(),
		Snaplen:        uint32(handle.SnapLen()),
		LinkType:       uint32(handle.LinkType()),
		Endianness:     "le",
		TimeResolution: "us",
		CodecVersion:   components.CodecVersionV1,
		CodecProfile:   components.CodecProfileV1,
	}

	if _, err := client.CreateCapture(ctx, meta); err != nil {
		return err
	}

	deadline := time.Time{}
	if duration > 0 {
		deadline = time.Now().Add(duration)
	}

	var packetID uint64
	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}

		data, ci, err := handle.ReadPacketData()
		if errors.Is(err, pcap.NextErrorTimeoutExpired) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read packet: %w", err)
		}

		packet := caphouse.Packet{
			CaptureID: captureID,
			PacketID:  packetID,
			Timestamp: ci.Timestamp,
			InclLen:   uint32(ci.CaptureLength),
			OrigLen:   uint32(ci.Length),
			Frame:     data,
		}
		if err := client.IngestPacket(ctx, meta.LinkType, packet); err != nil {
			return err
		}
		packetID++
	}

	return client.Flush(ctx)
}

func newClient(ctx context.Context, dsn, database string, batchSize int, flushInterval time.Duration, debug bool) (*caphouse.Client, error) {
	if dsn == "" {
		return nil, errors.New("dsn is required")
	}
	cfg := caphouse.Config{
		DSN:           dsn,
		Database:      database,
		BatchSize:     batchSize,
		FlushInterval: flushInterval,
		Debug:         debug,
	}
	return caphouse.New(ctx, cfg)
}

func parseCaptureID(input string, allowNew bool) (uuid.UUID, bool, error) {
	if input == "" || input == "new" {
		if !allowNew {
			return uuid.Nil, false, errors.New("capture id is required")
		}
		return uuid.New(), true, nil
	}
	id, err := uuid.Parse(input)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("invalid capture id: %w", err)
	}
	return id, false, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
