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
	var readMode bool
	var writeMode bool
	var filePath string
	var capture string
	var sensor string
	var debug bool

	cmd := &cobra.Command{
		Use:   "caphouse",
		Short: "Store and export classic PCAPs in ClickHouse",
		Example: `  caphouse --dsn="clickhouse://user:pass@localhost:9000/default" --file capture.pcap --sensor test
  caphouse -w --dsn="clickhouse://user:pass@localhost:9000/default" --capture <uuid> --file out.pcap
  tcpdump -i en0 -w - | caphouse --dsn="clickhouse://user:pass@localhost:9000/default" --sensor test
  caphouse -w --dsn="clickhouse://user:pass@localhost:9000/default" --capture <uuid> | tcpreplay --intf1=en0 -`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			if readMode && writeMode {
				return errors.New("--read and --write are mutually exclusive")
			}
			mode := "read"
			if writeMode {
				mode = "write"
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

	cmd.Flags().BoolVarP(&readMode, "read", "r", false, "read PCAP from file/stdin and write into ClickHouse (default)")
	cmd.Flags().BoolVarP(&writeMode, "write", "w", false, "read from ClickHouse and write PCAP to file/stdout")
	cmd.Flags().StringVar(&filePath, "file", "-", "file path for read/write, or - for stdin/stdout")
	cmd.Flags().StringVar(&capture, "capture", "", "capture UUID or 'new' for read; required for write")
	cmd.Flags().StringVar(&sensor, "sensor", "", "sensor identifier (or CAPHOUSE_SENSOR) for read")

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
