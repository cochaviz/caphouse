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
	"github.com/spf13/cobra/doc"
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
		Long: `caphouse stores and exports classic PCAP files in ClickHouse.

Instead of writing raw frames to disk, it parses each packet into its protocol
layers and stores each layer in its own ClickHouse table. This makes packet data
queryable at the column level while still allowing lossless PCAP reconstruction.

Modes:
  -r (default)  Read a PCAP file or stream and ingest it into ClickHouse.
  -w         	Export a stored capture back as a PCAP file or stream.

The DSN must use the native ClickHouse protocol (clickhouse://host:9000/db).
HTTP connections are not supported.`,
		Example: `  # Ingest a file (new capture; UUID printed on completion)
  caphouse --dsn="clickhouse://user:pass@localhost:9000/db" --sensor=myhost --file=capture.pcap

  # Append packets to an existing capture
  caphouse --dsn="clickhouse://user:pass@localhost:9000/db" --sensor=myhost --file=more.pcap --capture=<uuid>

  # Pipe from tcpdump
  tcpdump -i eth0 -w - | caphouse --dsn="clickhouse://user:pass@localhost:9000/db" --sensor=myhost

  # Export to a file
  caphouse -w --dsn="clickhouse://user:pass@localhost:9000/db" --capture=<uuid> --file=out.pcap

  # Stream into tcpreplay
  caphouse -w --dsn="clickhouse://user:pass@localhost:9000/db" --capture=<uuid> | tcpreplay --intf1=eth0 -`,
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

	cmd.Flags().StringVar(&dsn, "dsn", "", "ClickHouse DSN, e.g. clickhouse://user:pass@host:9000/db (or CAPHOUSE_DSN)")
	cmd.Flags().StringVar(&database, "db", "", "ClickHouse database; falls back to the database in the DSN (or CAPHOUSE_DB, CAPHOUSE_DATABASE)")
	cmd.Flags().IntVar(&batchSize, "batch-size", 0, "packets per ClickHouse batch insert")
	cmd.Flags().DurationVar(&flushInterval, "flush-interval", 0, "maximum time between batch flushes")
	cmd.Flags().BoolVar(&debug, "debug", false, "enable verbose ClickHouse driver logging to stderr")

	cmd.Flags().BoolVarP(&readMode, "read", "r", false, "ingest PCAP from file or stdin into ClickHouse (default mode)")
	cmd.Flags().BoolVarP(&writeMode, "write", "w", false, "export a stored capture from ClickHouse as a PCAP file or stream")
	cmd.Flags().StringVar(&filePath, "file", "-", "input/output file path; - for stdin/stdout")
	cmd.Flags().StringVar(&capture, "capture", "", "capture UUID; omit or 'new' in read mode to create a new capture, required in write mode")
	cmd.Flags().StringVar(&sensor, "sensor", "", "sensor name attached to the capture, required in read mode (or CAPHOUSE_SENSOR)")

	cmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		if err == nil {
			return nil
		}
		_ = cmd.Usage()
		return err
	})

	cmd.AddCommand(&cobra.Command{
		Use:    "gen-man [directory]",
		Short:  "Generate man page into directory",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := os.MkdirAll(args[0], 0o755); err != nil {
				return err
			}
			header := &doc.GenManHeader{Title: "CAPHOUSE", Section: "1"}
			return doc.GenManTree(cmd, header, args[0])
		},
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
