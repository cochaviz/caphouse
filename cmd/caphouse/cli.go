package main

import (
	_ "embed"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"caphouse"
	"caphouse/components"

	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

//go:embed description.txt
var longDescription string

// config holds all resolved flag/env values for a single invocation.
type config struct {
	dsn           string
	database      string
	batchSize     int
	flushInterval time.Duration
	filePath      string
	capture       string
	sensor        string
	debug         bool
	silent        bool
}

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
	var silent bool

	cmd := &cobra.Command{
		Use:          "caphouse",
		Short:        "Store and export classic PCAPs in ClickHouse",
		Long:         longDescription,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if readMode && writeMode {
				return errors.New("--read and --write are mutually exclusive")
			}
			cfg := config{
				dsn:           firstNonEmpty(dsn, os.Getenv("CAPHOUSE_DSN")),
				database:      firstNonEmpty(database, os.Getenv("CAPHOUSE_DB"), os.Getenv("CAPHOUSE_DATABASE")),
				sensor:        firstNonEmpty(sensor, os.Getenv("CAPHOUSE_SENSOR")),
				filePath:      filePath,
				capture:       capture,
				batchSize:     batchSize,
				flushInterval: flushInterval,
				debug:         debug,
				silent:        silent,
			}
			if cfg.dsn == "" {
				return errors.New("dsn is required (flag --dsn or env CAPHOUSE_DSN)")
			}
			if writeMode {
				return runWrite(cmd, cfg)
			}
			return runRead(cmd, cfg)
		},
	}

	cmd.Flags().StringVar(&dsn, "dsn", "", "ClickHouse DSN, e.g. clickhouse://user:pass@host:9000/db (or CAPHOUSE_DSN)")
	cmd.Flags().StringVar(&database, "db", "", "ClickHouse database; falls back to the database in the DSN (or CAPHOUSE_DB, CAPHOUSE_DATABASE)")
	cmd.Flags().IntVar(&batchSize, "batch-size", 0, "packets per ClickHouse batch insert")
	cmd.Flags().DurationVar(&flushInterval, "flush-interval", 0, "maximum time between batch flushes")
	cmd.Flags().BoolVar(&debug, "debug", false, "enable verbose ClickHouse driver logging to stderr")
	cmd.Flags().BoolVarP(&silent, "silent", "s", false, "suppress warnings and progress output")

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

func runRead(cmd *cobra.Command, cfg config) error {
	if cfg.sensor == "" {
		return errors.New("sensor is required (flag --sensor or env CAPHOUSE_SENSOR)")
	}

	ctx := context.Background()
	logger := newLogger(cfg.debug, cfg.silent)

	client, err := newClient(ctx, cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.InitSchema(ctx); err != nil {
		return err
	}

	captureID, isNew, err := parseCaptureID(cfg.capture, true)
	if err != nil {
		return err
	}

	src, fileSize, captureID, err := openSource(cfg.filePath, captureID, isNew, logger)
	if err != nil {
		return err
	}
	if closer, ok := src.(io.Closer); ok {
		defer closer.Close()
	}

	var p ingestProgress
	cr := &countingReader{r: src, p: &p}

	srcLabel := cfg.filePath
	if srcLabel == "" || srcLabel == "-" {
		srcLabel = "stdin"
	}
	logger.Info("ingesting", "source", srcLabel, "sensor", cfg.sensor)

	start := time.Now()
	stopBar := startProgressBar(fileSize, &p, start, cfg.silent)

	id, err := ingestPCAPStream(ctx, client, cr, captureID, cfg.sensor, &p)
	stopBar()

	if err != nil {
		return err
	}

	logger.Info("done",
		"capture_id", id,
		"packets", p.packets.Load(),
		"bytes", p.bytesRead.Load(),
		"elapsed", time.Since(start).Truncate(time.Millisecond),
	)

	if isNew {
		fmt.Fprintf(cmd.OutOrStdout(), "capture_id=%s\n", id)
	}
	return nil
}

func runWrite(cmd *cobra.Command, cfg config) error {
	captureID, _, err := parseCaptureID(cfg.capture, false)
	if err != nil {
		return err
	}

	ctx := context.Background()

	client, err := newClient(ctx, cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	rc, err := client.ExportCapture(ctx, captureID)
	if err != nil {
		return err
	}
	defer rc.Close()

	out := io.Writer(cmd.OutOrStdout())
	if cfg.filePath != "" && cfg.filePath != "-" {
		f, err := os.Create(cfg.filePath)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer f.Close()
		out = f
	}

	_, err = io.Copy(out, rc)
	return err
}

// openSource opens the PCAP source (file or stdin). For files with an
// auto-generated capture ID it also derives a stable content-addressed ID and
// seeks the file back to the start. Returns the reader, file size (-1 for
// stdin), and the (possibly updated) capture ID.
func openSource(filePath string, captureID uuid.UUID, isNew bool, logger *slog.Logger) (io.Reader, int64, uuid.UUID, error) {
	if filePath == "" || filePath == "-" {
		return os.Stdin, -1, captureID, nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, 0, uuid.Nil, fmt.Errorf("open pcap: %w", err)
	}

	var fileSize int64 = -1
	if fi, err := f.Stat(); err == nil {
		fileSize = fi.Size()
	}

	if isNew {
		// Derive a stable, content-addressed capture ID from the file name and
		// contents so that re-ingesting the same file produces the same UUID
		// and ClickHouse deduplication works.
		stableID, err := stableCaptureID(filePath, f)
		if err != nil {
			f.Close()
			return nil, 0, uuid.Nil, err
		}
		captureID = stableID
		logger.Debug("stable capture_id derived", "source", filePath, "capture_id", captureID)
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			return nil, 0, uuid.Nil, fmt.Errorf("seek pcap: %w", err)
		}
	}

	return f, fileSize, captureID, nil
}

func ingestPCAPStream(ctx context.Context, client *caphouse.Client, r io.Reader, captureID uuid.UUID, sensor string, p *ingestProgress) (uuid.UUID, error) {
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
		p.packets.Add(1)
	}

	if err := client.Flush(ctx); err != nil {
		return uuid.Nil, err
	}

	return capID, nil
}
