package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"caphouse"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

//go:embed scripts/caphouse-monitor.sh
var monitorScript []byte

//go:embed description.txt
var longDescription string

//go:embed banner.txt
var banner string

// config holds all resolved flag/env values for a single invocation.
type config struct {
	dsn           string
	batchSize     int
	flushInterval time.Duration
	filePaths     []string // one or more input/output paths; globs expanded at runtime
	capture       string
	sensor        string
	queryExpr     string
	components    []string
	debug         bool
	silent        bool
	noStreams      bool
}

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var dsn string
	var batchSize int
	var flushInterval time.Duration
	var readMode bool
	var writeMode bool
	var capture string
	var sensor string
	var queryExpr string
	var componentsRaw string
	var debug bool
	var silent bool
	var noStreams bool

	cmd := &cobra.Command{
		Use:     "caphouse",
		Short:   "Store and export classic PCAPs in ClickHouse",
		Long:    longDescription,
		Version: resolveVersion(),

		Args:         cobra.ArbitraryArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !silent {
				fmt.Fprintln(
					cmd.ErrOrStderr(),
					strings.ReplaceAll(banner, "{{ version }}", resolveVersion()),
				)
			}
			if readMode && writeMode {
				return errors.New("--read and --write are mutually exclusive")
			}
			if capture == "all" && readMode {
				return errors.New("--capture all cannot be used with --read")
			}
			if componentsRaw != "" && queryExpr == "" {
				return errors.New("--components requires --query")
			}
			cfg := config{
				dsn:           firstNonEmpty(dsn, os.Getenv("CAPHOUSE_DSN")),
				sensor:        sensor,
				filePaths:     args,
				capture:       capture,
				batchSize:     batchSize,
				flushInterval: flushInterval,
				queryExpr:     queryExpr,
				components:    splitComponents(componentsRaw),
				debug:         debug,
				silent:        silent,
				noStreams:      noStreams,
			}
			if cfg.dsn == "" {
				return errors.New("dsn is required (flag --dsn or env CAPHOUSE_DSN)")
			}
			if queryExpr != "" && !writeMode {
				return runExplain(cmd, cfg)
			}
			if writeMode {
				return runWrite(cmd, cfg)
			}
			return runRead(cmd, cfg)
		},
	}

	cmd.Flags().StringVarP(&dsn, "dsn", "d", "", "ClickHouse DSN, e.g. clickhouse://user:pass@host:9000/db (or CAPHOUSE_DSN)")
	cmd.Flags().IntVar(&batchSize, "batch-size", 0, "packets per ClickHouse batch insert")
	cmd.Flags().DurationVar(&flushInterval, "flush-interval", 0, "maximum time between batch flushes")
	cmd.Flags().BoolVar(&debug, "debug", false, "enable verbose ClickHouse driver logging to stderr")
	cmd.Flags().BoolVarP(&silent, "silent", "s", false, "suppress warnings and progress output")
	cmd.Flags().BoolVar(&noStreams, "no-streams", false, "disable TCP stream tracking and L7 protocol detection during ingest")

	cmd.Flags().BoolVarP(&readMode, "read", "r", false, "ingest PCAP from file or stdin into ClickHouse (default mode)")
	cmd.Flags().BoolVarP(&writeMode, "write", "w", false, "export a stored capture from ClickHouse as a PCAP file or stream")
	cmd.Flags().StringVarP(&capture, "capture", "c", "", "capture UUID; omit or 'new' in read mode to create a new capture, required in write mode")
	cmd.Flags().StringVar(&sensor, "sensor", "", "sensor name attached to the capture; defaults to system hostname in read mode")
	cmd.Flags().StringVarP(&queryExpr, "query", "q", "", "filter expression (tcpdump-style); without --write prints equivalent SQL, with --write exports filtered PCAP")
	cmd.Flags().StringVarP(&componentsRaw, "components", "C", "", "comma-separated component tables to JOIN (e.g. ipv4,tcp,udp); only valid with --query")

	cmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		if err == nil {
			return nil
		}
		_ = cmd.Usage()
		return err
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "install-manual [directory] (should be executed as root)",
		Short: "Generate and install man page",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			manpath := "/usr/local/share/man/man1"

			if len(args) > 0 && args[0] != "" {
				manpath = args[0]
			}
			if err := os.MkdirAll(path.Clean(manpath), 0o755); err != nil {
				return err
			}
			header := &doc.GenManHeader{Title: "CAPHOUSE", Section: "1"}
			return doc.GenManTree(cmd, header, manpath)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "install-scripts [directory]",
		Short: "Install companion caphouse scripts (e.g. monitor)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home_dir, _ := os.UserHomeDir()
			scriptpath := path.Join(home_dir, ".local/bin")
			if len(args) > 0 && args[0] != "" {
				scriptpath = args[0]
			}
			if err := os.MkdirAll(scriptpath, 0o755); err != nil {
				return err
			}
			monitorFileLocation := filepath.Join(scriptpath, "caphouse-monitor")
			err := os.WriteFile(monitorFileLocation, monitorScript, os.FileMode(0755))

			if err != nil {
				return err
			}
			fmt.Printf("Installed caphouse-monitor to %s\n", monitorFileLocation)
			return nil
		},
	})

	return cmd
}

// splitComponents splits a comma-separated component string into a slice,
// trimming spaces and dropping empty entries.
func splitComponents(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func runExplain(cmd *cobra.Command, cfg config) error {
	q, err := caphouse.ParseQuery(cfg.queryExpr)
	if err != nil {
		return fmt.Errorf("parse filter: %w", err)
	}

	ctx := context.Background()
	logger := newLogger(cfg.debug, cfg.silent)
	client, err := newClient(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer client.Close()

	var sql string
	if cfg.capture == "all" {
		// nil captureIDs → no capture_id IN (...) filter; queries all captures.
		var err error
		sql, err = client.GenerateSQLForCaptures(nil, q, cfg.components)
		if err != nil {
			return err
		}
	} else {
		captureID, _, err := parseCaptureID(cfg.capture, false)
		if err != nil {
			return fmt.Errorf("--capture is required for --query: %w", err)
		}
		sql, err = client.GenerateSQL(captureID, q, cfg.components)
		if err != nil {
			return err
		}
	}

	fmt.Fprintln(cmd.OutOrStdout(), sql)
	return nil
}

func runRead(cmd *cobra.Command, cfg config) error {
	ctx := context.Background()
	logger := newLogger(cfg.debug, cfg.silent)

	if cfg.sensor == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			logger.Warn("--sensor not set, falling back to hostname", "sensor", h)
			cfg.sensor = h
		} else {
			return errors.New("sensor is required (--sensor)")
		}
	}

	client, err := newClient(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.InitSchema(ctx); err != nil {
		return err
	}

	// No positional args: fall back to stdin, but warn and skip if it's a TTY.
	if len(cfg.filePaths) == 0 {
		if isTerminal(os.Stdin) {
			logger.Warn("no input files specified and stdin is a terminal; nothing to ingest")
			return nil
		}
		// Stdin is a pipe or redirect — ingest it as a single unnamed stream.
		cfg.filePaths = []string{"-"}
	}

	files, err := resolveInputFiles(cfg.filePaths)
	if err != nil {
		return err
	}

	// Determine whether the user supplied an explicit capture UUID.
	explicitCapture := cfg.capture != "" && cfg.capture != "new"
	var sharedCaptureID uuid.UUID
	if explicitCapture {
		sharedCaptureID, _, err = parseCaptureID(cfg.capture, false)
		if err != nil {
			return err
		}
	}

	for _, filePath := range files {
		var captureID uuid.UUID
		isNew := true
		if explicitCapture {
			captureID = sharedCaptureID
			isNew = false
		}

		if err := ingestOneFile(ctx, cmd, cfg, logger, client, filePath, captureID, isNew); err != nil {
			if len(files) > 1 {
				return fmt.Errorf("%s: %w", filePath, err)
			}
			return err
		}
	}
	return nil
}

// ingestOneFile ingests a single PCAP file (or stdin when filePath is "" or "-").
func ingestOneFile(ctx context.Context, cmd *cobra.Command, cfg config, logger *slog.Logger, client *caphouse.Client, filePath string, captureID uuid.UUID, isNew bool) error {
	src, fileSize, captureID, packetIDBase, err := openSource(filePath, captureID, isNew, logger)
	if err != nil {
		return err
	}
	if closer, ok := src.(io.Closer); ok {
		defer closer.Close()
	}

	var p ingestProgress
	cr := &countingReader{r: src, p: &p}

	srcLabel := filePath
	if srcLabel == "" || srcLabel == "-" {
		srcLabel = "stdin"
	}
	logger.Info("ingesting", "source", srcLabel, "sensor", cfg.sensor)

	start := time.Now()
	stopBar := startProgressBar(fileSize, -1, &p, start, cfg.silent)

	id, err := client.IngestPCAPStream(ctx, cr, captureID, cfg.sensor, packetIDBase, func() { p.packets.Add(1) })
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
	ctx := context.Background()
	logger := newLogger(cfg.debug, cfg.silent)

	// --capture all: merge all captures within the query's time range.
	if cfg.capture == "all" {
		if cfg.queryExpr == "" {
			return errors.New("--capture all requires a --query with a time range filter")
		}
		f, err := caphouse.ParseQuery(cfg.queryExpr)
		if err != nil {
			return fmt.Errorf("parse filter: %w", err)
		}
		if _, _, ok := f.TimeRange(); !ok {
			return errors.New("--capture all requires a time range in the filter (e.g. 'time X to Y')")
		}
		client, err := newClient(ctx, cfg, logger)
		if err != nil {
			return err
		}
		defer client.Close()

		logger.Warn("exporting all captures in time range; this may produce large output",
			"filter", cfg.queryExpr)

		var p ingestProgress
		rc, totalPackets, err := client.ExportAllCapturesFiltered(ctx, f, &p.packets)
		if err != nil {
			return err
		}
		defer rc.Close()

		logger.Info("exporting all captures", "filter", cfg.queryExpr, "matched", totalPackets)
		return writeOutput(cmd, cfg, rc, "all", totalPackets, &p, logger)
	}

	captureID, _, err := parseCaptureID(cfg.capture, false)
	if err != nil {
		return err
	}

	client, err := newClient(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer client.Close()

	var p ingestProgress
	var rc io.ReadCloser
	var totalPackets int64

	if cfg.queryExpr != "" {
		f, err := caphouse.ParseQuery(cfg.queryExpr)
		if err != nil {
			return fmt.Errorf("parse filter: %w", err)
		}
		rc, totalPackets, err = client.ExportCaptureFiltered(ctx, captureID, f, &p.packets)
		if err != nil {
			return err
		}
		logger.Info("exporting filtered", "capture_id", captureID, "filter", cfg.queryExpr, "matched", totalPackets)
	} else {
		totalPackets, err = client.CountPackets(ctx, captureID)
		if err != nil {
			logger.Warn("could not count packets", "err", err)
			totalPackets = -1
		}
		rc, err = client.ExportCaptureWithProgress(ctx, captureID, &p.packets)
		if err != nil {
			return err
		}
		logger.Info("exporting", "capture_id", captureID)
	}
	defer rc.Close()
	return writeOutput(cmd, cfg, rc, captureID.String(), totalPackets, &p, logger)
}

// writeOutput streams rc to the configured output destination, showing a
// progress bar. label is used in the completion log line (e.g. a capture ID or
// "all").
func writeOutput(cmd *cobra.Command, cfg config, rc io.ReadCloser, label string, totalPackets int64, p *ingestProgress, logger *slog.Logger) error {
	// Write mode uses at most one output path.
	outPath := ""
	if len(cfg.filePaths) == 1 && cfg.filePaths[0] != "-" {
		outPath = cfg.filePaths[0]
	} else if len(cfg.filePaths) > 1 {
		return errors.New("--write accepts at most one --file path")
	}

	destLabel := outPath
	if destLabel == "" {
		destLabel = "stdout"
	}
	logger.Info("dest", "path", destLabel)

	out := io.Writer(cmd.OutOrStdout())
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer f.Close()
		out = f
	}

	start := time.Now()
	stopBar := startProgressBar(-1, totalPackets, p, start, cfg.silent)

	n, err := io.Copy(out, &countingReader{r: rc, p: p})
	stopBar()

	if err != nil {
		return err
	}

	logger.Info("done",
		"label", label,
		"bytes", n,
		"elapsed", time.Since(start).Truncate(time.Millisecond),
	)
	return nil
}

// openSource opens the PCAP source (file or stdin). For files it computes a
// SHA-256 of the basename and contents to derive a stable capture ID (when
// isNew) and a deterministic packetIDBase. Stdin always returns packetIDBase=0.
func openSource(filePath string, captureID uuid.UUID, isNew bool, logger *slog.Logger) (io.Reader, int64, uuid.UUID, uint64, error) {
	if filePath == "" || filePath == "-" {
		return os.Stdin, -1, captureID, 0, nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, 0, uuid.Nil, 0, fmt.Errorf("open pcap: %w", err)
	}

	var fileSize int64 = -1
	if fi, err := f.Stat(); err == nil {
		fileSize = fi.Size()
	}

	h := sha256.New()
	fmt.Fprintf(h, "%s\x00", filepath.Base(filePath))
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return nil, 0, uuid.Nil, 0, fmt.Errorf("hash pcap: %w", err)
	}
	sum := h.Sum(nil)

	if isNew {
		captureID = uuid.NewSHA1(capHouseNamespace, sum)
		logger.Debug("stable capture_id derived", "source", filePath, "capture_id", captureID)
	}

	packetIDBase := sumToPacketIDBase(sum)

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, 0, uuid.Nil, 0, fmt.Errorf("seek pcap: %w", err)
	}

	return f, fileSize, captureID, packetIDBase, nil
}

