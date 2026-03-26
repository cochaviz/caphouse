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
	"caphouse/query"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

//go:embed scripts/caphouse-monitor.sh
var monitorScript []byte

//go:embed scripts/caphouse-watch-dir.sh
var watchScript []byte

const longDescription = `caphouse stores and exports classic PCAP files in ClickHouse.

Instead of writing raw frames to disk, it parses each packet into its protocol
layers and stores each layer in its own ClickHouse table. This makes packet data
queryable at the column level while still allowing lossless PCAP reconstruction.

Supported protocol layers: Ethernet, dot1q (VLAN), Linux SLL, IPv4 (with
options), IPv6 (with extension headers), TCP, and UDP.

Modes:
  -r (default)  Read one or more PCAP files (or stdin) and ingest into ClickHouse.
  -w            Export a stored capture back as a PCAP file or stream.

Input files (read mode) and the output file (write mode) are positional
arguments. Multiple files and glob patterns are accepted in read mode.

The DSN must use the native ClickHouse protocol (clickhouse://host:9000/db).
HTTP connections are not supported.

Examples:
  # Ingest a file (new capture; UUID printed on completion)
  caphouse --dsn="clickhouse://user:pass@localhost:9000/db" --sensor=myhost capture.pcap

  # Ingest multiple files or a glob
  caphouse --dsn="clickhouse://user:pass@localhost:9000/db" --sensor=myhost ring*.pcap

  # Ingest without L7 stream tracking
  caphouse --dsn="clickhouse://user:pass@localhost:9000/db" --no-streams capture.pcap

  # Append packets to an existing capture
  caphouse --dsn="clickhouse://user:pass@localhost:9000/db" --sensor=myhost more.pcap --capture=<uuid>

  # Pipe from tcpdump
  tcpdump -i eth0 -w - | caphouse --dsn="clickhouse://user:pass@localhost:9000/db" --sensor=myhost

  # Export to a file
  caphouse -w --dsn="clickhouse://user:pass@localhost:9000/db" --capture=<uuid> out.pcap

  # Stream into tcpreplay
  caphouse -w --dsn="clickhouse://user:pass@localhost:9000/db" --capture=<uuid> | tcpreplay --intf1=eth0 -

  # Export all captures within a time window, merged and sorted by time
  caphouse -w --dsn="clickhouse://user:pass@localhost:9000/db" --capture=all \
    --from=2024-01-01T00:00:00Z --to=2024-01-01T01:00:00Z merged.pcap

  # Export all captures in a time window, filtered by destination IP
  caphouse -w --dsn="clickhouse://user:pass@localhost:9000/db" --capture=all \
    --from=2024-01-01T00:00:00Z --to=2024-01-01T01:00:00Z \
    --query="ipv4.dst = '1.1.1.1'" merged.pcap

  # Suppress all progress output (useful in scripts)
  caphouse -s --dsn="clickhouse://user:pass@localhost:9000/db" --sensor=myhost capture.pcap`

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
	fromTime      time.Time
	toTime        time.Time
	debug         bool
	silent        bool
	noStreams     bool
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
	var fromStr string
	var toStr string
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
				noStreams:     noStreams,
			}
			if fromStr != "" {
				t, err := time.Parse(time.RFC3339, fromStr)
				if err != nil {
					return fmt.Errorf("--from: %w", err)
				}
				cfg.fromTime = t
			}
			if toStr != "" {
				t, err := time.Parse(time.RFC3339, toStr)
				if err != nil {
					return fmt.Errorf("--to: %w", err)
				}
				cfg.toTime = t
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
	cmd.Flags().StringVarP(&queryExpr, "query", "q", "", "ClickHouse WHERE clause filter (e.g. 'ipv4.dst = \\'1.1.1.1\\' AND tcp.dst = 443'); without --write prints equivalent SQL")
	cmd.Flags().StringVarP(&componentsRaw, "components", "C", "", "comma-separated component tables to JOIN (e.g. ipv4,tcp,udp); only valid with --query")
	cmd.Flags().StringVar(&fromStr, "from", "", "start of time window for --capture all (RFC 3339, e.g. 2024-01-01T00:00:00Z)")
	cmd.Flags().StringVar(&toStr, "to", "", "end of time window for --capture all (RFC 3339, e.g. 2024-01-02T00:00:00Z)")

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
			scripts := []struct {
				name    string
				content []byte
			}{
				{"caphouse-monitor", monitorScript},
				{"caphouse-watch-dir", watchScript},
			}
			for _, s := range scripts {
				dest := filepath.Join(scriptpath, s.name)
				if err := os.WriteFile(dest, s.content, os.FileMode(0755)); err != nil {
					return err
				}
				fmt.Printf("Installed %s to %s\n", s.name, dest)
			}
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
	q, err := query.ParseQuery(cfg.queryExpr)
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
	if cfg.capture == "all" || cfg.capture == "" {
		// nil sessionIDs → no session_id IN (...) filter; queries all sessions.
		sql, err = client.GenerateSQLForSessions(nil, q, cfg.components)
		if err != nil {
			return err
		}
	} else {
		sessionID, err := parseSessionID(cfg.capture)
		if err != nil {
			return fmt.Errorf("--capture: %w", err)
		}
		sql, err = client.GenerateSQL(sessionID, q, cfg.components)
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
		cfg.filePaths = []string{"-"}
	}

	files, err := resolveInputFiles(cfg.filePaths)
	if err != nil {
		return err
	}

	for _, filePath := range files {
		if err := ingestOneFile(ctx, cmd, cfg, logger, client, filePath); err != nil {
			if len(files) > 1 {
				return fmt.Errorf("%s: %w", filePath, err)
			}
			return err
		}
	}
	return nil
}

// ingestOneFile ingests a single PCAP file (or stdin when filePath is "" or "-").
func ingestOneFile(ctx context.Context, cmd *cobra.Command, cfg config, logger *slog.Logger, client *caphouse.Client, filePath string) error {
	src, fileSize, sessionID, err := openSource(filePath, logger)
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

	id, err := client.IngestPCAPStream(ctx, cr, sessionID, cfg.sensor, func() { p.packets.Add(1) })
	stopBar()

	if err != nil {
		return err
	}

	logger.Info("done",
		"session_id", id,
		"packets", p.packets.Load(),
		"bytes", p.bytesRead.Load(),
		"elapsed", time.Since(start).Truncate(time.Millisecond),
	)

	fmt.Fprintf(cmd.OutOrStdout(), "session_id=%d\n", id)
	return nil
}

func runWrite(cmd *cobra.Command, cfg config) error {
	ctx := context.Background()
	logger := newLogger(cfg.debug, cfg.silent)

	// --capture all: merge all captures within the given time window.
	if cfg.capture == "all" {
		if cfg.fromTime.IsZero() || cfg.toTime.IsZero() {
			return errors.New("--capture all requires --from and --to time bounds")
		}
		if !cfg.fromTime.Before(cfg.toTime) {
			return errors.New("--from must be before --to")
		}
		client, err := newClient(ctx, cfg, logger)
		if err != nil {
			return err
		}
		defer client.Close()

		logger.Warn("exporting all captures in time range; this may produce large output",
			"from", cfg.fromTime, "to", cfg.toTime)

		var p ingestProgress
		rc, totalPackets, err := client.ExportAllCapturesFiltered(ctx, cfg.fromTime, cfg.toTime, query.Query{}, &p.packets)
		if err != nil {
			return err
		}
		defer rc.Close()

		logger.Info("exporting all captures", "from", cfg.fromTime, "to", cfg.toTime, "matched", totalPackets)
		return writeOutput(cmd, cfg, rc, "all", totalPackets, &p, logger)
	}

	sessionID, err := parseSessionID(cfg.capture)
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
		f, err := query.ParseQuery(cfg.queryExpr)
		if err != nil {
			return fmt.Errorf("parse filter: %w", err)
		}
		rc, totalPackets, err = client.ExportCaptureFiltered(ctx, sessionID, f, &p.packets)
		if err != nil {
			return err
		}
		logger.Info("exporting filtered", "session_id", sessionID, "filter", cfg.queryExpr, "matched", totalPackets)
	} else {
		totalPackets, err = client.CountPackets(ctx, sessionID)
		if err != nil {
			logger.Warn("could not count packets", "err", err)
			totalPackets = -1
		}
		rc, err = client.ExportCaptureWithProgress(ctx, sessionID, &p.packets)
		if err != nil {
			return err
		}
		logger.Info("exporting", "session_id", sessionID)
	}
	defer rc.Close()
	return writeOutput(cmd, cfg, rc, fmt.Sprintf("%d", sessionID), totalPackets, &p, logger)
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
// SHA-256 of the basename and contents to derive a deterministic session ID.
// Stdin always returns sessionID=0.
func openSource(filePath string, logger *slog.Logger) (io.Reader, int64, uint64, error) {
	if filePath == "" || filePath == "-" {
		return os.Stdin, -1, 0, nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open pcap: %w", err)
	}

	var fileSize int64 = -1
	if fi, err := f.Stat(); err == nil {
		fileSize = fi.Size()
	}

	h := sha256.New()
	fmt.Fprintf(h, "%s\x00", filepath.Base(filePath))
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return nil, 0, 0, fmt.Errorf("hash pcap: %w", err)
	}
	sum := h.Sum(nil)
	sessionID := sumToSessionID(sum)
	logger.Debug("session_id derived", "source", filePath, "session_id", sessionID)

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, 0, 0, fmt.Errorf("seek pcap: %w", err)
	}

	return f, fileSize, sessionID, nil
}
