package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"caphouse"

	"github.com/google/uuid"
)

// ingestProgress tracks bytes read and packets ingested atomically.
type ingestProgress struct {
	bytesRead atomic.Int64
	packets   atomic.Int64
}

// countingReader wraps an io.Reader and increments p.bytesRead as bytes flow through.
type countingReader struct {
	r io.Reader
	p *ingestProgress
}

func (cr *countingReader) Read(buf []byte) (int, error) {
	n, err := cr.r.Read(buf)
	cr.p.bytesRead.Add(int64(n))
	return n, err
}

const barWidth = 28

// isTerminal reports whether f is connected to a terminal.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// startProgressBar starts a goroutine that renders a progress bar to stderr
// every 250 ms. The returned stop function renders the final state and prints a
// newline. It is a no-op when silent is true or stderr is not a terminal.
//
// Pass totalBytes > 0 for a byte-based percentage bar (file ingest).
// Pass totalPackets > 0 for a packet-based percentage bar (export).
// Pass both <= 0 for an indeterminate spinner.
func startProgressBar(totalBytes, totalPackets int64, p *ingestProgress, start time.Time, silent bool) (stop func()) {
	if silent || !isTerminal(os.Stderr) {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				renderProgressBar(os.Stderr, totalBytes, totalPackets, p, start)
			}
		}
	}()
	return func() {
		close(done)
		renderProgressBar(os.Stderr, totalBytes, totalPackets, p, start)
		fmt.Fprintln(os.Stderr)
	}
}

// renderProgressBar writes a single \r-terminated progress line to w.
func renderProgressBar(w io.Writer, totalBytes, totalPackets int64, p *ingestProgress, start time.Time) {
	byt := p.bytesRead.Load()
	pkts := p.packets.Load()

	var rate float64
	if s := time.Since(start).Seconds(); s > 0 {
		rate = float64(byt) / s
	}

	makeBar := func(pct float64) string {
		filled := int(pct * barWidth)
		if filled >= barWidth {
			return strings.Repeat("=", barWidth)
		}
		return strings.Repeat("=", filled) + ">" + strings.Repeat(" ", barWidth-filled-1)
	}

	var line string
	switch {
	case totalPackets > 0:
		// Packet-based percentage bar (export mode).
		pct := float64(pkts) / float64(totalPackets)
		if pct > 1 {
			pct = 1
		}
		line = fmt.Sprintf("\r  [%s] %3.0f%%  %d / %d pkts  %s/s  ",
			makeBar(pct), pct*100, pkts, totalPackets, formatBytes(int64(rate)),
		)
	case totalBytes > 0:
		// Byte-based percentage bar (file ingest).
		pct := float64(byt) / float64(totalBytes)
		if pct > 1 {
			pct = 1
		}
		line = fmt.Sprintf("\r  [%s] %3.0f%%  %6d pkts  %s / %s  %s/s  ",
			makeBar(pct), pct*100, pkts,
			formatBytes(byt), formatBytes(totalBytes), formatBytes(int64(rate)),
		)
	case pkts > 0:
		// Indeterminate with packet count (stdin ingest).
		line = fmt.Sprintf("\r  %6d pkts  %s  %s/s  ",
			pkts, formatBytes(byt), formatBytes(int64(rate)),
		)
	default:
		// Indeterminate bytes only.
		line = fmt.Sprintf("\r  %s  %s/s  ",
			formatBytes(byt), formatBytes(int64(rate)),
		)
	}

	fmt.Fprint(w, line)
}

// formatBytes returns a human-readable byte count (e.g. "12.3 MB").
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// newLogger returns an slog.Logger writing to stderr.
// --silent discards all output; --debug enables DEBUG level.
func newLogger(debug, silent bool) *slog.Logger {
	if silent {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// capHouseNamespace is a fixed UUID v5 namespace for deterministic capture IDs.
var capHouseNamespace = uuid.MustParse("3f6a9c2e-1b84-5d70-a3f2-7e4c8b9d0f1e")

// parseCaptureID parses a capture UUID string. If input is empty or "new",
// a fresh random UUID is returned with isNew=true. Returns an error when
// allowNew is false and no valid UUID is provided.
func parseCaptureID(input string, allowNew bool) (uuid.UUID, bool, error) {
	if input == "" || input == "new" {
		if !allowNew {
			return uuid.Nil, false, fmt.Errorf("capture id is required")
		}
		return uuid.New(), true, nil
	}
	id, err := uuid.Parse(input)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("invalid capture id: %w", err)
	}
	return id, false, nil
}

// newClient constructs a caphouse.Client from a CLI config.
func newClient(ctx context.Context, cfg config, logger *slog.Logger) (*caphouse.Client, error) {
	return caphouse.New(ctx, caphouse.Config{
		DSN:                   cfg.dsn,
		BatchSize:             cfg.batchSize,
		FlushInterval:         cfg.flushInterval,
		Debug:                 cfg.debug,
		Logger:                logger,
		DisableStreamTracking: cfg.noStreams,
	})
}

// resolveVersion returns the binary version string derived from VCS metadata
// embedded by the Go toolchain at build time:
//  1. Module version (set by go install module@vX.Y.Z or a tagged build)
//  2. Short VCS commit hash (dev builds from a git working tree)
//  3. "dev" fallback when no build info is available
func resolveVersion() string {
	const fallback = "dev"
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
		if rev := lookupBuildSetting(info.Settings, "vcs.revision"); rev != "" {
			if len(rev) > 7 {
				rev = rev[:7]
			}
			return fmt.Sprintf("%s (%s)", fallback, rev)
		}
	}
	return fallback
}

func lookupBuildSetting(settings []debug.BuildSetting, key string) string {
	for _, s := range settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

// firstNonEmpty returns the first non-empty string from vals.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// sumToPacketIDBase extracts the packet-ID base from a file-content hash:
// bytes [8:12] of the SHA-256 sum, shifted left 32 to reserve the lower 32
// bits for the per-packet sequential offset.
func sumToPacketIDBase(sum []byte) uint64 {
	return uint64(binary.BigEndian.Uint32(sum[8:12])) << 32
}

// resolveInputFiles expands a list of file path patterns into concrete file
// paths. Patterns may be literal paths or glob expressions (e.g. "ring*.pcap").
// An empty or nil list (or a list containing only "-") is returned as-is,
// indicating stdin. Each pattern that matches no files is an error.
// Duplicate paths are silently removed while preserving order.
func resolveInputFiles(patterns []string) ([]string, error) {
	// Single "-" means stdin; pass through unchanged.
	if len(patterns) == 1 && patterns[0] == "-" {
		return patterns, nil
	}

	seen := make(map[string]bool)
	var out []string
	for _, pat := range patterns {
		if pat == "-" {
			return nil, errors.New("cannot combine stdin (-) with file paths")
		}
		matches, err := filepath.Glob(pat)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern %q: %w", pat, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no files matched %q", pat)
		}
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out, nil
}

// stablePacketIDBase computes the packet-ID base for in-memory PCAP data.
// It is the functional equivalent of the streaming hash in openSource and
// yields identical results for the same file.
func stablePacketIDBase(name string, data []byte) uint64 {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00", name)
	h.Write(data)
	return sumToPacketIDBase(h.Sum(nil))
}
