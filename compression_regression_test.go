//go:build compression && regression

package caphouse

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// compressionBaseline maps PCAP filename → the ch_vs_file_ratio measured at
// the time of the last committed baseline.
type compressionBaseline map[string]compressionBaselineEntry

type compressionBaselineEntry struct {
	ChVsFileRatio float64 `json:"ch_vs_file_ratio"`
}

const (
	compressionBaselineFile        = "benchmark_results/compression_ratio_baseline.json"
	compressionRegressionThreshold = 1.00 // any worse compression triggers failure
)

// TestCompressionRegression runs the same compression measurement as
// TestCompressionRatio (via the shared measureCompression helper) for every
// testdata/*.pcap file, compares ch_vs_file_ratio against the baseline stored
// in the last git commit, and writes an updated baseline file.
//
// If benchmark_results/compression_ratio_baseline.json does not exist in HEAD the test
// passes unconditionally (first run). On every subsequent run the test fails
// if the ClickHouse compressed footprint per raw PCAP byte increases by more
// than 5% relative to the baseline.
//
// After the test completes, benchmark_results/compression_ratio_baseline.json is updated
// in the working tree. Commit it alongside code changes to record the new
// expected compression performance.
func TestCompressionRegression(t *testing.T) {
	ctx := context.Background()

	paths, err := filepath.Glob("testdata/*.pcap")
	if err != nil {
		t.Fatalf("glob testdata: %v", err)
	}
	if len(paths) == 0 {
		t.Skip("no testdata/*.pcap files found")
	}

	baseline := loadCompressionBaseline(t)
	current := make(compressionBaseline, len(paths))

	for _, path := range paths {
		name := filepath.Base(path)

		t.Run(name, func(t *testing.T) {
			m := measureCompression(t, ctx, path)
			ratio := m.ChVsFileRatio()

			t.Logf("ch_vs_file_ratio: %.4f  (compressed ClickHouse bytes per raw PCAP byte)", ratio)

			current[name] = compressionBaselineEntry{ChVsFileRatio: ratio}

			if prev, ok := baseline[name]; ok {
				checkCompressionRegression(t, name, ratio, prev.ChVsFileRatio)
			} else {
				t.Logf("no baseline for %s — skipping regression check", name)
			}
		})
	}

	saveCompressionBaseline(t, current)
}

// checkCompressionRegression fails t if the ratio has worsened by more than
// compressionRegressionThreshold relative to prev.
func checkCompressionRegression(t *testing.T, label string, cur, prev float64) {
	t.Helper()
	if cur > prev*compressionRegressionThreshold {
		pct := 100.0*cur/prev - 100.0
		t.Errorf("compression regression in %s: ch_vs_file_ratio %.4f vs baseline %.4f (+%.1f%%)",
			label, cur, prev, pct)
	}
}

// loadCompressionBaseline reads benchmark_results/compression_ratio_baseline.json
// from the merge-base of the current branch and main. Returns an empty map if
// the file does not exist at that commit.
func loadCompressionBaseline(t *testing.T) compressionBaseline {
	t.Helper()
	out, err := exec.Command("git", "show", baselineCommit(t)+":"+compressionBaselineFile).Output()
	if err != nil {
		t.Logf("no %s at baseline commit — treating as first run", compressionBaselineFile)
		return compressionBaseline{}
	}
	var b compressionBaseline
	if err := json.Unmarshal(out, &b); err != nil {
		t.Logf("warning: could not parse %s at baseline commit: %v", compressionBaselineFile, err)
		return compressionBaseline{}
	}
	return b
}

// saveCompressionBaseline writes current results to
// benchmark_results/compression_ratio_baseline.json in the working tree.
func saveCompressionBaseline(t *testing.T, b compressionBaseline) {
	t.Helper()
	if err := os.MkdirAll("benchmark_results", 0o755); err != nil {
		t.Fatalf("create benchmark_results dir: %v", err)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatalf("marshal compression baseline: %v", err)
	}
	if err := os.WriteFile(compressionBaselineFile, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", compressionBaselineFile, err)
	}
	t.Logf("updated %s", compressionBaselineFile)
}
