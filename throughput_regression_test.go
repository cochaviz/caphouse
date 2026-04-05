//go:build throughput && regression

package caphouse

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// benchBaseline maps PCAP filename → per-operation timings.
type benchBaseline map[string]benchFileResult

type benchFileResult struct {
	IngestNsPerOp int64 `json:"ingest_ns_per_op"`
	ExportNsPerOp int64 `json:"export_ns_per_op"`
}

const (
	benchBaselineFile        = "benchmark_results/throughput_baseline.json"
	benchRegressionThreshold = 1.05 // 5% slowdown triggers failure
)

// TestBenchmarkRegression runs the same ingest and export benchmarks as
// BenchmarkIngest / BenchmarkExport (via the shared ingestBenchFunc /
// exportBenchFunc helpers) for every testdata/*.pcap file, compares the
// results against the baseline stored in the last git commit, and writes an
// updated baseline file.
//
// If benchmark_results/throughput_baseline.json does not exist in HEAD the test passes
// unconditionally (first run). On every subsequent run the test fails if any
// operation is more than 20% slower than the committed baseline.
//
// After the test completes, benchmark_results/throughput_baseline.json is updated in the
// working tree. Commit it alongside code changes to record the new expected
// performance.
func TestBenchmarkRegression(t *testing.T) {
	ctx := context.Background()

	paths, _ := filepath.Glob("testdata/*.pcap")
	if len(paths) == 0 {
		t.Skip("no testdata/*.pcap files found")
	}

	baseline := loadBenchBaseline(t)
	current := make(benchBaseline, len(paths))

	for _, path := range paths {
		path := path
		name := filepath.Base(path)

		t.Run(name, func(t *testing.T) {
			ingestR := testing.Benchmark(ingestBenchFunc(ctx, path))
			exportR := testing.Benchmark(exportBenchFunc(ctx, path))

			res := benchFileResult{
				IngestNsPerOp: ingestR.NsPerOp(),
				ExportNsPerOp: exportR.NsPerOp(),
			}
			current[name] = res

			t.Logf("ingest: %d ns/op  export: %d ns/op", res.IngestNsPerOp, res.ExportNsPerOp)

			if prev, ok := baseline[name]; ok {
				checkBenchRegression(t, name+" ingest", res.IngestNsPerOp, prev.IngestNsPerOp)
				checkBenchRegression(t, name+" export", res.ExportNsPerOp, prev.ExportNsPerOp)
			} else {
				t.Logf("no baseline for %s — skipping regression check", name)
			}
		})
	}

	saveBenchBaseline(t, current)
}

// checkBenchRegression fails t if cur is more than benchRegressionThreshold times prev.
func checkBenchRegression(t *testing.T, label string, cur, prev int64) {
	t.Helper()
	if float64(cur) > float64(prev)*benchRegressionThreshold {
		pct := 100.0*float64(cur)/float64(prev) - 100.0
		t.Errorf("regression in %s: %d ns/op vs baseline %d ns/op (+%.1f%%)",
			label, cur, prev, pct)
	}
}

// loadBenchBaseline reads benchmark_results/throughput_baseline.json from the
// merge-base of the current branch and main. Returns an empty map if the file
// does not exist at that commit.
func loadBenchBaseline(t *testing.T) benchBaseline {
	t.Helper()
	out, err := exec.Command("git", "show", baselineCommit(t)+":"+benchBaselineFile).Output()
	if err != nil {
		t.Logf("no %s at baseline commit — treating as first run", benchBaselineFile)
		return benchBaseline{}
	}
	var b benchBaseline
	if err := json.Unmarshal(out, &b); err != nil {
		t.Logf("warning: could not parse %s at baseline commit: %v", benchBaselineFile, err)
		return benchBaseline{}
	}
	return b
}

// saveBenchBaseline writes current results to benchmark_results/throughput_baseline.json
// in the working tree so the developer can inspect and commit it.
func saveBenchBaseline(t *testing.T, b benchBaseline) {
	t.Helper()
	if err := os.MkdirAll("benchmark_results", 0o755); err != nil {
		t.Fatalf("create benchmark_results dir: %v", err)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatalf("marshal bench baseline: %v", err)
	}
	if err := os.WriteFile(benchBaselineFile, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", benchBaselineFile, err)
	}
	t.Logf("updated %s", benchBaselineFile)
}
