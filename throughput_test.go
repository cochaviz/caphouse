//go:build throughput

package caphouse

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// ingestBenchFunc returns a benchmark function for the given PCAP path.
// It is shared between BenchmarkIngest and TestBenchmarkRegression so both
// measure the exact same workload.
func ingestBenchFunc(ctx context.Context, path string) func(*testing.B) {
	return func(b *testing.B) {
		b.Helper()
		info, err := os.Stat(path)
		if err != nil {
			b.Fatalf("stat %s: %v", path, err)
		}
		b.SetBytes(info.Size())
		b.ReportAllocs()

		sessionID := benchSessionID(b, path)

		b.ResetTimer()
		for range b.N {
			f, err := os.Open(path)
			if err != nil {
				b.Fatalf("open %s: %v", path, err)
			}
			_, ingestErr := e2eClient.IngestPCAPStream(ctx, f, sessionID, "bench", nil)
			f.Close()
			if ingestErr != nil {
				b.Fatalf("IngestPCAPStream: %v", ingestErr)
			}
		}
	}
}

// exportBenchFunc returns a benchmark function for the given PCAP path.
// It ingests the file once before the timer starts, then benchmarks Export.
// It is shared between BenchmarkExport and TestBenchmarkRegression.
func exportBenchFunc(ctx context.Context, path string) func(*testing.B) {
	return func(b *testing.B) {
		b.Helper()
		info, err := os.Stat(path)
		if err != nil {
			b.Fatalf("stat %s: %v", path, err)
		}
		b.SetBytes(info.Size())
		b.ReportAllocs()

		sessionID := benchSessionID(b, path)

		// Ingest once so there is data to export (not timed).
		f, err := os.Open(path)
		if err != nil {
			b.Fatalf("open %s: %v", path, err)
		}
		_, ingestErr := e2eClient.IngestPCAPStream(ctx, f, sessionID, "bench", nil)
		f.Close()
		if ingestErr != nil {
			b.Fatalf("IngestPCAPStream: %v", ingestErr)
		}

		b.ResetTimer()
		for range b.N {
			rc, _, err := e2eClient.Export(ctx, ExportOpts{SessionID: &sessionID})
			if err != nil {
				b.Fatalf("Export: %v", err)
			}
			if _, err := io.Copy(io.Discard, rc); err != nil {
				rc.Close()
				b.Fatalf("export read: %v", err)
			}
			rc.Close()
		}
	}
}

// BenchmarkIngest measures packet ingest throughput for every testdata/*.pcap
// file. Each sub-benchmark is named after the file and reports:
//
//	bytes/op  — file size per ingest run
//	allocs/op — Go allocations per ingest run
//
// Run with: go test -tags throughput -bench=BenchmarkIngest -benchtime=3x ./...
func BenchmarkIngest(b *testing.B) {
	ctx := context.Background()
	paths, _ := filepath.Glob("testdata/*.pcap")
	if len(paths) == 0 {
		b.Skip("no testdata/*.pcap files found")
	}
	for _, path := range paths {
		path := path
		b.Run(filepath.Base(path), ingestBenchFunc(ctx, path))
	}
}

// BenchmarkExport measures packet export throughput for every testdata/*.pcap
// file. Each file is ingested once before the benchmark loop; the benchmark
// itself measures only the Export call. Reports:
//
//	bytes/op  — original file size (proxy for exported PCAP size)
//	allocs/op — Go allocations per export run
//
// Run with: go test -tags throughput -bench=BenchmarkExport -benchtime=3x ./...
func BenchmarkExport(b *testing.B) {
	ctx := context.Background()
	paths, _ := filepath.Glob("testdata/*.pcap")
	if len(paths) == 0 {
		b.Skip("no testdata/*.pcap files found")
	}
	for _, path := range paths {
		path := path
		b.Run(filepath.Base(path), exportBenchFunc(ctx, path))
	}
}

// benchSessionID derives a stable session ID from the file's name and contents
// using SHA-256, matching the derivation used by the CLI and round-trip tests.
func benchSessionID(tb testing.TB, path string) uint64 {
	tb.Helper()
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00", filepath.Base(path))
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read %s: %v", path, err)
	}
	h.Write(data)
	return binary.BigEndian.Uint64(h.Sum(nil)[0:8])
}
