//go:build e2e

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

// TestE2ERoundtrip ingests every classic PCAP file in testdata/ via
// IngestPCAPStream and verifies byte-exact export. PCAPng files are covered
// separately by TestE2EPcapNgCompat (pcapng_e2e_test.go).
func TestE2ERoundtrip(t *testing.T) {
	ctx := context.Background()
	paths, err := filepath.Glob("testdata/*.pcap")
	if err != nil {
		t.Fatalf("glob testdata: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no pcap files found in testdata/")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			// Derive session ID from filename + file contents (same as CLI).
			h := sha256.New()
			fmt.Fprintf(h, "%s\x00", filepath.Base(path))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			h.Write(raw)
			sessionID := binary.BigEndian.Uint64(h.Sum(nil)[0:8])
			raw = nil // allow GC

			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("open %s: %v", path, err)
			}
			_, ingestErr := e2eClient.IngestPCAPStream(ctx, f, sessionID, "test", nil)
			f.Close()
			if ingestErr != nil {
				t.Fatalf("IngestPCAPStream: %v", ingestErr)
			}

			rc, _, err := e2eClient.Export(ctx, ExportOpts{SessionID: &sessionID})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			tmp, err := os.CreateTemp(t.TempDir(), "export-*.pcap")
			if err != nil {
				rc.Close()
				t.Fatalf("create temp file: %v", err)
			}
			if _, err := io.Copy(tmp, rc); err != nil {
				tmp.Close()
				rc.Close()
				t.Fatalf("export read: %v", err)
			}
			rc.Close()
			tmp.Close()

			orig, err := os.Open(path)
			if err != nil {
				t.Fatalf("open original: %v", err)
			}
			exported, err := os.Open(tmp.Name())
			if err != nil {
				orig.Close()
				t.Fatalf("open exported: %v", err)
			}
			equal, err := filesEqual(orig, exported)
			orig.Close()
			exported.Close()
			if err != nil {
				t.Fatalf("compare: %v", err)
			}
			if !equal {
				origStat, _ := os.Stat(path)
				expStat, _ := os.Stat(tmp.Name())
				t.Fatalf("exported pcap does not match original (got %d bytes, want %d)", expStat.Size(), origStat.Size())
			}
		})
	}
}

// filesEqual compares two files by streaming them in chunks without loading
// either into memory.
func filesEqual(a, b *os.File) (bool, error) {
	const chunkSize = 64 * 1024
	bufA := make([]byte, chunkSize)
	bufB := make([]byte, chunkSize)
	for {
		nA, errA := io.ReadFull(a, bufA)
		nB, errB := io.ReadFull(b, bufB)
		if nA != nB {
			return false, nil
		}
		if string(bufA[:nA]) != string(bufB[:nB]) {
			return false, nil
		}
		if errA == io.EOF || errA == io.ErrUnexpectedEOF {
			if errB == io.EOF || errB == io.ErrUnexpectedEOF {
				return true, nil
			}
			return false, nil
		}
		if errA != nil {
			return false, errA
		}
		if errB != nil {
			return false, errB
		}
	}
}
