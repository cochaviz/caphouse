//go:build e2e

package caphouse

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

// TestE2EPcapNgCompat verifies that pcapng files can be ingested without error
// and that the result is a valid classic PCAP stream. No byte-exact guarantee
// is made — the pcapng format is converted on ingest and metadata blocks are
// discarded.
func TestE2EPcapNgCompat(t *testing.T) {
	ctx := context.Background()
	paths, err := filepath.Glob("testdata/*.pcapng")
	if err != nil {
		t.Fatalf("glob testdata: %v", err)
	}
	if len(paths) == 0 {
		t.Skip("no pcapng files found in testdata/; skipping")
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			// ParseGlobalHeader must signal pcapng format.
			if len(data) < 24 {
				t.Fatalf("%s too short", path)
			}
			_, err = ParseGlobalHeader(data[:24])
			if !errors.Is(err, ErrPcapNG) {
				t.Fatalf("expected ErrPcapNG, got %v", err)
			}

			// IngestPCAPStream must succeed (handles pcapng internally).
			h := sha256.New()
			fmt.Fprintf(h, "%s\x00", filepath.Base(path))
			h.Write(data)
			sessionID := binary.BigEndian.Uint64(h.Sum(nil)[0:8])

			if _, err := e2eClient.IngestPCAPStream(ctx, bytes.NewReader(data), sessionID, "test", nil); err != nil {
				t.Fatalf("IngestPCAPStream: %v", err)
			}

			// Exported bytes must be a valid classic PCAP stream.
			rc, _, err := e2eClient.Export(ctx, ExportOpts{SessionID: &sessionID})
			if err != nil {
				t.Fatalf("Export: %v", err)
			}
			out, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("Export read: %v", err)
			}
			if _, err := pcapgo.NewReader(bytes.NewReader(out)); err != nil {
				t.Fatalf("exported bytes are not valid PCAP: %v", err)
			}
		})
	}
}
