//go:build integration

package caphouse

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

// TestParseNgCaptureMeta verifies that ParseNgCaptureMeta extracts correct
// metadata from a pcapng file.
func TestParseNgCaptureMeta(t *testing.T) {
	paths, err := filepath.Glob("testdata/*.pcapng")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) == 0 {
		t.Skip("no pcapng files in testdata/; skipping")
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			meta, _, err := ParseNgCaptureMeta(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("ParseNgCaptureMeta: %v", err)
			}
			if meta.Endianness != "le" {
				t.Errorf("Endianness = %q, want %q", meta.Endianness, "le")
			}
			if meta.TimeResolution != "us" {
				t.Errorf("TimeResolution = %q, want %q", meta.TimeResolution, "us")
			}
			if meta.Snaplen == 0 {
				t.Error("Snaplen is 0")
			}
		})
	}
}

// TestPcapNgToClassicRoundTrip ingests a pcapng file through the mock client
// and verifies that all packet frames are present in the classic PCAP output.
func TestPcapNgToClassicRoundTrip(t *testing.T) {
	paths, err := filepath.Glob("testdata/*.pcapng")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) == 0 {
		t.Skip("no pcapng files in testdata/; skipping")
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			input, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			meta, ngr, err := ParseNgCaptureMeta(bytes.NewReader(input))
			if err != nil {
				t.Fatalf("ParseNgCaptureMeta: %v", err)
			}
			meta.SessionID = 1
			client := newMockClient(meta)
			wantFrames := ingestAll(t, client, meta.LinkType, ngr)

			out, err := client.ExportCaptureBytes()
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			outReader, err := pcapgo.NewReader(bytes.NewReader(out))
			if err != nil {
				t.Fatalf("read exported pcap: %v", err)
			}
			for i, want := range wantFrames {
				got, _, err := outReader.ReadPacketData()
				if err != nil {
					t.Fatalf("read output packet %d: %v", i, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("packet %d frame mismatch", i)
				}
			}
			if _, _, err := outReader.ReadPacketData(); !errors.Is(err, io.EOF) {
				t.Fatalf("expected EOF after all packets")
			}
		})
	}
}

// TestSyntheticHeaderWarning verifies that the synthetic-header warning fires
// only when GlobalHeaderRaw is absent (pcapng-sourced captures) and never for
// classical PCAP captures where the raw header is preserved.
func TestSyntheticHeaderWarning(t *testing.T) {
	// Classical PCAP: ParseGlobalHeader must populate GlobalHeaderRaw.
	classicPaths, err := filepath.Glob("testdata/*.pcap")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, path := range classicPaths {
		data, err := os.ReadFile(path)
		if err != nil || len(data) < 24 {
			continue
		}
		meta, err := ParseGlobalHeader(data[:24])
		if err != nil {
			continue // skip pcapng files accidentally named .pcap
		}
		if len(meta.GlobalHeaderRaw) != 24 {
			t.Errorf("classical PCAP %s: GlobalHeaderRaw has %d bytes, want 24 — synthetic-header warning would fire on export", path, len(meta.GlobalHeaderRaw))
		}
	}

	// PCAPng: ParseNgCaptureMeta must NOT populate GlobalHeaderRaw.
	ngPaths, err := filepath.Glob("testdata/*.pcapng")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(ngPaths) == 0 {
		t.Log("no pcapng files in testdata/; skipping pcapng half of test")
	}
	for _, path := range ngPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		meta, _, err := ParseNgCaptureMeta(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("ParseNgCaptureMeta %s: %v", path, err)
		}
		if len(meta.GlobalHeaderRaw) == 24 {
			t.Errorf("pcapng %s: GlobalHeaderRaw unexpectedly set to 24 bytes — synthetic-header warning would NOT fire on export", path)
		}
	}
}
