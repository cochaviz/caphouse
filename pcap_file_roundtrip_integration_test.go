//go:build integration

package caphouse

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
)

// packetReader abstracts over pcapgo.Reader and pcapgo.NgReader.
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

func TestPCAPFileRoundTrip(t *testing.T) {
	paths, err := filepath.Glob("testdata/*.pcap")
	if err != nil {
		t.Fatalf("glob testdata: %v", err)
	}
	if len(paths) == 0 {
		t.Skip("no pcap files in testdata/; skipping file roundtrip test")
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			input, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if len(input) < 24 {
				t.Fatalf("%s too short", path)
			}

			meta, err := ParseGlobalHeader(input[:24])
			if err != nil {
				t.Fatalf("parse global header: %v", err)
			}
			meta.CaptureID = uuid.New()
			meta.GlobalHeaderRaw = input[:24]

			reader, err := pcapgo.NewReader(bytes.NewReader(input))
			if err != nil {
				t.Fatalf("pcap reader: %v", err)
			}

			client := newMockClient(meta)
			ingestAll(t, client, meta.LinkType, reader)

			out, err := client.ExportCaptureBytes()
			if err != nil {
				t.Fatalf("export capture: %v", err)
			}
			if !bytes.Equal(out, input) {
				t.Fatalf("pcap bytes mismatch")
			}
		})
	}
}

// ingestAll reads all packets from reader into the client and returns the raw frames.
func ingestAll(t *testing.T, client *mockClient, linkType uint32, reader packetReader) [][]byte {
	t.Helper()
	var frames [][]byte
	var packetID uint64
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read packet: %v", err)
		}
		copied := make([]byte, len(data))
		copy(copied, data)
		frames = append(frames, copied)

		if err := client.IngestPacket(linkType, Packet{
			CaptureID: client.meta.CaptureID,
			PacketID:  packetID,
			Timestamp: ci.Timestamp,
			InclLen:   uint32(ci.CaptureLength),
			OrigLen:   uint32(ci.Length),
			Frame:     data,
		}); err != nil {
			t.Fatalf("ingest packet %d: %v", packetID, err)
		}
		packetID++
	}
	return frames
}
