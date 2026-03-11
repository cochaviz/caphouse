package caphouse

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type packetExpect struct {
	data []byte
	ts   time.Time
}

func TestPCAPExportRoundTrip(t *testing.T) {
	packets := []packetExpect{
		{data: []byte{0x00, 0x01, 0x02, 0x03}, ts: time.Unix(1700000000, 123456000)},
		{data: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}, ts: time.Unix(1700000001, 999000000)},
	}

	var input bytes.Buffer
	writer := pcapgo.NewWriter(&input)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write header: %v", err)
	}
	for _, pkt := range packets {
		ci := gopacket.CaptureInfo{
			Timestamp:     pkt.ts,
			CaptureLength: len(pkt.data),
			Length:        len(pkt.data),
		}
		if err := writer.WritePacket(ci, pkt.data); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}

	inputBytes := input.Bytes()
	if len(inputBytes) < 24 {
		t.Fatalf("pcap too short")
	}

	meta, err := ParseGlobalHeader(inputBytes[:24])
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	var output bytes.Buffer
	if err := writePCAPHeader(&output, meta); err != nil {
		t.Fatalf("write output header: %v", err)
	}

	reader, err := pcapgo.NewReader(bytes.NewReader(inputBytes))
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	order := byteOrder(meta.Endianness)
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read input packet: %v", err)
		}
		if err := writePacketRecord(&output, order, meta.TimeResolution, ci.Timestamp, uint32(ci.CaptureLength), uint32(ci.Length), data); err != nil {
			t.Fatalf("write output packet: %v", err)
		}
	}

	outReader, err := pcapgo.NewReader(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if got, want := outReader.Snaplen(), meta.Snaplen; got != want {
		t.Fatalf("snaplen mismatch: got %d want %d", got, want)
	}
	if got, want := outReader.LinkType(), layers.LinkType(meta.LinkType); got != want {
		t.Fatalf("linktype mismatch: got %d want %d", got, want)
	}

	for i, expect := range packets {
		data, ci, err := outReader.ReadPacketData()
		if err != nil {
			t.Fatalf("read output packet %d: %v", i, err)
		}
		if !bytes.Equal(data, expect.data) {
			t.Fatalf("packet %d data mismatch", i)
		}
		if ci.Timestamp.Unix() != expect.ts.Unix() || ci.Timestamp.Nanosecond()/1000 != expect.ts.Nanosecond()/1000 {
			t.Fatalf("packet %d timestamp mismatch", i)
		}
	}
}

// TestTimeResolutionRoundTrip verifies that both "us" and "ns" PCAP files
// round-trip timestamps correctly through writePCAPHeader + writePacketRecord.
func TestTimeResolutionRoundTrip(t *testing.T) {
	// ts has sub-microsecond nanosecond precision to distinguish us from ns.
	ts := time.Unix(1700000000, 123456789) // .123456789s — truncates to .123456µs

	tests := []struct {
		name    string
		magic   []byte // first 4 bytes of global header (LE)
		timeRes string
		wantNs  int // expected Nanosecond() after round-trip
	}{
		{
			name:    "us",
			magic:   []byte{0xD4, 0xC3, 0xB2, 0xA1}, // LE µs magic
			timeRes: "us",
			wantNs:  123456000, // truncated to microsecond
		},
		{
			name:    "ns",
			magic:   []byte{0x4D, 0x3C, 0xB2, 0xA1}, // LE ns magic
			timeRes: "ns",
			wantNs:  123456789, // preserved to nanosecond
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Build a minimal PCAP global header with the given magic.
			var rawHdr [24]byte
			copy(rawHdr[:4], tc.magic)
			binary.LittleEndian.PutUint16(rawHdr[4:6], 2)
			binary.LittleEndian.PutUint16(rawHdr[6:8], 4)
			binary.LittleEndian.PutUint32(rawHdr[16:20], 65535)
			binary.LittleEndian.PutUint32(rawHdr[20:24], 1) // Ethernet

			meta, err := ParseGlobalHeader(rawHdr[:])
			if err != nil {
				t.Fatalf("ParseGlobalHeader: %v", err)
			}
			if meta.TimeResolution != tc.timeRes {
				t.Fatalf("TimeResolution = %q, want %q", meta.TimeResolution, tc.timeRes)
			}

			frame := []byte{0xde, 0xad, 0xbe, 0xef}
			var out bytes.Buffer
			if err := writePCAPHeader(&out, meta); err != nil {
				t.Fatalf("writePCAPHeader: %v", err)
			}
			order := byteOrder(meta.Endianness)
			if err := writePacketRecord(&out, order, meta.TimeResolution, ts, uint32(len(frame)), uint32(len(frame)), frame); err != nil {
				t.Fatalf("writePacketRecord: %v", err)
			}

			// The written header must be byte-for-byte identical to the input
			// (including the magic, so a reader detects the correct resolution).
			if !bytes.Equal(out.Bytes()[:24], rawHdr[:]) {
				t.Fatalf("global header mismatch: got %x want %x", out.Bytes()[:24], rawHdr[:])
			}

			// Parse back and verify timestamp precision.
			r, err := pcapgo.NewReader(bytes.NewReader(out.Bytes()))
			if err != nil {
				t.Fatalf("NewReader: %v", err)
			}
			_, ci, err := r.ReadPacketData()
			if err != nil {
				t.Fatalf("ReadPacketData: %v", err)
			}
			if ci.Timestamp.Unix() != ts.Unix() {
				t.Fatalf("seconds mismatch: got %d want %d", ci.Timestamp.Unix(), ts.Unix())
			}
			if ci.Timestamp.Nanosecond() != tc.wantNs {
				t.Fatalf("nanosecond field: got %d want %d", ci.Timestamp.Nanosecond(), tc.wantNs)
			}
		})
	}
}
