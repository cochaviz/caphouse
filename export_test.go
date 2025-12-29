package caphouse

import (
	"bytes"
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
	metaRow := captureMetaRow{
		Endianness:     meta.Endianness,
		Snaplen:        meta.Snaplen,
		LinkType:       meta.LinkType,
		TimeResolution: meta.TimeResolution,
	}

	var output bytes.Buffer
	if err := writePCAPHeader(&output, metaRow); err != nil {
		t.Fatalf("write output header: %v", err)
	}

	reader, err := pcapgo.NewReader(bytes.NewReader(inputBytes))
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	order := byteOrder(metaRow.Endianness)
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read input packet: %v", err)
		}
		if err := writePacketRecord(&output, order, ci.Timestamp, uint32(ci.CaptureLength), uint32(ci.Length), data); err != nil {
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
