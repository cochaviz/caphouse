package components

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseTCPLayer(t *testing.T, data []byte) *layers.TCP {
	t.Helper()
	pkt := gopacket.NewPacket(data, layers.LayerTypeTCP, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeTCP)
	if l == nil {
		t.Fatalf("failed to parse tcp layer")
	}
	return l.(*layers.TCP)
}

func buildTCPBytes(t *testing.T, tcp *layers.TCP) []byte {
	t.Helper()
	// Serialize without computing checksums since there's no network layer.
	return mustSerializeFixLengths(t, tcp)
}

func TestTCPEncodeBasic(t *testing.T) {
	tcp := &layers.TCP{
		SrcPort:    80,
		DstPort:    12345,
		Seq:        0xDEADBEEF,
		Ack:        0,
		DataOffset: 5,
		SYN:        true,
		Window:     65535,
	}
	data := buildTCPBytes(t, tcp)
	parsed := parseTCPLayer(t, data)

	enc := &TCPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*TCPComponent)

	if got.SrcPort != 80 {
		t.Errorf("SrcPort: got %d want 80", got.SrcPort)
	}
	if got.DstPort != 12345 {
		t.Errorf("DstPort: got %d want 12345", got.DstPort)
	}
	if got.Seq != 0xDEADBEEF {
		t.Errorf("Seq: got 0x%x want 0xDEADBEEF", got.Seq)
	}
	if got.Flags&TCPFlagSYN == 0 {
		t.Error("SYN flag not set")
	}
	if got.Flags&TCPFlagACK != 0 {
		t.Error("ACK flag unexpectedly set")
	}
	if got.Window != 65535 {
		t.Errorf("Window: got %d want 65535", got.Window)
	}
	if got.DataOffset != 5 {
		t.Errorf("DataOffset: got %d want 5", got.DataOffset)
	}
	if got.LayerSize() != 20 {
		t.Errorf("LayerSize: got %d want 20", got.LayerSize())
	}
}

func TestTCPEncodeAllStandardFlags(t *testing.T) {
	tcp := &layers.TCP{
		SrcPort:    1234,
		DstPort:    5678,
		DataOffset: 5,
		FIN:        true,
		SYN:        true,
		RST:        true,
		PSH:        true,
		ACK:        true,
		URG:        true,
		ECE:        true,
		CWR:        true,
	}
	data := buildTCPBytes(t, tcp)
	parsed := parseTCPLayer(t, data)

	enc := &TCPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got := comps[0].(*TCPComponent)

	for _, flag := range []struct {
		name string
		bit  uint16
	}{
		{"FIN", TCPFlagFIN},
		{"SYN", TCPFlagSYN},
		{"RST", TCPFlagRST},
		{"PSH", TCPFlagPSH},
		{"ACK", TCPFlagACK},
		{"URG", TCPFlagURG},
		{"ECE", TCPFlagECE},
		{"CWR", TCPFlagCWR},
	} {
		if got.Flags&flag.bit == 0 {
			t.Errorf("%s flag not set in encoded flags 0x%x", flag.name, got.Flags)
		}
	}
}

func TestTCPEncodeNSFlag(t *testing.T) {
	tcp := &layers.TCP{
		SrcPort:    1,
		DstPort:    2,
		DataOffset: 5,
		NS:         true,
	}
	data := buildTCPBytes(t, tcp)
	parsed := parseTCPLayer(t, data)

	enc := &TCPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got := comps[0].(*TCPComponent)
	if got.Flags&TCPFlagNS == 0 {
		t.Errorf("NS flag not set in encoded flags 0x%x", got.Flags)
	}
}

func TestTCPEncodeWithOptions(t *testing.T) {
	// MSS option: kind=2, length=4, value=1460 — 4 bytes total
	// NOP: kind=1 — 1 byte
	// NOP: kind=1 — 1 byte
	// Pad to 4-byte boundary: 2 more NOPs
	// Total options: 4 + 1 + 1 + 2 = 8 bytes → DataOffset = (20+8)/4 = 7
	tcp := &layers.TCP{
		SrcPort:    443,
		DstPort:    9999,
		DataOffset: 7,
		SYN:        true,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
		},
	}
	data := buildTCPBytes(t, tcp)
	parsed := parseTCPLayer(t, data)

	enc := &TCPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got := comps[0].(*TCPComponent)

	if len(got.OptionsRaw) == 0 {
		t.Fatal("expected OptionsRaw to be populated")
	}
	if got.DataOffset != 7 {
		t.Errorf("DataOffset: got %d want 7", got.DataOffset)
	}
	if got.LayerSize() != 28 {
		t.Errorf("LayerSize: got %d want 28", got.LayerSize())
	}
}

func TestTCPEncodeWrongLayer(t *testing.T) {
	enc := &TCPComponent{}
	_, err := enc.Encode(&layers.UDP{})
	if err == nil {
		t.Fatal("expected error for wrong layer type")
	}
}

func TestTCPReconstructInvalidDataOffset(t *testing.T) {
	// DataOffset = 4 means header length = 16 bytes, but minimum is 20 (DataOffset >= 5)
	comp := &TCPComponent{DataOffset: 4}
	if err := comp.Reconstruct(&DecodeContext{}); err == nil {
		t.Fatal("expected error for invalid data_offset < 5")
	}
}

func TestTCPRoundTrip(t *testing.T) {
	tcp := &layers.TCP{
		SrcPort:    8080,
		DstPort:    54321,
		Seq:        0x12345678,
		Ack:        0xABCDEF01,
		DataOffset: 5,
		ACK:        true,
		PSH:        true,
		Window:     8192,
		Urgent:     0,
	}
	data := buildTCPBytes(t, tcp)
	parsed := parseTCPLayer(t, data)

	enc := &TCPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}
