package components

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseIPv4Layer(t *testing.T, frame []byte) *layers.IPv4 {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeIPv4)
	if l == nil {
		t.Fatalf("failed to parse ipv4 layer from frame")
	}
	return l.(*layers.IPv4)
}

func buildIPv4Frame(t *testing.T, ip4 *layers.IPv4, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	return mustSerialize(t, eth, ip4, gopacket.Payload(payload))
}

func TestIPv4EncodeBasic(t *testing.T) {
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 1),
		DstIP:    net.IPv4(198, 51, 100, 2),
	}
	frame := buildIPv4Frame(t, ip4, []byte{0x01, 0x02, 0x03, 0x04})
	parsed := parseIPv4Layer(t, frame)

	enc := &IPv4Component{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*IPv4Component)

	if got.Protocol != uint8(layers.IPProtocolUDP) {
		t.Errorf("Protocol: got %d want %d", got.Protocol, uint8(layers.IPProtocolUDP))
	}
	wantSrc, _ := netip.ParseAddr("192.0.2.1")
	wantDst, _ := netip.ParseAddr("198.51.100.2")
	if got.SrcIP4.String() != wantSrc.String() {
		t.Errorf("SrcIP: got %s want %s", got.SrcIP4, wantSrc)
	}
	if got.DstIP4.String() != wantDst.String() {
		t.Errorf("DstIP: got %s want %s", got.DstIP4, wantDst)
	}
	if got.IPv4IHL != 5 {
		t.Errorf("IHL: got %d want 5", got.IPv4IHL)
	}
	if got.IPv4TTL != 64 {
		t.Errorf("TTL: got %d want 64", got.IPv4TTL)
	}
	if len(got.OptionsRaw) != 0 {
		t.Errorf("OptionsRaw: expected empty, got %d bytes", len(got.OptionsRaw))
	}
	if got.HeaderLen() != 20 {
		t.Errorf("HeaderLen: got %d want 20", got.HeaderLen())
	}
}

func TestIPv4EncodeWithOptions(t *testing.T) {
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      128,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
		Options: []layers.IPv4Option{
			{OptionType: 1, OptionLength: 1},
			{OptionType: 1, OptionLength: 1},
			{OptionType: 1, OptionLength: 1},
			{OptionType: 1, OptionLength: 1},
		},
	}
	frame := buildIPv4Frame(t, ip4, []byte{0xaa, 0xbb})
	parsed := parseIPv4Layer(t, frame)

	enc := &IPv4Component{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got := comps[0].(*IPv4Component)
	if len(got.OptionsRaw) == 0 {
		t.Fatalf("expected OptionsRaw to be populated")
	}
	if got.IPv4IHL != 6 { // 20 + 4 option bytes = 24, IHL = 24/4 = 6
		t.Errorf("IHL: got %d want 6", got.IPv4IHL)
	}
	if got.HeaderLen() != 24 {
		t.Errorf("HeaderLen: got %d want 24", got.HeaderLen())
	}
}

func TestIPv4EncodeWrongLayer(t *testing.T) {
	enc := &IPv4Component{}
	_, err := enc.Encode(&layers.Ethernet{})
	if err == nil {
		t.Fatal("expected error for wrong layer type")
	}
}

func TestIPv4RoundTrip(t *testing.T) {
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		TOS:      16,
		SrcIP:    net.IPv4(203, 0, 113, 1),
		DstIP:    net.IPv4(203, 0, 113, 2),
	}
	frame := buildIPv4Frame(t, ip4, []byte{0x01})
	parsed := parseIPv4Layer(t, frame)

	enc := &IPv4Component{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}

func TestIPv4RoundTripWithOptions(t *testing.T) {
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 168, 1, 1),
		DstIP:    net.IPv4(192, 168, 1, 2),
		Options: []layers.IPv4Option{
			{OptionType: 1, OptionLength: 1},
			{OptionType: 1, OptionLength: 1},
			{OptionType: 1, OptionLength: 1},
			{OptionType: 1, OptionLength: 1},
		},
	}
	frame := buildIPv4Frame(t, ip4, []byte{0x01})
	parsed := parseIPv4Layer(t, frame)

	enc := &IPv4Component{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}

func TestIPv4ReconstructOptionsNotMultipleOf4(t *testing.T) {
	comp := &IPv4Component{
		IPv4IHL:    6,
		OptionsRaw: []byte{0x01, 0x02, 0x03}, // 3 bytes — not multiple of 4
	}
	if err := comp.Reconstruct(&DecodeContext{}); err == nil {
		t.Fatal("expected error for options not multiple of 4")
	}
}

func TestIPv4ReconstructIHLMismatch(t *testing.T) {
	// IHL=7 implies 28-byte header, but OptionsRaw has only 4 bytes (IHL should be 6).
	comp := &IPv4Component{
		IPv4IHL:    7, // claims 28 bytes but options only have 4 bytes (total would be 24)
		OptionsRaw: bytes.Repeat([]byte{0x01}, 4),
	}
	if err := comp.Reconstruct(&DecodeContext{}); err == nil {
		t.Fatal("expected error for IHL/options length mismatch")
	}
}
