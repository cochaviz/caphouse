package components

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseIPv6ExtLayer(t *testing.T, frame []byte, extType gopacket.LayerType) gopacket.Layer {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	l := pkt.Layer(extType)
	if l == nil {
		t.Fatalf("failed to parse ipv6 ext layer (%v) from frame", extType)
	}
	return l
}

func TestIPv6ExtEncodeHopByHop(t *testing.T) {
	// 8-byte Hop-by-Hop extension header: next=UDP(17), len=0 (means 8 bytes), 6 pad bytes
	hopByHopRaw := []byte{17, 0, 0, 0, 0, 0, 0, 0}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolIPv6HopByHop,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	frame := mustSerialize(t, eth, ip6, gopacket.Payload(append(hopByHopRaw, 0xde, 0xad)))
	parsed := parseIPv6ExtLayer(t, frame, layers.LayerTypeIPv6HopByHop)

	enc := &IPv6ExtComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*IPv6ExtComponent)
	if len(got.ExtRaw) == 0 {
		t.Fatal("ExtRaw is empty")
	}
	if got.ExtType != uint16(layers.LayerTypeIPv6HopByHop) {
		t.Errorf("ExtType: got %d want %d", got.ExtType, uint16(layers.LayerTypeIPv6HopByHop))
	}
}

func TestIPv6ExtSetIndex(t *testing.T) {
	comp := &IPv6ExtComponent{}
	if comp.Index() != 0 {
		t.Errorf("initial Index: got %d want 0", comp.Index())
	}
	comp.SetIndex(3)
	if comp.Index() != 3 {
		t.Errorf("Index after SetIndex(3): got %d want 3", comp.Index())
	}
}

func TestIPv6ExtReconstructTooShort(t *testing.T) {
	comp := &IPv6ExtComponent{
		ExtRaw: []byte{0x11}, // only 1 byte, need >= 2
	}
	if err := comp.Reconstruct(&DecodeContext{}); err == nil {
		t.Fatal("expected error for ExtRaw < 2 bytes")
	}
}

func TestIPv6ExtReconstructLengthMismatch(t *testing.T) {
	// ExtRaw has 4 bytes but HeaderLen() expects (len[1]+1)*8 = 8 bytes
	comp := &IPv6ExtComponent{
		ExtRaw: []byte{17, 0, 0, 0}, // len byte = 0 → HeaderLen = 8, but only 4 bytes
	}
	if err := comp.Reconstruct(&DecodeContext{}); err == nil {
		t.Fatal("expected error for ExtRaw length mismatch")
	}
}

func TestIPv6ExtRoundTrip(t *testing.T) {
	hopByHopRaw := []byte{17, 0, 0, 0, 0, 0, 0, 0}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolIPv6HopByHop,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	frame := mustSerialize(t, eth, ip6, gopacket.Payload(append(hopByHopRaw, 0x42)))
	parsed := parseIPv6ExtLayer(t, frame, layers.LayerTypeIPv6HopByHop)

	enc := &IPv6ExtComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}
