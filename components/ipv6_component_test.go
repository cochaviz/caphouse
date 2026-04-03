package components

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseIPv6Layer(t *testing.T, frame []byte) *layers.IPv6 {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeIPv6)
	if l == nil {
		t.Fatalf("failed to parse ipv6 layer from frame")
	}
	return l.(*layers.IPv6)
}

func buildIPv6Frame(t *testing.T, ip6 *layers.IPv6, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv6,
	}
	return mustSerialize(t, eth, ip6, gopacket.Payload(payload))
}

func TestIPv6EncodeBasic(t *testing.T) {
	ip6 := &layers.IPv6{
		Version:      6,
		HopLimit:     64,
		TrafficClass: 0xAB,
		NextHeader:   layers.IPProtocolUDP,
		SrcIP:        net.ParseIP("2001:db8::1"),
		DstIP:        net.ParseIP("2001:db8::2"),
	}
	frame := buildIPv6Frame(t, ip6, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	parsed := parseIPv6Layer(t, frame)

	enc := &IPv6Component{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*IPv6Component)

	if got.Protocol != uint8(layers.IPProtocolUDP) {
		t.Errorf("Protocol: got %d want %d", got.Protocol, uint8(layers.IPProtocolUDP))
	}
	if got.IPv6HopLimit != 64 {
		t.Errorf("HopLimit: got %d want 64", got.IPv6HopLimit)
	}
	if got.IPv6TrafficClass != 0xAB {
		t.Errorf("TrafficClass: got 0x%x want 0xAB", got.IPv6TrafficClass)
	}
	if got.SrcIP6.String() != "2001:db8::1" {
		t.Errorf("SrcIP: got %s want 2001:db8::1", got.SrcIP6)
	}
	if got.DstIP6.String() != "2001:db8::2" {
		t.Errorf("DstIP: got %s want 2001:db8::2", got.DstIP6)
	}
	if got.LayerSize() != 40 {
		t.Errorf("LayerSize: got %d want 40", got.LayerSize())
	}
}

func TestIPv6EncodeWrongLayer(t *testing.T) {
	enc := &IPv6Component{}
	_, err := enc.Encode(&layers.Ethernet{})
	if err == nil {
		t.Fatal("expected error for wrong layer type")
	}
}

func TestIPv6RoundTrip(t *testing.T) {
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   128,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      net.ParseIP("::1"),
		DstIP:      net.ParseIP("::2"),
	}
	frame := buildIPv6Frame(t, ip6, []byte{0x01})
	parsed := parseIPv6Layer(t, frame)

	enc := &IPv6Component{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}
