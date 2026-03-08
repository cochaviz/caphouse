package components

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseUDPLayer(t *testing.T, data []byte) *layers.UDP {
	t.Helper()
	pkt := gopacket.NewPacket(data, layers.LayerTypeUDP, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeUDP)
	if l == nil {
		t.Fatalf("failed to parse udp layer")
	}
	return l.(*layers.UDP)
}

func TestUDPEncodeBasic(t *testing.T) {
	udp := &layers.UDP{
		SrcPort: 1234,
		DstPort: 53,
	}
	// FixLengths computes the UDP length field; no checksum needed without IP layer.
	data := mustSerializeFixLengths(t, udp, gopacket.Payload([]byte{0x01, 0x02}))
	parsed := parseUDPLayer(t, data)

	enc := &UDPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*UDPComponent)

	if got.SrcPort != 1234 {
		t.Errorf("SrcPort: got %d want 1234", got.SrcPort)
	}
	if got.DstPort != 53 {
		t.Errorf("DstPort: got %d want 53", got.DstPort)
	}
	if got.Length != 10 { // 8-byte header + 2 bytes payload
		t.Errorf("Length: got %d want 10", got.Length)
	}
	if got.HeaderLen() != 8 {
		t.Errorf("HeaderLen: got %d want 8", got.HeaderLen())
	}
}

func TestUDPEncodeWrongLayer(t *testing.T) {
	enc := &UDPComponent{}
	_, err := enc.Encode(&layers.TCP{})
	if err == nil {
		t.Fatal("expected error for wrong layer type")
	}
}

func TestUDPRoundTrip(t *testing.T) {
	udp := &layers.UDP{
		SrcPort: 9000,
		DstPort: 9001,
	}
	data := mustSerializeFixLengths(t, udp, gopacket.Payload([]byte{0xca, 0xfe}))
	parsed := parseUDPLayer(t, data)

	enc := &UDPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}
