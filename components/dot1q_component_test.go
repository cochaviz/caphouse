package components

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseDot1QLayer(t *testing.T, frame []byte) *layers.Dot1Q {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeDot1Q)
	if l == nil {
		t.Fatalf("failed to parse dot1q layer from frame")
	}
	return l.(*layers.Dot1Q)
}

func TestDot1QEncodeBasic(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeDot1Q,
	}
	tag := &layers.Dot1Q{
		VLANIdentifier: 42,
		Priority:       3,
		DropEligible:   true,
		Type:           layers.EthernetTypeIPv4,
	}
	frame := mustSerialize(t, eth, tag, gopacket.Payload([]byte{0x01}))
	parsed := parseDot1QLayer(t, frame)

	enc := &Dot1QComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*Dot1QComponent)
	if got.VLANID != 42 {
		t.Errorf("VLANID: got %d want 42", got.VLANID)
	}
	if got.Priority != 3 {
		t.Errorf("Priority: got %d want 3", got.Priority)
	}
	if got.DropEligible != 1 {
		t.Errorf("DropEligible: got %d want 1", got.DropEligible)
	}
	if got.EtherType != uint16(layers.EthernetTypeIPv4) {
		t.Errorf("EtherType: got 0x%x", got.EtherType)
	}
	if got.HeaderLen() != 4 {
		t.Errorf("HeaderLen: got %d want 4", got.HeaderLen())
	}
}

func TestDot1QEncodeWrongLayer(t *testing.T) {
	enc := &Dot1QComponent{}
	_, err := enc.Encode(&layers.Ethernet{})
	if err == nil {
		t.Fatal("expected error for wrong layer type")
	}
}

func TestDot1QSetIndex(t *testing.T) {
	comp := &Dot1QComponent{}
	if comp.Index() != 0 {
		t.Errorf("initial Index: got %d want 0", comp.Index())
	}
	comp.SetIndex(7)
	if comp.Index() != 7 {
		t.Errorf("Index after SetIndex(7): got %d want 7", comp.Index())
	}
}

func TestDot1QRoundTrip(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		EthernetType: layers.EthernetTypeDot1Q,
	}
	tag := &layers.Dot1Q{
		VLANIdentifier: 100,
		Priority:       5,
		DropEligible:   false,
		Type:           layers.EthernetTypeIPv6,
	}
	frame := mustSerialize(t, eth, tag, gopacket.Payload([]byte{0xff}))
	parsed := parseDot1QLayer(t, frame)

	enc := &Dot1QComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}
