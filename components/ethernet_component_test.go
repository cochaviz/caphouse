package components

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseEthernetLayer(t *testing.T, frame []byte) *layers.Ethernet {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeEthernet)
	if l == nil {
		t.Fatalf("failed to parse ethernet layer from frame")
	}
	return l.(*layers.Ethernet)
}

func TestEthernetEncodeBasic(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	frame := mustSerialize(t, eth, gopacket.Payload([]byte{0xde, 0xad}))
	parsed := parseEthernetLayer(t, frame)

	enc := &EthernetComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*EthernetComponent)
	if !bytes.Equal(got.SrcMAC, net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Errorf("SrcMAC mismatch: %x", got.SrcMAC)
	}
	if !bytes.Equal(got.DstMAC, net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}) {
		t.Errorf("DstMAC mismatch: %x", got.DstMAC)
	}
	if got.EtherType != uint16(layers.EthernetTypeIPv4) {
		t.Errorf("EtherType: got 0x%x want 0x%x", got.EtherType, uint16(layers.EthernetTypeIPv4))
	}
	if got.LayerSize() != 14 {
		t.Errorf("LayerSize: got %d want 14", got.LayerSize())
	}
	if got.Kind() != ComponentEthernet {
		t.Errorf("Kind: got %d want %d", got.Kind(), ComponentEthernet)
	}
}

func TestEthernetEncodeWrongLayer(t *testing.T) {
	enc := &EthernetComponent{}
	_, err := enc.Encode(&layers.IPv4{})
	if err == nil {
		t.Fatal("expected error for wrong layer type")
	}
}

func TestEthernetReconstructInvalidMAC(t *testing.T) {
	comp := &EthernetComponent{
		SrcMAC: []byte{0x00, 0x11}, // too short
		DstMAC: []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
	}
	if err := comp.Reconstruct(&DecodeContext{}); err == nil {
		t.Fatal("expected error for invalid SrcMAC length")
	}
}

func TestEthernetReconstructAddsLayer(t *testing.T) {
	comp := &EthernetComponent{
		SrcMAC:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:    []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EtherType: uint16(layers.EthernetTypeIPv4),
	}
	ctx := &DecodeContext{}
	if err := comp.Reconstruct(ctx); err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if len(ctx.Layers) != 1 {
		t.Fatalf("expected 1 layer, got %d", len(ctx.Layers))
	}
	if ctx.Offset != 14 {
		t.Errorf("Offset: got %d want 14", ctx.Offset)
	}
}

func TestEthernetRoundTrip(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv6,
	}
	frame := mustSerialize(t, eth, gopacket.Payload([]byte{0x01, 0x02, 0x03}))
	parsed := parseEthernetLayer(t, frame)
	wantHeader := parsed.LayerContents() // 14-byte ethernet header

	enc := &EthernetComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	ctx := &DecodeContext{}
	if err := comps[0].(LayerDecoder).Reconstruct(ctx); err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, ctx.Layers...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// gopacket pads ethernet frames to 60 bytes minimum; only compare the header.
	got := buf.Bytes()
	if len(got) < 14 || !bytes.Equal(got[:14], wantHeader) {
		t.Fatalf("ethernet header mismatch:\n  got:  %x\n  want: %x", got[:14], wantHeader)
	}
}
