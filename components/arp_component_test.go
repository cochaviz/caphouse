package components

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildARPLayer(op uint16, senderMAC net.HardwareAddr, senderIP, targetIP net.IP, targetMAC net.HardwareAddr) *layers.ARP {
	return &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   senderMAC,
		SourceProtAddress: senderIP.To4(),
		DstHwAddress:      targetMAC,
		DstProtAddress:    targetIP.To4(),
	}
}

func parseARPLayer(t *testing.T, data []byte) *layers.ARP {
	t.Helper()
	pkt := gopacket.NewPacket(data, layers.LayerTypeARP, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeARP)
	if l == nil {
		t.Fatalf("failed to parse arp layer")
	}
	return l.(*layers.ARP)
}

func TestARPEncodeRequest(t *testing.T) {
	senderMAC := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	targetMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	senderIP := net.ParseIP("192.168.1.10")
	targetIP := net.ParseIP("192.168.1.1")

	arp := buildARPLayer(layers.ARPRequest, senderMAC, senderIP, targetIP, targetMAC)
	data := mustSerialize(t, arp)
	parsed := parseARPLayer(t, data)

	enc := &ARPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*ARPComponent)

	if got.ArpOp != layers.ARPRequest {
		t.Errorf("ArpOp: got %d want %d (Request)", got.ArpOp, layers.ARPRequest)
	}
	if !bytes.Equal(got.SenderMAC[:], senderMAC) {
		t.Errorf("SenderMAC: got %x want %x", got.SenderMAC, senderMAC)
	}
	if !bytes.Equal(got.TargetMAC[:], targetMAC) {
		t.Errorf("TargetMAC: got %x want %x", got.TargetMAC, targetMAC)
	}
	if !got.SenderIP.Equal(senderIP) {
		t.Errorf("SenderIP: got %v want %v", got.SenderIP, senderIP)
	}
	if !got.TargetIP.Equal(targetIP) {
		t.Errorf("TargetIP: got %v want %v", got.TargetIP, targetIP)
	}
}

func TestARPEncodeReply(t *testing.T) {
	senderMAC := net.HardwareAddr{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02}
	targetMAC := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	senderIP := net.ParseIP("192.168.1.1")
	targetIP := net.ParseIP("192.168.1.10")

	arp := buildARPLayer(layers.ARPReply, senderMAC, senderIP, targetIP, targetMAC)
	data := mustSerialize(t, arp)
	parsed := parseARPLayer(t, data)

	enc := &ARPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got := comps[0].(*ARPComponent)

	if got.ArpOp != layers.ARPReply {
		t.Errorf("ArpOp: got %d want %d (Reply)", got.ArpOp, layers.ARPReply)
	}
	if !got.SenderIP.Equal(senderIP) {
		t.Errorf("SenderIP: got %v want %v", got.SenderIP, senderIP)
	}
	if !got.TargetIP.Equal(targetIP) {
		t.Errorf("TargetIP: got %v want %v", got.TargetIP, targetIP)
	}
}

func TestARPEncodeWrongLayer(t *testing.T) {
	enc := &ARPComponent{}
	_, err := enc.Encode(&layers.UDP{})
	if err == nil {
		t.Fatal("expected error for wrong layer type")
	}
}

func TestARPMetadata(t *testing.T) {
	c := &ARPComponent{}
	if c.Kind() != ComponentARP {
		t.Errorf("Kind: got %d want %d", c.Kind(), ComponentARP)
	}
	if ComponentTable(c) != "pcap_arp" {
		t.Errorf("Table: got %q want %q", ComponentTable(c), "pcap_arp")
	}
	if c.LayerSize() != 28 {
		t.Errorf("LayerSize: got %d want 28", c.LayerSize())
	}
}

func TestARPReconstructAddsLayer(t *testing.T) {
	comp := &ARPComponent{
		ArpOp:     layers.ARPRequest,
		SenderMAC: [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		SenderIP:  net.ParseIP("10.0.0.1").To4(),
		TargetMAC: [6]byte{},
		TargetIP:  net.ParseIP("10.0.0.2").To4(),
	}
	ctx := &DecodeContext{}
	if err := comp.Reconstruct(ctx); err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if len(ctx.Layers) != 1 {
		t.Fatalf("expected 1 layer, got %d", len(ctx.Layers))
	}
	if ctx.Offset != 28 {
		t.Errorf("Offset: got %d want 28", ctx.Offset)
	}
}

func TestARPRoundTrip(t *testing.T) {
	senderMAC := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	targetMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	senderIP := net.ParseIP("172.16.0.5")
	targetIP := net.ParseIP("172.16.0.1")

	arp := buildARPLayer(layers.ARPRequest, senderMAC, senderIP, targetIP, targetMAC)
	data := mustSerialize(t, arp)
	parsed := parseARPLayer(t, data)

	enc := &ARPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}
