package components

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildLinuxSLLFrame builds a raw Linux SLL (LINKTYPE_LINUX_SLL) frame.
// SLL header is 16 bytes: pktType(2) + addrType(2) + addrLen(2) + addr(8) + etherType(2).
func buildLinuxSLLFrame(pktType uint16, addr []byte, etherType uint16, payload []byte) []byte {
	hdr := make([]byte, 16)
	binary.BigEndian.PutUint16(hdr[0:2], pktType)
	binary.BigEndian.PutUint16(hdr[2:4], 1) // ARPHRD_ETHER
	binary.BigEndian.PutUint16(hdr[4:6], 6) // addrLen
	copy(hdr[6:14], addr)
	binary.BigEndian.PutUint16(hdr[14:16], etherType)
	return append(hdr, payload...)
}

func parseLinuxSLLLayer(t *testing.T, frame []byte) *layers.LinuxSLL {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeLinuxSLL, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeLinuxSLL)
	if l == nil {
		t.Fatalf("failed to parse linux sll layer from frame")
	}
	return l.(*layers.LinuxSLL)
}

func TestLinuxSLLEncodeBasic(t *testing.T) {
	addr := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00}
	frame := buildLinuxSLLFrame(0, addr, uint16(layers.EthernetTypeIPv4), []byte{0x01, 0x02})
	parsed := parseLinuxSLLLayer(t, frame)

	enc := &LinuxSLLComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*LinuxSLLComponent)

	if len(got.L2HdrRaw) == 0 {
		t.Fatal("L2HdrRaw is empty")
	}
	if got.L2Len != uint16(len(got.L2HdrRaw)) {
		t.Errorf("L2Len mismatch: got %d, len(L2HdrRaw)=%d", got.L2Len, len(got.L2HdrRaw))
	}
	if got.Kind() != ComponentLinuxSLL {
		t.Errorf("Kind: got %d want %d", got.Kind(), ComponentLinuxSLL)
	}
}

func TestLinuxSLLEncodeWrongLayer(t *testing.T) {
	enc := &LinuxSLLComponent{}
	_, err := enc.Encode(&layers.Ethernet{})
	if err == nil {
		t.Fatal("expected error for wrong layer type")
	}
}

func TestLinuxSLLReconstructEmpty(t *testing.T) {
	comp := &LinuxSLLComponent{L2HdrRaw: nil}
	if err := comp.Reconstruct(&DecodeContext{}); err == nil {
		t.Fatal("expected error for empty L2HdrRaw")
	}
}

func TestLinuxSLLReconstructLenMismatch(t *testing.T) {
	comp := &LinuxSLLComponent{
		L2Len:    20, // claims 20 bytes
		L2HdrRaw: []byte{0x01, 0x02, 0x03}, // only 3 bytes
	}
	if err := comp.Reconstruct(&DecodeContext{}); err == nil {
		t.Fatal("expected error for L2Len mismatch")
	}
}

func TestLinuxSLLRoundTrip(t *testing.T) {
	addr := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x00}
	frame := buildLinuxSLLFrame(0, addr, uint16(layers.EthernetTypeIPv6), []byte{0xff})
	parsed := parseLinuxSLLLayer(t, frame)

	enc := &LinuxSLLComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}
