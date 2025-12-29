package caphouse

import (
	"bytes"
	"net"
	"testing"
	"time"

	"caphouse/components"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

func findDot1QComponents(comps []components.ClickhouseMappedDecoder) []*components.Dot1QComponent {
	out := []*components.Dot1QComponent{}
	for _, comp := range comps {
		if tag, ok := comp.(*components.Dot1QComponent); ok {
			out = append(out, tag)
		}
	}
	return out
}

func sumHeaderLen(comps []components.ClickhouseMappedDecoder) int {
	total := 0
	for _, comp := range comps {
		if comp.Kind() == components.ComponentRawTail {
			continue
		}
		total += comp.HeaderLen()
	}
	return total
}

func TestCodecDot1QStackingRawTail(t *testing.T) {
	payload := bytes.Repeat([]byte{0x9a}, 18)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x22, 0x33, 0x44, 0x55, 0x66},
		DstMAC:       net.HardwareAddr{0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc},
		EthernetType: layers.EthernetTypeDot1Q,
	}
	tag1 := &layers.Dot1Q{
		VLANIdentifier: 10,
		Type:           layers.EthernetTypeDot1Q,
	}
	tag2 := &layers.Dot1Q{
		VLANIdentifier: 20,
		Type:           layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 30),
		DstIP:    net.IPv4(198, 51, 100, 40),
	}
	udp := &layers.UDP{SrcPort: 9000, DstPort: 9001}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("udp checksum: %v", err)
	}
	frame := serializeLayers(t, eth, tag1, tag2, ip4, udp, gopacket.Payload(payload))

	packet := Packet{
		CaptureID: uuid.New(),
		PacketID:  20,
		Timestamp: time.Unix(1700000400, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := EncodePacket(testLinkTypeEthernet, packet)
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentDot1Q) {
		t.Fatalf("expected dot1q component bit")
	}
	tags := findDot1QComponents(encoded.Components)
	if len(tags) != 2 {
		t.Fatalf("expected 2 dot1q components, got %d", len(tags))
	}
	seen := map[uint16]bool{
		tags[0].TagIndex: true,
		tags[1].TagIndex: true,
	}
	if !seen[0] || !seen[1] {
		t.Fatalf("dot1q tag indexes not set")
	}

	expectedOffset := sumHeaderLen(encoded.Components)
	if encoded.Nucleus.TailOffset != uint16(expectedOffset) {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, expectedOffset)
	}
	rawTail := findRawTailComponent(encoded.Components)
	if rawTail == nil {
		t.Fatalf("raw tail missing")
	}
	if !bytes.Equal(rawTail.Bytes, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
}

func TestCodecIPv4TCPStaysRawTail(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 32)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 3),
		DstIP:    net.IPv4(10, 0, 0, 4),
	}
	tcp := &layers.TCP{SrcPort: 80, DstPort: 12345, Seq: 1, Ack: 0}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("tcp checksum: %v", err)
	}
	frame := serializeLayers(t, eth, ip4, tcp, gopacket.Payload(payload))

	packet := Packet{
		CaptureID: uuid.New(),
		PacketID:  21,
		Timestamp: time.Unix(1700000401, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := EncodePacket(testLinkTypeEthernet, packet)
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("unexpected raw frame fallback")
	}
	if !hasComponentKind(encoded.Components, components.ComponentIPv4) {
		t.Fatalf("expected ipv4 component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentRawTail) {
		t.Fatalf("expected raw tail component")
	}
	rawTail := findRawTailComponent(encoded.Components)
	if rawTail == nil {
		t.Fatalf("raw tail missing")
	}
	if !bytes.Equal(rawTail.Bytes, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
}

func TestCodecIPv6ICMPStaysRawTail(t *testing.T) {
	payload := bytes.Repeat([]byte{0x6b}, 16)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02},
		DstMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x03, 0x04},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      net.ParseIP("2001:db8::10"),
		DstIP:      net.ParseIP("2001:db8::20"),
	}
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	if err := icmp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatalf("icmpv6 checksum: %v", err)
	}
	echo := &layers.ICMPv6Echo{
		Identifier: 0x1234,
		SeqNumber:  1,
	}
	frame := serializeLayers(t, eth, ip6, icmp, echo, gopacket.Payload(payload))

	packet := Packet{
		CaptureID: uuid.New(),
		PacketID:  22,
		Timestamp: time.Unix(1700000402, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := EncodePacket(testLinkTypeEthernet, packet)
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("unexpected raw frame fallback")
	}
	if !hasComponentKind(encoded.Components, components.ComponentIPv6) {
		t.Fatalf("expected ipv6 component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentRawTail) {
		t.Fatalf("expected raw tail component")
	}
	rawTail := findRawTailComponent(encoded.Components)
	if rawTail == nil {
		t.Fatalf("raw tail missing")
	}
	if !bytes.Equal(rawTail.Bytes, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
}
