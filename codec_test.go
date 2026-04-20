package caphouse

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cochaviz/caphouse/components"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	testLinkTypeEthernet = 1
	testLinkTypeRaw      = 101
	testEtherTypeIPv4    = 0x0800
	testEtherTypeIPv6    = 0x86DD
)

func hasComponentKind(comps []components.Component, kind uint) bool {
	for _, comp := range comps {
		if comp.Kind() == kind {
			return true
		}
	}
	return false
}

func serializeLayers(t *testing.T, layers ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, layers...); err != nil {
		t.Fatalf("serialize layers: %v", err)
	}
	out := buf.Bytes()
	if len(out) == 0 {
		t.Fatalf("empty serialized frame")
	}
	copied := make([]byte, len(out))
	copy(copied, out)
	return copied
}

func TestCodecEncodeDecodeIPv4Ethernet(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	ipHeader := buildIPv4Header(nil, len(payload))
	frame := buildEthernetFrame(testEtherTypeIPv4, append(ipHeader, payload...))

	packet := Packet{
		SessionID: 1,
		PacketID:  1,
		Timestamp: time.Unix(1700000000, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := encodePacket(testLinkTypeEthernet, packet)
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentEthernet) {
		t.Fatalf("expected ethernet component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentIPv4) {
		t.Fatalf("expected ipv4 component")
	}

	wantTailOffset := uint16(14 + 20)
	if encoded.Nucleus.TailOffset != wantTailOffset {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, wantTailOffset)
	}
	if !bytes.Equal(encoded.Nucleus.Payload, payload) {
		t.Fatalf("raw tail mismatch")
	}

	reconstructed, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(reconstructed, frame) {
		t.Fatalf("reconstructed frame mismatch")
	}
}

func TestCodecIPv6WithHopByHop(t *testing.T) {
	payload := []byte{0x11, 0x22, 0x33, 0x44}
	ext := []byte{17, 0, 0, 0, 0, 0, 0, 0}
	ipHeader := buildIPv6Header(len(ext)+len(payload), 0, 64, 0xAB)
	ipHeader = append(ipHeader, ext...)
	frame := buildEthernetFrame(testEtherTypeIPv6, append(ipHeader, payload...))

	packet := Packet{
		SessionID: 1,
		PacketID:  3,
		Timestamp: time.Unix(1700000002, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := encodePacket(testLinkTypeEthernet, packet)
	if !hasComponentKind(encoded.Components, components.ComponentIPv6) {
		t.Fatalf("ipv6 component missing")
	}
	if !hasComponentKind(encoded.Components, components.ComponentIPv6Ext) {
		t.Fatalf("ipv6 ext component missing")
	}

	reconstructed, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(reconstructed, frame) {
		t.Fatalf("reconstructed frame mismatch")
	}
}

func TestCodecNonIPFallback(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02, 0x03}
	frame := buildEthernetFrame(0x0806, payload)

	packet := Packet{
		SessionID: 1,
		PacketID:  4,
		Timestamp: time.Unix(1700000003, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := encodePacket(testLinkTypeEthernet, packet)
	if hasComponentKind(encoded.Components, components.ComponentIPv4) || hasComponentKind(encoded.Components, components.ComponentIPv6) {
		t.Fatalf("expected no ip component")
	}
	if encoded.Nucleus.TailOffset != 14 {
		t.Fatalf("tail_offset mismatch: got %d want 14", encoded.Nucleus.TailOffset)
	}

	reconstructed, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(reconstructed, frame) {
		t.Fatalf("reconstructed frame mismatch")
	}
}

func TestCodecRawLinkType(t *testing.T) {
	payload := []byte{0x99, 0x98, 0x97}
	ipHeader := buildIPv4Header(nil, len(payload))
	frame := append(ipHeader, payload...)

	packet := Packet{
		SessionID: 1,
		PacketID:  5,
		Timestamp: time.Unix(1700000004, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := encodePacket(testLinkTypeRaw, packet)
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentEthernet) {
		t.Fatalf("did not expect ethernet component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentIPv4) {
		t.Fatalf("expected ipv4 component")
	}
	if encoded.Nucleus.TailOffset != uint16(len(ipHeader)) {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, len(ipHeader))
	}

	reconstructed, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(reconstructed, frame) {
		t.Fatalf("reconstructed frame mismatch")
	}
}

func TestCodecIPv4UDP(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 32)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 10),
		DstIP:    net.IPv4(198, 51, 100, 20),
	}
	udp := &layers.UDP{
		SrcPort: 1234,
		DstPort: 5678,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum: %v", err)
	}
	frame := serializeLayers(t, eth, ip4, udp, gopacket.Payload(payload))

	packet := Packet{
		SessionID: 1,
		PacketID:  10,
		Timestamp: time.Unix(1700000100, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := encodePacket(testLinkTypeEthernet, packet)
	if !hasComponentKind(encoded.Components, components.ComponentEthernet) {
		t.Fatalf("expected ethernet component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentIPv4) {
		t.Fatalf("expected ipv4 component")
	}
	if hasComponentKind(encoded.Components, components.ComponentIPv6) || hasComponentKind(encoded.Components, components.ComponentIPv6Ext) {
		t.Fatalf("did not expect ipv6 components")
	}
	if !hasComponentKind(encoded.Components, components.ComponentUDP) {
		t.Fatalf("expected udp component")
	}

	if encoded.Nucleus.TailOffset != 14+20+8 {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, 14+20+8)
	}
	if !bytes.Equal(encoded.Nucleus.Payload, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
	out, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("frame roundtrip mismatch")
	}
}

func TestCodecIPv6UDP(t *testing.T) {
	payload := bytes.Repeat([]byte{0x55}, 24)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		DstMAC:       net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	udp := &layers.UDP{
		SrcPort: 10000,
		DstPort: 53,
	}
	if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatalf("set udp checksum: %v", err)
	}
	frame := serializeLayers(t, eth, ip6, udp, gopacket.Payload(payload))

	packet := Packet{
		SessionID: 1,
		PacketID:  11,
		Timestamp: time.Unix(1700000101, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := encodePacket(testLinkTypeEthernet, packet)
	if !hasComponentKind(encoded.Components, components.ComponentEthernet) {
		t.Fatalf("expected ethernet component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentIPv6) {
		t.Fatalf("expected ipv6 component")
	}
	if hasComponentKind(encoded.Components, components.ComponentIPv4) {
		t.Fatalf("did not expect ipv4 component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentUDP) {
		t.Fatalf("expected udp component")
	}

	if encoded.Nucleus.TailOffset != 14+40+8 {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, 14+40+8)
	}
	if !bytes.Equal(encoded.Nucleus.Payload, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
	out, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("frame roundtrip mismatch")
	}
}

func TestCodecIPv4OptionsUDP(t *testing.T) {
	payload := bytes.Repeat([]byte{0x7e}, 20)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(203, 0, 113, 1),
		DstIP:    net.IPv4(203, 0, 113, 2),
		Options: []layers.IPv4Option{
			{OptionType: 1, OptionLength: 1},
			{OptionType: 1, OptionLength: 1},
			{OptionType: 1, OptionLength: 1},
			{OptionType: 1, OptionLength: 1},
		},
	}
	udp := &layers.UDP{
		SrcPort: 3333,
		DstPort: 4444,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum: %v", err)
	}
	frame := serializeLayers(t, eth, ip4, udp, gopacket.Payload(payload))

	packet := Packet{
		SessionID: 1,
		PacketID:  12,
		Timestamp: time.Unix(1700000102, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := encodePacket(testLinkTypeEthernet, packet)
	ipComp := findComponent(encoded.Components, &components.IPv4Component{})
	if ipComp == nil {
		t.Fatalf("ipv4 component missing")
	}
	if len(ipComp.OptionsRaw) == 0 {
		t.Fatalf("expected options_raw to be populated")
	}
	if !hasComponentKind(encoded.Components, components.ComponentUDP) {
		t.Fatalf("expected udp component")
	}
	if encoded.Nucleus.TailOffset != 14+24+8 {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, 14+24+8)
	}
	if !bytes.Equal(encoded.Nucleus.Payload, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
	out, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("frame roundtrip mismatch")
	}
}

func TestCodecUnsupportedLinkType(t *testing.T) {
	frame := []byte{0x01, 0x02, 0x03}
	packet := Packet{
		SessionID: 1,
		PacketID:  6,
		Timestamp: time.Unix(1700000005, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := encodePacket(9999, packet)
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("expected raw frame fallback")
	}
	if !bytes.Equal(encoded.Nucleus.Payload, frame) {
		t.Fatalf("raw frame mismatch")
	}
}

func TestCodecTailOffsetMismatch(t *testing.T) {
	nucleus := components.PacketNucleus{
		Components: components.NewComponentMask(components.ComponentEthernet),
		TailOffset: 10, // Ethernet is 14 bytes, so 10 != 14 → mismatch
	}
	l2 := &components.EthernetComponent{
		SrcMAC:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:    []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EtherType: testEtherTypeIPv4,
	}
	_, err := reconstructFrame(nucleus, []components.Component{l2})
	if err == nil {
		t.Fatalf("expected tail_offset mismatch error")
	}
}

func TestCodecTruncatedBit(t *testing.T) {
	ipHeader := buildIPv4Header(nil, 0)
	frame := buildEthernetFrame(testEtherTypeIPv4, ipHeader)
	packet := Packet{
		SessionID: 1,
		PacketID:  7,
		Timestamp: time.Unix(1700000006, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame) + 10),
		Frame:     frame,
	}

	encoded := encodePacket(testLinkTypeEthernet, packet)
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentTruncated) {
		t.Fatalf("expected truncated bit")
	}
}

func TestCodecPCAPRoundTrip(t *testing.T) {
	packets := []struct {
		frame []byte
		ts    time.Time
	}{
		{frame: buildEthernetFrame(testEtherTypeIPv4, buildIPv4Header(nil, 0)), ts: time.Unix(1700000010, 1000)},
		{frame: buildEthernetFrame(0x0806, []byte{0x01, 0x02, 0x03}), ts: time.Unix(1700000011, 2000)},
	}

	var input bytes.Buffer
	writer := pcapgo.NewWriter(&input)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write header: %v", err)
	}
	for _, pkt := range packets {
		ci := gopacket.CaptureInfo{
			Timestamp:     pkt.ts,
			CaptureLength: len(pkt.frame),
			Length:        len(pkt.frame),
		}
		if err := writer.WritePacket(ci, pkt.frame); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}

	inputBytes := input.Bytes()
	if len(inputBytes) < 24 {
		t.Fatalf("pcap too short")
	}
	meta, err := ParseGlobalHeader(inputBytes[:24])
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	var output bytes.Buffer
	if err := writePCAPHeader(&output, meta); err != nil {
		t.Fatalf("write output header: %v", err)
	}

	reader, err := pcapgo.NewReader(bytes.NewReader(inputBytes))
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	order := byteOrder(meta.Endianness)
	packetID := uint32(0)
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read input packet: %v", err)
		}

		encoded := encodePacket(uint32(meta.LinkType), Packet{
			SessionID: 1,
			PacketID:  packetID,
			Timestamp: ci.Timestamp,
			InclLen:   uint32(ci.CaptureLength),
			OrigLen:   uint32(ci.Length),
			Frame:     data,
		})
		packetID++

		reconstructed, err := reconstructFrame(encoded.Nucleus, encoded.Components)
		if err != nil {
			t.Fatalf("reconstruct: %v", err)
		}
		if err := writePacketRecord(&output, order, meta.TimeResolution, ci.Timestamp, uint32(ci.CaptureLength), uint32(ci.Length), reconstructed); err != nil {
			t.Fatalf("write output packet: %v", err)
		}
	}

	outReader, err := pcapgo.NewReader(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	for i, expect := range packets {
		data, ci, err := outReader.ReadPacketData()
		if err != nil {
			t.Fatalf("read output packet %d: %v", i, err)
		}
		if !bytes.Equal(data, expect.frame) {
			t.Fatalf("packet %d data mismatch", i)
		}
		if ci.Timestamp.Unix() != expect.ts.Unix() || ci.Timestamp.Nanosecond()/1000 != expect.ts.Nanosecond()/1000 {
			t.Fatalf("packet %d timestamp mismatch", i)
		}
	}
}

func buildEthernetFrame(etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(frame[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}

func buildIPv4Header(options []byte, payloadLen int) []byte {
	if len(options)%4 != 0 {
		panic("options length must be multiple of 4")
	}
	ihl := 5 + len(options)/4
	headerLen := ihl * 4
	totalLen := headerLen + payloadLen
	header := make([]byte, headerLen)
	header[0] = byte(4<<4 | ihl)
	header[1] = 0x10
	binary.BigEndian.PutUint16(header[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(header[4:6], 0x1234)
	binary.BigEndian.PutUint16(header[6:8], 0x4000)
	header[8] = 64
	header[9] = 17
	binary.BigEndian.PutUint16(header[10:12], 0)
	copy(header[12:16], []byte{192, 0, 2, 1})
	copy(header[16:20], []byte{198, 51, 100, 2})
	copy(header[20:], options)
	return header
}

func TestDNSEncodeDecode(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 10),
		DstIP:    net.IPv4(8, 8, 8, 8),
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum: %v", err)
	}
	dns := &layers.DNS{
		ID:     0x1234,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		RD:     true,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
			{Name: []byte("www.example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		},
	}

	frame := serializeLayers(t, eth, ip4, udp, dns)

	packet := Packet{
		SessionID: 1,
		PacketID:  100,
		Timestamp: time.Unix(1700000200, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := encodePacket(testLinkTypeEthernet, packet)

	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentDNS) {
		t.Fatalf("expected DNS component bit set")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("did not expect raw frame fallback")
	}

	dnsComp := findComponent(encoded.Components, &components.DNSComponent{})
	if dnsComp == nil {
		t.Fatalf("DNS component missing from list")
	}

	if dnsComp.TransactionID != 0x1234 {
		t.Fatalf("transaction_id mismatch: got 0x%x want 0x1234", dnsComp.TransactionID)
	}
	if dnsComp.QR != 0 {
		t.Fatalf("qr mismatch: got %d want 0 (query)", dnsComp.QR)
	}
	if dnsComp.Flags&0x02 == 0 {
		t.Fatalf("RD flag not set in flags byte")
	}
	if len(dnsComp.QuestionsName) != 2 {
		t.Fatalf("questions_name length mismatch: got %d want 2", len(dnsComp.QuestionsName))
	}
	if dnsComp.QuestionsName[0] != "example.com" {
		t.Fatalf("questions_name[0] mismatch: got %q want %q", dnsComp.QuestionsName[0], "example.com")
	}
	if dnsComp.QuestionsName[1] != "www.example.com" {
		t.Fatalf("questions_name[1] mismatch: got %q want %q", dnsComp.QuestionsName[1], "www.example.com")
	}
	if dnsComp.QuestionsType[0] != uint16(layers.DNSTypeA) {
		t.Fatalf("questions_type[0] mismatch")
	}
	if dnsComp.QuestionsType[1] != uint16(layers.DNSTypeAAAA) {
		t.Fatalf("questions_type[1] mismatch")
	}

	if len(encoded.Nucleus.Payload) > 0 {
		t.Fatalf("expected empty Payload for DNS packet, got %d bytes", len(encoded.Nucleus.Payload))
	}

	reconstructed, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(reconstructed, frame) {
		t.Fatalf("reconstructed frame mismatch (len got %d want %d)", len(reconstructed), len(frame))
	}
}

func TestNTPEncodeDecode(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 20),
		DstIP:    net.IPv4(216, 239, 35, 0),
	}
	udp := &layers.UDP{
		SrcPort: 54321,
		DstPort: 123,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum: %v", err)
	}
	ntp := &layers.NTP{
		LeapIndicator:      0, // no warning
		Version:            4,
		Mode:               3, // client
		Stratum:            0,
		Poll:               3,
		Precision:          -6,
		RootDelay:          0x00010000,
		RootDispersion:     0x00020000,
		ReferenceID:        0x4c4f434c,
		ReferenceTimestamp: 0xE63B_7B00_00000000,
		TransmitTimestamp:  0xE63B_7C00_12345678,
	}

	frame := serializeLayers(t, eth, ip4, udp, ntp)

	packet := Packet{
		SessionID: 1,
		PacketID:  200,
		Timestamp: time.Unix(1700000300, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := encodePacket(testLinkTypeEthernet, packet)

	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentNTP) {
		t.Fatalf("expected NTP component bit set")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("did not expect raw frame fallback")
	}

	ntpComp := findComponent(encoded.Components, &components.NTPComponent{})
	if ntpComp == nil {
		t.Fatalf("NTP component missing from list")
	}
	if ntpComp.Version != 4 {
		t.Fatalf("version mismatch: got %d want 4", ntpComp.Version)
	}
	if ntpComp.Mode != 3 { // 3 = client
		t.Fatalf("mode mismatch: got %d want 3 (client)", ntpComp.Mode)
	}
	if ntpComp.TransmitTS != 0xE63B_7C00_12345678 {
		t.Fatalf("transmit_ts mismatch: got 0x%x", ntpComp.TransmitTS)
	}

	if len(encoded.Nucleus.Payload) > 0 {
		t.Fatalf("expected empty Payload for NTP packet, got %d bytes", len(encoded.Nucleus.Payload))
	}

	reconstructed, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(reconstructed, frame) {
		t.Fatalf("reconstructed frame mismatch (len got %d want %d)", len(reconstructed), len(frame))
	}
}

func TestDNSTruncatedPayload(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 1),
		DstIP:    net.IPv4(192, 0, 2, 2),
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum: %v", err)
	}
	// 3-byte DNS payload — too short to parse (DNS requires >= 12 bytes)
	badDNS := []byte{0xde, 0xad, 0xbe}
	frame := serializeLayers(t, eth, ip4, udp, gopacket.Payload(badDNS))

	packet := Packet{
		SessionID: 1,
		PacketID:  300,
		Timestamp: time.Unix(1700000400, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := encodePacket(testLinkTypeEthernet, packet)

	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentDNS) {
		t.Fatalf("expected no DNS component for truncated payload")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("did not expect raw frame fallback")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentEthernet) {
		t.Fatalf("expected Ethernet component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentIPv4) {
		t.Fatalf("expected IPv4 component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentUDP) {
		t.Fatalf("expected UDP component")
	}

	if len(encoded.Nucleus.Payload) < len(badDNS) || !bytes.Equal(encoded.Nucleus.Payload[:len(badDNS)], badDNS) {
		t.Fatalf("Payload prefix mismatch: got %x", encoded.Nucleus.Payload)
	}

	reconstructed, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(reconstructed, frame) {
		t.Fatalf("reconstructed frame mismatch (len got %d want %d)", len(reconstructed), len(frame))
	}
}

func TestDNSMalformedQuestions(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 1),
		DstIP:    net.IPv4(192, 0, 2, 2),
	}
	udp := &layers.UDP{
		SrcPort: 12346,
		DstPort: 53,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum: %v", err)
	}
	// Valid 12-byte DNS header claiming qdcount=1, but no question data follows.
	// gopacket will fail to parse the question section ("dns name offset too high").
	badDNS := []byte{
		0xab, 0xcd, // transaction ID
		0x01, 0x00, // flags: QR=0 (query), RD=1
		0x00, 0x01, // qdcount = 1
		0x00, 0x00, // ancount = 0
		0x00, 0x00, // nscount = 0
		0x00, 0x00, // arcount = 0
		// no question data
	}
	frame := serializeLayers(t, eth, ip4, udp, gopacket.Payload(badDNS))

	packet := Packet{
		SessionID: 1,
		PacketID:  301,
		Timestamp: time.Unix(1700000401, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := encodePacket(testLinkTypeEthernet, packet)

	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentDNS) {
		t.Fatalf("expected no DNS component for malformed questions")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("did not expect raw frame fallback")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentEthernet) {
		t.Fatalf("expected Ethernet component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentIPv4) {
		t.Fatalf("expected IPv4 component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentUDP) {
		t.Fatalf("expected UDP component")
	}

	if len(encoded.Nucleus.Payload) < len(badDNS) || !bytes.Equal(encoded.Nucleus.Payload[:len(badDNS)], badDNS) {
		t.Fatalf("Payload prefix mismatch: got %x", encoded.Nucleus.Payload)
	}

	reconstructed, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(reconstructed, frame) {
		t.Fatalf("reconstructed frame mismatch (len got %d want %d)", len(reconstructed), len(frame))
	}
}

func TestNTPTruncatedPayload(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 10),
		DstIP:    net.IPv4(216, 239, 35, 0),
	}
	udp := &layers.UDP{
		SrcPort: 54322,
		DstPort: 123,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum: %v", err)
	}
	// 10-byte NTP payload — too short to parse (NTP requires >= 48 bytes)
	badNTP := make([]byte, 10)
	badNTP[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
	frame := serializeLayers(t, eth, ip4, udp, gopacket.Payload(badNTP))

	packet := Packet{
		SessionID: 1,
		PacketID:  302,
		Timestamp: time.Unix(1700000402, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := encodePacket(testLinkTypeEthernet, packet)

	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentNTP) {
		t.Fatalf("expected no NTP component for truncated payload")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("did not expect raw frame fallback")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentEthernet) {
		t.Fatalf("expected Ethernet component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentIPv4) {
		t.Fatalf("expected IPv4 component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentUDP) {
		t.Fatalf("expected UDP component")
	}

	if len(encoded.Nucleus.Payload) < len(badNTP) || !bytes.Equal(encoded.Nucleus.Payload[:len(badNTP)], badNTP) {
		t.Fatalf("Payload prefix mismatch: got %x", encoded.Nucleus.Payload)
	}

	reconstructed, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(reconstructed, frame) {
		t.Fatalf("reconstructed frame mismatch (len got %d want %d)", len(reconstructed), len(frame))
	}
}

func buildIPv6Header(payloadLen int, nextHeader uint8, hopLimit uint8, trafficClass uint8) []byte {
	header := make([]byte, 40)
	header[0] = 0x60 | ((trafficClass >> 4) & 0x0F)
	header[1] = (trafficClass & 0x0F) << 4
	binary.BigEndian.PutUint16(header[4:6], uint16(payloadLen))
	header[6] = nextHeader
	header[7] = hopLimit
	copy(header[8:24], []byte{
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1,
	})
	copy(header[24:40], []byte{
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 2,
	})
	return header
}

func findComponent[K components.Component](comps []components.Component, ref K) K {
	for _, comp := range comps {
		if comp.Kind() == ref.Kind() {
			return comp.(K) // type gymnastics
		}
	}
	return ref
}

func findMultipleComponents[K components.Component](comps []components.Component, ref K) []K {
	out := []K{}
	for _, comp := range comps {
		if comp.Kind() == ref.Kind() {
			out = append(out, comp.(K))
		}
	}
	return out
}

func sumLayerSize(comps []components.Component) int {
	total := 0
	for _, comp := range comps {
		total += comp.LayerSize()
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
		SessionID: 1,
		PacketID:  20,
		Timestamp: time.Unix(1700000400, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := encodePacket(testLinkTypeEthernet, packet)
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentDot1Q) {
		t.Fatalf("expected dot1q component bit")
	}
	tags := findMultipleComponents(encoded.Components, &components.Dot1QComponent{})
	if len(tags) != 2 {
		t.Fatalf("expected 2 dot1q components, got %d", len(tags))
	}
	seen := map[uint16]bool{
		tags[0].LayerIndex: true,
		tags[1].LayerIndex: true,
	}
	// eth should have position 0, then tags should be position
	// 1 and 2
	if !seen[1] || !seen[2] {
		t.Fatalf("dot1q tag indexes not set")
	}

	if !hasComponentKind(encoded.Components, components.ComponentUDP) {
		t.Fatalf("expected udp component")
	}
	expectedOffset := sumLayerSize(encoded.Components)
	if encoded.Nucleus.TailOffset != uint16(expectedOffset) {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, expectedOffset)
	}
	if !bytes.Equal(encoded.Nucleus.Payload, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
}

func TestCodecIPv4TCP(t *testing.T) {
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
		SessionID: 1,
		PacketID:  21,
		Timestamp: time.Unix(1700000401, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := encodePacket(testLinkTypeEthernet, packet)
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("unexpected raw frame fallback")
	}
	if !hasComponentKind(encoded.Components, components.ComponentIPv4) {
		t.Fatalf("expected ipv4 component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentTCP) {
		t.Fatalf("expected tcp component")
	}
	if !bytes.Equal(encoded.Nucleus.Payload, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
	out, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("frame roundtrip mismatch")
	}
}

func TestCodecIPv6ICMPv6Component(t *testing.T) {
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
		SessionID: 1,
		PacketID:  22,
		Timestamp: time.Unix(1700000402, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := encodePacket(testLinkTypeEthernet, packet)
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("unexpected raw frame fallback")
	}
	if !hasComponentKind(encoded.Components, components.ComponentIPv6) {
		t.Fatalf("expected ipv6 component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentICMPv6) {
		t.Fatalf("expected icmpv6 component")
	}
	// ICMPv6 fixed header (4 bytes) is now a component; only the echo body + payload remain as tail.
	if !bytes.Equal(encoded.Nucleus.Payload, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
}

// TestTruncatedUDPHeaderStillParsesL3 checks that a frame whose UDP header is
// shorter than the required 8 bytes still produces Ethernet + IPv4 components,
// with the truncated UDP bytes stored in Payload (no raw-frame fallback).
func TestTruncatedUDPHeaderStillParsesL3(t *testing.T) {
	partialUDP := []byte{0x04, 0xd2, 0x16, 0x2e} // 4 bytes: src/dst port only
	ipHeader := buildIPv4Header(nil, len(partialUDP))
	// buildIPv4Header sets proto=17 (UDP) — no change needed
	frame := buildEthernetFrame(testEtherTypeIPv4, append(ipHeader, partialUDP...))

	packet := Packet{
		SessionID: 1,
		PacketID:  30,
		Timestamp: time.Unix(1700000500, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := encodePacket(testLinkTypeEthernet, packet)

	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("unexpected raw-frame fallback for truncated UDP")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentEthernet) {
		t.Fatalf("expected Ethernet component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentIPv4) {
		t.Fatalf("expected IPv4 component")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentUDP) {
		t.Fatalf("did not expect UDP component for truncated header")
	}

	wantOffset := uint16(14 + 20) // Ethernet + IPv4 only
	if encoded.Nucleus.TailOffset != wantOffset {
		t.Fatalf("tail_offset: got %d want %d", encoded.Nucleus.TailOffset, wantOffset)
	}
	if !bytes.HasPrefix(encoded.Nucleus.Payload, partialUDP) {
		t.Fatalf("Payload does not start with partial UDP bytes: %x", encoded.Nucleus.Payload)
	}

	out, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("frame roundtrip mismatch")
	}
}

// TestTruncatedTCPHeaderStillParsesL3 checks that a frame whose TCP header is
// shorter than the required 20 bytes still produces Ethernet + IPv4 components,
// with the truncated TCP bytes stored in Payload (no raw-frame fallback).
func TestTruncatedTCPHeaderStillParsesL3(t *testing.T) {
	partialTCP := make([]byte, 10) // 10 bytes: not enough for a 20-byte TCP header
	partialTCP[0] = 0x00
	partialTCP[1] = 0x50 // src port = 80
	partialTCP[2] = 0x30
	partialTCP[3] = 0x39 // dst port = 12345

	ipHeader := buildIPv4Header(nil, len(partialTCP))
	ipHeader[9] = 6 // override proto to TCP
	frame := buildEthernetFrame(testEtherTypeIPv4, append(ipHeader, partialTCP...))

	packet := Packet{
		SessionID: 1,
		PacketID:  31,
		Timestamp: time.Unix(1700000501, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := encodePacket(testLinkTypeEthernet, packet)

	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("unexpected raw-frame fallback for truncated TCP")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentEthernet) {
		t.Fatalf("expected Ethernet component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentIPv4) {
		t.Fatalf("expected IPv4 component")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentTCP) {
		t.Fatalf("did not expect TCP component for truncated header")
	}

	wantOffset := uint16(14 + 20) // Ethernet + IPv4 only
	if encoded.Nucleus.TailOffset != wantOffset {
		t.Fatalf("tail_offset: got %d want %d", encoded.Nucleus.TailOffset, wantOffset)
	}
	if !bytes.HasPrefix(encoded.Nucleus.Payload, partialTCP) {
		t.Fatalf("Payload does not start with partial TCP bytes: %x", encoded.Nucleus.Payload)
	}

	out, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("frame roundtrip mismatch")
	}
}

// TestTruncatedIPv4HeaderStillParsesL2 checks that a frame whose IPv4 header
// is shorter than the required 20 bytes still produces an Ethernet component,
// with the truncated IPv4 bytes stored in Payload (no raw-frame fallback).
func TestTruncatedIPv4HeaderStillParsesL2(t *testing.T) {
	partialIPv4 := make([]byte, 10) // 10 bytes: not enough for a 20-byte IPv4 header
	partialIPv4[0] = 0x45           // version=4, IHL=5 (claims 20 bytes but we only supply 10)
	partialIPv4[1] = 0x00
	copy(partialIPv4[2:4], []byte{0x00, 0x1e}) // total length = 30
	partialIPv4[9] = 6                         // protocol = TCP
	frame := buildEthernetFrame(testEtherTypeIPv4, partialIPv4)

	packet := Packet{
		SessionID: 1,
		PacketID:  32,
		Timestamp: time.Unix(1700000502, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := encodePacket(testLinkTypeEthernet, packet)

	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("unexpected raw-frame fallback for truncated IPv4")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentEthernet) {
		t.Fatalf("expected Ethernet component")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentIPv4) {
		t.Fatalf("did not expect IPv4 component for truncated header")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentTCP) {
		t.Fatalf("did not expect TCP component")
	}

	wantOffset := uint16(14) // Ethernet only
	if encoded.Nucleus.TailOffset != wantOffset {
		t.Fatalf("tail_offset: got %d want %d", encoded.Nucleus.TailOffset, wantOffset)
	}
	if !bytes.HasPrefix(encoded.Nucleus.Payload, partialIPv4) {
		t.Fatalf("Payload does not start with partial IPv4 bytes: %x", encoded.Nucleus.Payload)
	}

	out, err := reconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("frame roundtrip mismatch")
	}
}
