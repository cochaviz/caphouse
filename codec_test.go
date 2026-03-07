package caphouse

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"caphouse/components"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
)

const (
	testLinkTypeEthernet = 1
	testLinkTypeRaw      = 101
	testEtherTypeIPv4    = 0x0800
	testEtherTypeIPv6    = 0x86DD
)

func findEthernetComponent(comps []components.ClickhouseMappedDecoder) *components.EthernetComponent {
	for _, comp := range comps {
		if eth, ok := comp.(*components.EthernetComponent); ok {
			return eth
		}
	}
	return nil
}

func findIPv4Component(comps []components.ClickhouseMappedDecoder) *components.IPv4Component {
	for _, comp := range comps {
		if ip, ok := comp.(*components.IPv4Component); ok {
			return ip
		}
	}
	return nil
}

func findIPv4OptionsComponent(comps []components.ClickhouseMappedDecoder) *components.IPv4OptionsComponent {
	for _, comp := range comps {
		if opts, ok := comp.(*components.IPv4OptionsComponent); ok {
			return opts
		}
	}
	return nil
}

func findIPv6Component(comps []components.ClickhouseMappedDecoder) *components.IPv6Component {
	for _, comp := range comps {
		if ip, ok := comp.(*components.IPv6Component); ok {
			return ip
		}
	}
	return nil
}

func findIPv6ExtComponent(comps []components.ClickhouseMappedDecoder) *components.IPv6ExtComponent {
	for _, comp := range comps {
		if ext, ok := comp.(*components.IPv6ExtComponent); ok {
			return ext
		}
	}
	return nil
}

func findRawTailComponent(comps []components.ClickhouseMappedDecoder) *components.RawTailComponent {
	for _, comp := range comps {
		if tail, ok := comp.(*components.RawTailComponent); ok {
			return tail
		}
	}
	return nil
}

func hasComponentKind(comps []components.ClickhouseMappedDecoder, kind uint) bool {
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
		CaptureID: uuid.New(),
		PacketID:  1,
		Timestamp: time.Unix(1700000000, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeEthernet, packet)
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentEthernet) {
		t.Fatalf("expected ethernet component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentIPv4) {
		t.Fatalf("expected ipv4 component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawTail) {
		t.Fatalf("expected raw tail component")
	}

	wantTailOffset := uint16(14 + 20)
	if encoded.Nucleus.TailOffset != wantTailOffset {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, wantTailOffset)
	}
	ipComponent := findIPv4Component(encoded.Components)
	if ipComponent == nil {
		t.Fatalf("ipv4 component not populated")
	}
	if ipComponent.Protocol != 17 {
		t.Fatalf("protocol mismatch: got %d want 17", ipComponent.Protocol)
	}
	rawTail := findRawTailComponent(encoded.Components)
	if rawTail == nil || !bytes.Equal(rawTail.Bytes, payload) {
		t.Fatalf("raw tail mismatch")
	}

	reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(reconstructed, frame) {
		t.Fatalf("reconstructed frame mismatch")
	}
}

func TestCodecIPv4Options(t *testing.T) {
	options := []byte{0x01, 0x02, 0x03, 0x04}
	payload := []byte{0xaa, 0xbb, 0xcc}
	ipHeader := buildIPv4Header(options, len(payload))
	frame := buildEthernetFrame(testEtherTypeIPv4, append(ipHeader, payload...))

	packet := Packet{
		CaptureID: uuid.New(),
		PacketID:  2,
		Timestamp: time.Unix(1700000001, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeEthernet, packet)
	ipComponent := findIPv4Component(encoded.Components)
	if ipComponent == nil {
		t.Fatalf("ipv4 component missing")
	}
	if ipComponent.IPv4IHL != uint8(len(ipHeader)/4) {
		t.Fatalf("ihl mismatch: got %d want %d", ipComponent.IPv4IHL, len(ipHeader)/4)
	}
	optionsComponent := findIPv4OptionsComponent(encoded.Components)
	if optionsComponent == nil || !bytes.Equal(optionsComponent.OptionsRaw, options) {
		t.Fatalf("ipv4 options mismatch")
	}

	reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  3,
		Timestamp: time.Unix(1700000002, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeEthernet, packet)
	ipComponent := findIPv6Component(encoded.Components)
	if ipComponent == nil {
		t.Fatalf("ipv6 component missing")
	}
	if ipComponent.Protocol != 0 {
		t.Fatalf("ipv6 next header mismatch: got %d want 0", ipComponent.Protocol)
	}
	if ipComponent.IPv6TrafficClass != 0xAB {
		t.Fatalf("ipv6 traffic class mismatch: got %d want %d", ipComponent.IPv6TrafficClass, 0xAB)
	}
	extComponent := findIPv6ExtComponent(encoded.Components)
	if extComponent == nil || !bytes.Equal(extComponent.ExtRaw, ext) {
		t.Fatalf("ipv6 ext header mismatch")
	}

	reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  4,
		Timestamp: time.Unix(1700000003, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeEthernet, packet)
	if findIPv4Component(encoded.Components) != nil || findIPv6Component(encoded.Components) != nil {
		t.Fatalf("expected no ip component")
	}
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawTail) {
		t.Fatalf("expected raw tail component")
	}
	if encoded.Nucleus.TailOffset != 14 {
		t.Fatalf("tail_offset mismatch: got %d want 14", encoded.Nucleus.TailOffset)
	}

	reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  5,
		Timestamp: time.Unix(1700000004, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeRaw, packet)
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentEthernet) {
		t.Fatalf("did not expect ethernet component")
	}
	if findIPv4Component(encoded.Components) == nil {
		t.Fatalf("expected ipv4 component")
	}
	if encoded.Nucleus.TailOffset != uint16(len(ipHeader)) {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, len(ipHeader))
	}

	reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  10,
		Timestamp: time.Unix(1700000100, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeEthernet, packet)
	if !hasComponentKind(encoded.Components, components.ComponentEthernet) {
		t.Fatalf("expected ethernet component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentIPv4) {
		t.Fatalf("expected ipv4 component")
	}
	if hasComponentKind(encoded.Components, components.ComponentIPv6) || hasComponentKind(encoded.Components, components.ComponentIPv6Ext) {
		t.Fatalf("did not expect ipv6 components")
	}
	if hasComponentKind(encoded.Components, components.ComponentIPv4Options) {
		t.Fatalf("did not expect ipv4 options component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentUDP) {
		t.Fatalf("expected udp component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentRawTail) {
		t.Fatalf("expected raw tail component")
	}

	if encoded.Nucleus.TailOffset != 14+20+8 {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, 14+20+8)
	}
	rawTail := findRawTailComponent(encoded.Components)
	if rawTail == nil {
		t.Fatalf("raw tail missing")
	}
	if !bytes.Equal(rawTail.Bytes, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
	out, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  11,
		Timestamp: time.Unix(1700000101, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeEthernet, packet)
	if !hasComponentKind(encoded.Components, components.ComponentEthernet) {
		t.Fatalf("expected ethernet component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentIPv6) {
		t.Fatalf("expected ipv6 component")
	}
	if hasComponentKind(encoded.Components, components.ComponentIPv4) || hasComponentKind(encoded.Components, components.ComponentIPv4Options) {
		t.Fatalf("did not expect ipv4 components")
	}
	if !hasComponentKind(encoded.Components, components.ComponentUDP) {
		t.Fatalf("expected udp component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentRawTail) {
		t.Fatalf("expected raw tail component")
	}

	if encoded.Nucleus.TailOffset != 14+40+8 {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, 14+40+8)
	}
	rawTail := findRawTailComponent(encoded.Components)
	if rawTail == nil {
		t.Fatalf("raw tail missing")
	}
	if !bytes.Equal(rawTail.Bytes, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
	out, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  12,
		Timestamp: time.Unix(1700000102, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeEthernet, packet)
	if !hasComponentKind(encoded.Components, components.ComponentIPv4Options) {
		t.Fatalf("expected ipv4 options component")
	}
	if !hasComponentKind(encoded.Components, components.ComponentUDP) {
		t.Fatalf("expected udp component")
	}
	if encoded.Nucleus.TailOffset != 14+24+8 {
		t.Fatalf("tail_offset mismatch: got %d want %d", encoded.Nucleus.TailOffset, 14+24+8)
	}
	rawTail := findRawTailComponent(encoded.Components)
	if rawTail == nil {
		t.Fatalf("raw tail missing")
	}
	if !bytes.Equal(rawTail.Bytes, frame[encoded.Nucleus.TailOffset:]) {
		t.Fatalf("raw tail mismatch")
	}
	out, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  6,
		Timestamp: time.Unix(1700000005, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(9999, packet)
	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("expected raw frame fallback")
	}
	if !bytes.Equal(encoded.Nucleus.FrameRaw, frame) {
		t.Fatalf("raw frame mismatch")
	}
}

func TestCodecTailOffsetMismatch(t *testing.T) {
	nucleus := components.PacketNucleus{
		Components: components.NewComponentMask(components.ComponentEthernet, components.ComponentRawTail),
		TailOffset: 10,
	}
	l2 := &components.EthernetComponent{
		SrcMAC:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:    []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EtherType: testEtherTypeIPv4,
	}
	tail := &components.RawTailComponent{Bytes: []byte{0x03}}
	_, err := ReconstructFrame(nucleus, []components.ClickhouseMappedDecoder{l2, tail})
	if err == nil {
		t.Fatalf("expected tail_offset mismatch error")
	}
}

func TestCodecTruncatedBit(t *testing.T) {
	ipHeader := buildIPv4Header(nil, 0)
	frame := buildEthernetFrame(testEtherTypeIPv4, ipHeader)
	packet := Packet{
		CaptureID: uuid.New(),
		PacketID:  7,
		Timestamp: time.Unix(1700000006, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame) + 10),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeEthernet, packet)
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
	metaRow := captureMetaRow{
		Endianness:     meta.Endianness,
		Snaplen:        meta.Snaplen,
		LinkType:       meta.LinkType,
		TimeResolution: meta.TimeResolution,
	}

	var output bytes.Buffer
	if err := writePCAPHeader(&output, metaRow); err != nil {
		t.Fatalf("write output header: %v", err)
	}

	reader, err := pcapgo.NewReader(bytes.NewReader(inputBytes))
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	order := byteOrder(metaRow.Endianness)
	packetID := uint64(0)
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read input packet: %v", err)
		}

		encoded := EncodePacket(uint32(metaRow.LinkType), Packet{
			CaptureID: uuid.New(),
			PacketID:  packetID,
			Timestamp: ci.Timestamp,
			InclLen:   uint32(ci.CaptureLength),
			OrigLen:   uint32(ci.Length),
			Frame:     data,
		})
		packetID++

		reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
		if err != nil {
			t.Fatalf("reconstruct: %v", err)
		}
		if err := writePacketRecord(&output, order, ci.Timestamp, uint32(ci.CaptureLength), uint32(ci.Length), reconstructed); err != nil {
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

func findDNSComponent(comps []components.ClickhouseMappedDecoder) *components.DNSComponent {
	for _, comp := range comps {
		if c, ok := comp.(*components.DNSComponent); ok {
			return c
		}
	}
	return nil
}

func findNTPComponent(comps []components.ClickhouseMappedDecoder) *components.NTPComponent {
	for _, comp := range comps {
		if c, ok := comp.(*components.NTPComponent); ok {
			return c
		}
	}
	return nil
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
		CaptureID: uuid.New(),
		PacketID:  100,
		Timestamp: time.Unix(1700000200, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeEthernet, packet)

	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentDNS) {
		t.Fatalf("expected DNS component bit set")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("did not expect raw frame fallback")
	}

	dnsComp := findDNSComponent(encoded.Components)
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

	rawTail := findRawTailComponent(encoded.Components)
	if rawTail != nil && len(rawTail.Bytes) > 0 {
		t.Fatalf("expected empty raw_tail for DNS packet, got %d bytes", len(rawTail.Bytes))
	}

	reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  200,
		Timestamp: time.Unix(1700000300, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}

	encoded := EncodePacket(testLinkTypeEthernet, packet)

	if !components.ComponentHas(encoded.Nucleus.Components, components.ComponentNTP) {
		t.Fatalf("expected NTP component bit set")
	}
	if components.ComponentHas(encoded.Nucleus.Components, components.ComponentRawFrame) {
		t.Fatalf("did not expect raw frame fallback")
	}

	ntpComp := findNTPComponent(encoded.Components)
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

	rawTail := findRawTailComponent(encoded.Components)
	if rawTail != nil && len(rawTail.Bytes) > 0 {
		t.Fatalf("expected empty raw_tail for NTP packet, got %d bytes", len(rawTail.Bytes))
	}

	reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  300,
		Timestamp: time.Unix(1700000400, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := EncodePacket(testLinkTypeEthernet, packet)

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

	rawTail := findRawTailComponent(encoded.Components)
	if rawTail == nil {
		t.Fatalf("expected raw_tail to contain malformed DNS bytes")
	}
	if len(rawTail.Bytes) < len(badDNS) || !bytes.Equal(rawTail.Bytes[:len(badDNS)], badDNS) {
		t.Fatalf("raw_tail prefix mismatch: got %x", rawTail.Bytes)
	}

	reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  301,
		Timestamp: time.Unix(1700000401, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := EncodePacket(testLinkTypeEthernet, packet)

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

	rawTail := findRawTailComponent(encoded.Components)
	if rawTail == nil {
		t.Fatalf("expected raw_tail to contain malformed DNS bytes")
	}
	if len(rawTail.Bytes) < len(badDNS) || !bytes.Equal(rawTail.Bytes[:len(badDNS)], badDNS) {
		t.Fatalf("raw_tail prefix mismatch: got %x", rawTail.Bytes)
	}

	reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
		CaptureID: uuid.New(),
		PacketID:  302,
		Timestamp: time.Unix(1700000402, 0),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	}
	encoded := EncodePacket(testLinkTypeEthernet, packet)

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

	rawTail := findRawTailComponent(encoded.Components)
	if rawTail == nil {
		t.Fatalf("expected raw_tail to contain truncated NTP bytes")
	}
	if len(rawTail.Bytes) < len(badNTP) || !bytes.Equal(rawTail.Bytes[:len(badNTP)], badNTP) {
		t.Fatalf("raw_tail prefix mismatch: got %x", rawTail.Bytes)
	}

	reconstructed, err := ReconstructFrame(encoded.Nucleus, encoded.Components)
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
