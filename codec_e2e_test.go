package caphouse

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
)

type pcapFrame struct {
	data []byte
	ts   time.Time
}

func readPCAPFrames(t *testing.T, data []byte) []pcapFrame {
	t.Helper()

	reader, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap read: %v", err)
	}

	var frames []pcapFrame
	for {
		payload, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("pcap read packet: %v", err)
		}
		copied := make([]byte, len(payload))
		copy(copied, payload)
		frames = append(frames, pcapFrame{data: copied, ts: ci.Timestamp})
	}
	return frames
}

func TestMockClientRoundTripEthernet(t *testing.T) {
	meta := CaptureMeta{
		CaptureID:      uuid.New(),
		LinkType:       testLinkTypeEthernet,
		Endianness:     "le",
		TimeResolution: "us",
		Snaplen:        65535,
	}
	client := newMockClient(meta)

	payload1 := bytes.Repeat([]byte{0x10}, 32)
	eth1 := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       net.HardwareAddr{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4a := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 10),
		DstIP:    net.IPv4(198, 51, 100, 20),
	}
	udp1 := &layers.UDP{SrcPort: 1111, DstPort: 2222}
	if err := udp1.SetNetworkLayerForChecksum(ip4a); err != nil {
		t.Fatalf("udp checksum: %v", err)
	}
	frame1 := serializeLayers(t, eth1, ip4a, udp1, gopacket.Payload(payload1))

	payload2 := bytes.Repeat([]byte{0x22}, 24)
	eth2 := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11},
		DstMAC:       net.HardwareAddr{0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
		EthernetType: layers.EthernetTypeDot1Q,
	}
	tag1 := &layers.Dot1Q{
		VLANIdentifier: 100,
		Type:           layers.EthernetTypeDot1Q,
	}
	tag2 := &layers.Dot1Q{
		VLANIdentifier: 200,
		Type:           layers.EthernetTypeIPv4,
	}
	ip4b := &layers.IPv4{
		Version:  4,
		TTL:      32,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(203, 0, 113, 1),
		DstIP:    net.IPv4(203, 0, 113, 2),
	}
	udp2 := &layers.UDP{SrcPort: 3333, DstPort: 4444}
	if err := udp2.SetNetworkLayerForChecksum(ip4b); err != nil {
		t.Fatalf("udp checksum: %v", err)
	}
	frame2 := serializeLayers(t, eth2, tag1, tag2, ip4b, udp2, gopacket.Payload(payload2))

	payload3 := bytes.Repeat([]byte{0x33}, 28)
	eth3 := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       net.HardwareAddr{0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	udp3 := &layers.UDP{SrcPort: 5555, DstPort: 6666}
	if err := udp3.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatalf("udp checksum: %v", err)
	}
	frame3 := serializeLayers(t, eth3, ip6, udp3, gopacket.Payload(payload3))

	frames := []pcapFrame{
		{data: frame1, ts: time.Unix(1700000200, 1000)},
		{data: frame2, ts: time.Unix(1700000201, 2000)},
		{data: frame3, ts: time.Unix(1700000202, 3000)},
	}

	for i, frame := range frames {
		err := client.IngestPacket(meta.LinkType, Packet{
			CaptureID: meta.CaptureID,
			PacketID:  uint64(i),
			Timestamp: frame.ts,
			InclLen:   uint32(len(frame.data)),
			OrigLen:   uint32(len(frame.data)),
			Frame:     frame.data,
		})
		if err != nil {
			t.Fatalf("ingest packet %d: %v", i, err)
		}
	}

	out, err := client.ExportCaptureBytes()
	if err != nil {
		t.Fatalf("export capture: %v", err)
	}
	got := readPCAPFrames(t, out)
	if len(got) != len(frames) {
		t.Fatalf("export frame count mismatch: got %d want %d", len(got), len(frames))
	}

	for i, frame := range frames {
		if !bytes.Equal(got[i].data, frame.data) {
			t.Fatalf("frame %d mismatch", i)
		}
		if got[i].ts.Unix() != frame.ts.Unix() || got[i].ts.Nanosecond()/1000 != frame.ts.Nanosecond()/1000 {
			t.Fatalf("frame %d timestamp mismatch", i)
		}
	}
}

func TestMockClientRoundTripRawIPv4(t *testing.T) {
	meta := CaptureMeta{
		CaptureID:      uuid.New(),
		LinkType:       testLinkTypeRaw,
		Endianness:     "le",
		TimeResolution: "us",
		Snaplen:        65535,
	}
	client := newMockClient(meta)

	payload := bytes.Repeat([]byte{0x44}, 40)
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}
	udp := &layers.UDP{SrcPort: 7777, DstPort: 8888}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("udp checksum: %v", err)
	}
	frame := serializeLayers(t, ip4, udp, gopacket.Payload(payload))

	err := client.IngestPacket(meta.LinkType, Packet{
		CaptureID: meta.CaptureID,
		PacketID:  0,
		Timestamp: time.Unix(1700000300, 4000),
		InclLen:   uint32(len(frame)),
		OrigLen:   uint32(len(frame)),
		Frame:     frame,
	})
	if err != nil {
		t.Fatalf("ingest packet: %v", err)
	}

	out, err := client.ExportCaptureBytes()
	if err != nil {
		t.Fatalf("export capture: %v", err)
	}
	got := readPCAPFrames(t, out)
	if len(got) != 1 {
		t.Fatalf("export frame count mismatch: got %d want 1", len(got))
	}
	if !bytes.Equal(got[0].data, frame) {
		t.Fatalf("frame mismatch")
	}
	if got[0].ts.Unix() != 1700000300 || got[0].ts.Nanosecond()/1000 != 4 {
		t.Fatalf("timestamp mismatch")
	}
}
