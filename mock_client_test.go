package caphouse

import (
	"bytes"
	"fmt"
	"sort"

	"caphouse/components"

	"github.com/google/uuid"
)

type mockClient struct {
	meta CaptureMeta

	packets  map[uint64]components.PacketNucleus
	ethernet map[uint64]*components.EthernetComponent
	dot1q    map[uint64][]*components.Dot1QComponent
	linuxSLL map[uint64]*components.LinuxSLLComponent
	ipv4     map[uint64]*components.IPv4Component
	ipv6     map[uint64]*components.IPv6Component
	ipv6Ext  map[uint64][]*components.IPv6ExtComponent
	tcp      map[uint64]*components.TCPComponent
	udp      map[uint64]*components.UDPComponent
	dns      map[uint64]*components.DNSComponent
	ntp      map[uint64]*components.NTPComponent
}

func newMockClient(meta CaptureMeta) *mockClient {
	if meta.CaptureID == uuid.Nil {
		meta.CaptureID = uuid.New()
	}
	if meta.Endianness == "" {
		meta.Endianness = "le"
	}
	if meta.TimeResolution == "" {
		meta.TimeResolution = "us"
	}
	if meta.Snaplen == 0 {
		meta.Snaplen = 65535
	}
	return &mockClient{
		meta:     meta,
		packets:  map[uint64]components.PacketNucleus{},
		ethernet: map[uint64]*components.EthernetComponent{},
		dot1q:    map[uint64][]*components.Dot1QComponent{},
		linuxSLL: map[uint64]*components.LinuxSLLComponent{},
		ipv4:     map[uint64]*components.IPv4Component{},
		ipv6:     map[uint64]*components.IPv6Component{},
		ipv6Ext:  map[uint64][]*components.IPv6ExtComponent{},
		tcp:      map[uint64]*components.TCPComponent{},
		udp:      map[uint64]*components.UDPComponent{},
		dns:      map[uint64]*components.DNSComponent{},
		ntp:      map[uint64]*components.NTPComponent{},
	}
}

func (m *mockClient) IngestPacket(linkType uint32, p Packet) error {
	normalizePacket(&p)
	encoded := EncodePacket(linkType, p)
	m.packets[p.PacketID] = encoded.Nucleus
	for _, component := range encoded.Components {
		switch component := component.(type) {
		case *components.EthernetComponent:
			m.ethernet[p.PacketID] = component
		case *components.Dot1QComponent:
			m.dot1q[p.PacketID] = append(m.dot1q[p.PacketID], component)
		case *components.LinuxSLLComponent:
			m.linuxSLL[p.PacketID] = component
		case *components.IPv4Component:
			m.ipv4[p.PacketID] = component
		case *components.IPv6Component:
			m.ipv6[p.PacketID] = component
		case *components.IPv6ExtComponent:
			m.ipv6Ext[p.PacketID] = append(m.ipv6Ext[p.PacketID], component)
		case *components.TCPComponent:
			m.tcp[p.PacketID] = component
		case *components.UDPComponent:
			m.udp[p.PacketID] = component
		case *components.DNSComponent:
			m.dns[p.PacketID] = component
		case *components.NTPComponent:
			m.ntp[p.PacketID] = component
		}
	}
	return nil
}

func (m *mockClient) ExportCaptureBytes() ([]byte, error) {
	metaRow := captureMetaRow{
		Endianness:      m.meta.Endianness,
		Snaplen:         m.meta.Snaplen,
		LinkType:        m.meta.LinkType,
		TimeResolution:  m.meta.TimeResolution,
		GlobalHeaderRaw: m.meta.GlobalHeaderRaw,
	}
	var out bytes.Buffer
	if err := writePCAPHeader(&out, metaRow); err != nil {
		return nil, err
	}
	order := byteOrder(metaRow.Endianness)

	packetIDs := make([]uint64, 0, len(m.packets))
	for id := range m.packets {
		packetIDs = append(packetIDs, id)
	}
	sort.Slice(packetIDs, func(i, j int) bool { return packetIDs[i] < packetIDs[j] })

	for _, id := range packetIDs {
		nucleus := m.packets[id]
		componentsList := []components.Component{}
		if comp := m.ethernet[id]; comp != nil {
			componentsList = append(componentsList, comp)
		}
		for _, tag := range m.dot1q[id] {
			componentsList = append(componentsList, tag)
		}
		if comp := m.linuxSLL[id]; comp != nil {
			componentsList = append(componentsList, comp)
		}
		if comp := m.ipv4[id]; comp != nil {
			componentsList = append(componentsList, comp)
		}
		if comp := m.ipv6[id]; comp != nil {
			componentsList = append(componentsList, comp)
		}
		for _, ext := range m.ipv6Ext[id] {
			componentsList = append(componentsList, ext)
		}
		if comp := m.tcp[id]; comp != nil {
			componentsList = append(componentsList, comp)
		}
		if comp := m.udp[id]; comp != nil {
			componentsList = append(componentsList, comp)
		}
		if comp := m.dns[id]; comp != nil {
			componentsList = append(componentsList, comp)
		}
		if comp := m.ntp[id]; comp != nil {
			componentsList = append(componentsList, comp)
		}

		frame, err := ReconstructFrame(nucleus, componentsList)
		if err != nil {
			return nil, fmt.Errorf("reconstruct packet %d: %w", id, err)
		}
		if err := writePacketRecord(&out, order, nucleus.Timestamp, nucleus.InclLen, nucleus.OrigLen, frame); err != nil {
			return nil, err
		}
	}

	return out.Bytes(), nil
}
