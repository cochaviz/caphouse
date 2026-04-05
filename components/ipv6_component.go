package components

import (
	_ "embed"
	"errors"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed ipv6_schema.sql
var ipv6SchemaSQL string

// IPv6Component stores parsed IPv6 fields.
type IPv6Component struct {
	SessionID uint64 `ch:"session_id"`
	PacketID  uint32 `ch:"packet_id"`

	CodecVersion uint16 `ch:"codec_version"`

	Protocol uint8 `ch:"protocol"`

	SrcIP6 netip.Addr `ch:"src"`
	DstIP6 netip.Addr `ch:"dst"`

	IPv6PayloadLen   uint16 `ch:"payload_len"`
	IPv6HopLimit     uint8  `ch:"hop_limit"`
	IPv6FlowLabel    uint32 `ch:"flow_label"`
	IPv6TrafficClass uint8  `ch:"traffic_class"`

	LayerIndex uint16 `ch:"layer_index"`
}

func (c *IPv6Component) Kind() uint           { return ComponentIPv6 }
func (c *IPv6Component) Name() string         { return "ipv6" }
func (c *IPv6Component) Order() uint          { return OrderL3Base }
func (c *IPv6Component) Index() uint16        { return c.LayerIndex }
func (c *IPv6Component) SetIndex(i uint16)    { c.LayerIndex = i }
func (c *IPv6Component) LayerSize() int       { return 40 }
func (c *IPv6Component) FetchOrderBy() string { return "packet_id" }

func (c *IPv6Component) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *IPv6Component) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *IPv6Component) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.PacketID = nucleus.PacketID
}

func (c *IPv6Component) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("ipv6 component missing")
	}
	layer := &layers.IPv6{
		Version:      6,
		TrafficClass: c.IPv6TrafficClass,
		FlowLabel:    c.IPv6FlowLabel,
		Length:       c.IPv6PayloadLen,
		NextHeader:   layers.IPProtocol(c.Protocol),
		HopLimit:     c.IPv6HopLimit,
		SrcIP:        net.IP(c.SrcIP6.AsSlice()),
		DstIP:        net.IP(c.DstIP6.AsSlice()),
	}
	ctx.Layers = append(ctx.Layers, layer)
	ctx.Offset += 40
	return nil
}

func (c *IPv6Component) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *IPv6Component) Encode(layer gopacket.Layer) ([]Component, error) {
	ip6, ok := layer.(*layers.IPv6)
	if !ok {
		return nil, errors.New("unsupported ipv6 layer")
	}
	contents := ip6.LayerContents()
	if len(contents) < 40 {
		return nil, ErrShortFrame
	}
	src, ok := netip.AddrFromSlice(ip6.SrcIP)
	if !ok {
		src = netip.Addr{}
	}
	dst, ok := netip.AddrFromSlice(ip6.DstIP)
	if !ok {
		dst = netip.Addr{}
	}
	return []Component{&IPv6Component{
		CodecVersion:     CodecVersionV1,
		Protocol:         uint8(ip6.NextHeader),
		SrcIP6:           src,
		DstIP6:           dst,
		IPv6PayloadLen:   ip6.Length,
		IPv6HopLimit:     ip6.HopLimit,
		IPv6FlowLabel:    ip6.FlowLabel,
		IPv6TrafficClass: ip6.TrafficClass,
	}}, nil
}

func (c *IPv6Component) Schema(table string) string { return applySchema(ipv6SchemaSQL, table) }
