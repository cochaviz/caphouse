package components

import (
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

//go:embed ipv6_schema.sql
var ipv6SchemaSQL string

// IPv6Component stores parsed IPv6 fields.
type IPv6Component struct {
	CaptureID uuid.UUID `ch:"capture_id"`
	PacketID  uint64    `ch:"packet_id"`
	Timestamp time.Time `ch:"ts"`

	CodecVersion uint16 `ch:"codec_version"`

	ParsedOK uint8  `ch:"parsed_ok"`
	ParseErr string `ch:"parse_err"`

	Protocol uint8 `ch:"protocol"`

	SrcIP6 netip.Addr `ch:"src_ip_v6"`
	DstIP6 netip.Addr `ch:"dst_ip_v6"`

	IPv6PayloadLen   uint16 `ch:"ipv6_payload_len"`
	IPv6HopLimit     uint8  `ch:"ipv6_hop_limit"`
	IPv6FlowLabel    uint32 `ch:"ipv6_flow_label"`
	IPv6TrafficClass uint8  `ch:"ipv6_traffic_class"`
}

func (c *IPv6Component) Kind() uint           { return ComponentIPv6 }
func (c *IPv6Component) Table() string        { return "pcap_ipv6" }
func (c *IPv6Component) Order() uint          { return OrderL3Base }
func (c *IPv6Component) Index() uint16        { return 0 }
func (c *IPv6Component) SetIndex(_ uint16)    {}
func (c *IPv6Component) HeaderLen() int       { return 40 }
func (c *IPv6Component) FetchFINAL() bool     { return false }
func (c *IPv6Component) FetchOrderBy() string { return "packet_id" }

func (c *IPv6Component) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

// ClickhouseValues overrides reflection to convert netip.Addr to strings.
func (c *IPv6Component) ClickhouseValues() ([]any, error) {
	return []any{
		c.CaptureID, c.PacketID, c.Timestamp, c.CodecVersion,
		c.ParsedOK, shortErr(c.ParseErr), c.Protocol,
		ipv6String(c.SrcIP6), ipv6String(c.DstIP6),
		c.IPv6PayloadLen, c.IPv6HopLimit, c.IPv6FlowLabel, c.IPv6TrafficClass,
	}, nil
}

func (c *IPv6Component) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
	c.Timestamp = nucleus.Timestamp
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

func (c *IPv6Component) ScanColumns() []string {
	return []string{
		"packet_id", "ts", "parsed_ok", "parse_err", "protocol",
		"src_ip_v6", "dst_ip_v6",
		"ipv6_payload_len", "ipv6_hop_limit", "ipv6_flow_label", "ipv6_traffic_class",
	}
}

func (c *IPv6Component) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	var src, dst string
	c.CaptureID = captureID
	err := rows.Scan(
		&c.PacketID, &c.Timestamp, &c.ParsedOK, &c.ParseErr, &c.Protocol,
		&src, &dst,
		&c.IPv6PayloadLen, &c.IPv6HopLimit, &c.IPv6FlowLabel, &c.IPv6TrafficClass,
	)
	c.SrcIP6, _ = netip.ParseAddr(src)
	c.DstIP6, _ = netip.ParseAddr(dst)
	return c.PacketID, err
}

func (c *IPv6Component) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
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
	return []ClickhouseMappedDecoder{&IPv6Component{
		CodecVersion:     CodecVersionV1,
		ParsedOK:         1,
		Protocol:         uint8(ip6.NextHeader),
		SrcIP6:           src,
		DstIP6:           dst,
		IPv6PayloadLen:   ip6.Length,
		IPv6HopLimit:     ip6.HopLimit,
		IPv6FlowLabel:    ip6.FlowLabel,
		IPv6TrafficClass: ip6.TrafficClass,
	}}, nil
}

func IPv6Schema(table string) string {
	return applySchema(ipv6SchemaSQL, table)
}

func IPv6Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_dst_v6 (dst_ip_v6) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_proto (protocol) TYPE set(256) GRANULARITY 4", table),
	}
}
