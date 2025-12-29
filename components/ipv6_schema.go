package components

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

// IPv6Component stores parsed IPv6 fields.
type IPv6Component struct {
	CaptureID uuid.UUID
	PacketID  uint64
	Timestamp time.Time

	CodecVersion uint16

	ParsedOK uint8
	ParseErr string

	Protocol uint8

	SrcIP6 netip.Addr
	DstIP6 netip.Addr

	IPv6PayloadLen   uint16
	IPv6HopLimit     uint8
	IPv6FlowLabel    uint32
	IPv6TrafficClass uint8
}

func (c *IPv6Component) Kind() uint {
	return ComponentIPv6
}

func (c *IPv6Component) Table() string {
	return "pcap_ipv6"
}

func (c *IPv6Component) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *IPv6Component) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *IPv6Component) Order() uint {
	return OrderL3Base
}

func (c *IPv6Component) Index() uint16 {
	return 0
}

func (c *IPv6Component) SetIndex(_ uint16) {}

func (c *IPv6Component) HeaderLen() int {
	return 40
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

func IPv6Schema(table string) string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s
(
  capture_id UUID,
  packet_id UInt64,
  ts DateTime64(9),

  codec_version UInt16,

  parsed_ok UInt8,
  parse_err LowCardinality(String),

  protocol UInt8,

  src_ip_v6 IPv6,
  dst_ip_v6 IPv6,

  ipv6_payload_len UInt16,
  ipv6_hop_limit UInt8,
  ipv6_flow_label UInt32,
  ipv6_traffic_class UInt8
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (toDate(ts), protocol, dst_ip_v6, capture_id, packet_id)`, table)
}

func IPv6Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_dst_v6 (dst_ip_v6) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_proto (protocol) TYPE set(256) GRANULARITY 4", table),
	}
}
