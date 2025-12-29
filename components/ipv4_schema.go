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

// IPv4Component stores parsed IPv4 fields.
type IPv4Component struct {
	CaptureID uuid.UUID
	PacketID  uint64
	Timestamp time.Time

	CodecVersion uint16

	ParsedOK uint8
	ParseErr string

	Protocol uint8

	SrcIP4 netip.Addr
	DstIP4 netip.Addr

	IPv4IHL         uint8
	IPv4TOS         uint8
	IPv4TotalLen    uint16
	IPv4ID          uint16
	IPv4Flags       uint8
	IPv4FragOffset  uint16
	IPv4TTL         uint8
	IPv4HdrChecksum uint16
}

func (c *IPv4Component) Kind() uint {
	return ComponentIPv4
}

func (c *IPv4Component) Table() string {
	return "pcap_ipv4"
}

func (c *IPv4Component) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *IPv4Component) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *IPv4Component) Order() uint {
	return OrderL3Base
}

func (c *IPv4Component) Index() uint16 {
	return 0
}

func (c *IPv4Component) SetIndex(_ uint16) {}

func (c *IPv4Component) HeaderLen() int {
	return 20
}

func (c *IPv4Component) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
	c.Timestamp = nucleus.Timestamp
}

func (c *IPv4Component) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("ipv4 component missing")
	}
	layer := &layers.IPv4{
		Version:    4,
		IHL:        c.IPv4IHL,
		TOS:        c.IPv4TOS,
		Length:     c.IPv4TotalLen,
		Id:         c.IPv4ID,
		Flags:      layers.IPv4Flag(c.IPv4Flags),
		FragOffset: c.IPv4FragOffset,
		TTL:        c.IPv4TTL,
		Protocol:   layers.IPProtocol(c.Protocol),
		Checksum:   c.IPv4HdrChecksum,
		SrcIP:      net.IP(c.SrcIP4.AsSlice()),
		DstIP:      net.IP(c.DstIP4.AsSlice()),
	}
	ctx.Layers = append(ctx.Layers, layer)
	ctx.Offset += 20
	ctx.LastIPv4 = layer
	return nil
}

func IPv4Schema(table string) string {
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

  src_ip_v4 IPv4,
  dst_ip_v4 IPv4,

  ipv4_ihl UInt8,
  ipv4_tos UInt8,
  ipv4_total_len UInt16,
  ipv4_id UInt16,
  ipv4_flags UInt8,
  ipv4_frag_offset UInt16,
  ipv4_ttl UInt8,
  ipv4_hdr_checksum UInt16
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (toDate(ts), protocol, dst_ip_v4, capture_id, packet_id)`, table)
}

func IPv4Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_dst_v4 (dst_ip_v4) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_proto (protocol) TYPE set(256) GRANULARITY 4", table),
	}
}
