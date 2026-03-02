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

//go:embed ipv4_schema.sql
var ipv4SchemaSQL string

// IPv4Component stores parsed IPv4 fields.
type IPv4Component struct {
	CaptureID uuid.UUID `ch:"capture_id"`
	PacketID  uint64    `ch:"packet_id"`
	Timestamp time.Time `ch:"ts"`

	CodecVersion uint16 `ch:"codec_version"`

	ParsedOK uint8  `ch:"parsed_ok"`
	ParseErr string `ch:"parse_err"`

	Protocol uint8 `ch:"protocol"`

	SrcIP4 netip.Addr `ch:"src_ip_v4"`
	DstIP4 netip.Addr `ch:"dst_ip_v4"`

	IPv4IHL         uint8  `ch:"ipv4_ihl"`
	IPv4TOS         uint8  `ch:"ipv4_tos"`
	IPv4TotalLen    uint16 `ch:"ipv4_total_len"`
	IPv4ID          uint16 `ch:"ipv4_id"`
	IPv4Flags       uint8  `ch:"ipv4_flags"`
	IPv4FragOffset  uint16 `ch:"ipv4_frag_offset"`
	IPv4TTL         uint8  `ch:"ipv4_ttl"`
	IPv4HdrChecksum uint16 `ch:"ipv4_hdr_checksum"`
}

func (c *IPv4Component) Kind() uint           { return ComponentIPv4 }
func (c *IPv4Component) Table() string        { return "pcap_ipv4" }
func (c *IPv4Component) Order() uint          { return OrderL3Base }
func (c *IPv4Component) Index() uint16        { return 0 }
func (c *IPv4Component) SetIndex(_ uint16)    {}
func (c *IPv4Component) HeaderLen() int       { return 20 }
func (c *IPv4Component) FetchFINAL() bool     { return false }
func (c *IPv4Component) FetchOrderBy() string { return "packet_id" }

func (c *IPv4Component) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

// ClickhouseValues overrides reflection to convert netip.Addr to strings.
func (c *IPv4Component) ClickhouseValues() ([]any, error) {
	return []any{
		c.CaptureID, c.PacketID, c.Timestamp, c.CodecVersion,
		c.ParsedOK, shortErr(c.ParseErr), c.Protocol,
		ipv4String(c.SrcIP4), ipv4String(c.DstIP4),
		c.IPv4IHL, c.IPv4TOS, c.IPv4TotalLen, c.IPv4ID,
		c.IPv4Flags, c.IPv4FragOffset, c.IPv4TTL, c.IPv4HdrChecksum,
	}, nil
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

func (c *IPv4Component) ScanColumns() []string {
	return []string{
		"packet_id", "ts", "parsed_ok", "parse_err", "protocol",
		"src_ip_v4", "dst_ip_v4",
		"ipv4_ihl", "ipv4_tos", "ipv4_total_len", "ipv4_id",
		"ipv4_flags", "ipv4_frag_offset", "ipv4_ttl", "ipv4_hdr_checksum",
	}
}

func (c *IPv4Component) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	var src, dst string
	c.CaptureID = captureID
	err := rows.Scan(
		&c.PacketID, &c.Timestamp, &c.ParsedOK, &c.ParseErr, &c.Protocol,
		&src, &dst,
		&c.IPv4IHL, &c.IPv4TOS, &c.IPv4TotalLen, &c.IPv4ID,
		&c.IPv4Flags, &c.IPv4FragOffset, &c.IPv4TTL, &c.IPv4HdrChecksum,
	)
	c.SrcIP4, _ = netip.ParseAddr(src)
	c.DstIP4, _ = netip.ParseAddr(dst)
	return c.PacketID, err
}

func (c *IPv4Component) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
	ip4, ok := layer.(*layers.IPv4)
	if !ok {
		return nil, errors.New("unsupported ipv4 layer")
	}
	contents := ip4.LayerContents()
	if len(contents) < 20 {
		return nil, ErrShortFrame
	}
	headerLen := int(ip4.IHL) * 4
	if ip4.IHL == 0 {
		headerLen = len(contents)
	}
	if headerLen < 20 || headerLen > len(contents) {
		return nil, fmt.Errorf("invalid ipv4 header length %d", headerLen)
	}
	src, ok := netip.AddrFromSlice(ip4.SrcIP)
	if !ok {
		src = netip.Addr{}
	}
	dst, ok := netip.AddrFromSlice(ip4.DstIP)
	if !ok {
		dst = netip.Addr{}
	}
	result := []ClickhouseMappedDecoder{&IPv4Component{
		CodecVersion:    CodecVersionV1,
		ParsedOK:        1,
		Protocol:        uint8(ip4.Protocol),
		SrcIP4:          src,
		DstIP4:          dst,
		IPv4IHL:         ip4.IHL,
		IPv4TOS:         ip4.TOS,
		IPv4TotalLen:    ip4.Length,
		IPv4ID:          ip4.Id,
		IPv4Flags:       uint8(ip4.Flags),
		IPv4FragOffset:  ip4.FragOffset,
		IPv4TTL:         ip4.TTL,
		IPv4HdrChecksum: ip4.Checksum,
	}}
	if optionsLen := headerLen - 20; optionsLen > 0 {
		result = append(result, newIPv4OptionsComponent(contents[20:headerLen]))
	}
	return result, nil
}

func IPv4Schema(table string) string {
	return applySchema(ipv4SchemaSQL, table)
}

func IPv4Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_dst_v4 (dst_ip_v4) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_proto (protocol) TYPE set(256) GRANULARITY 4", table),
	}
}
