package components

import (
	_ "embed"
	"errors"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/uuid"
)

//go:embed ipv6_ext_schema.sql
var ipv6ExtSchemaSQL string

// IPv6ExtComponent stores one raw IPv6 extension header (repeatable).
type IPv6ExtComponent struct {
	CaptureID    uuid.UUID `ch:"capture_id"`
	PacketID     uint64    `ch:"packet_id"`
	CodecVersion uint16    `ch:"codec_version"`
	ExtIndex     uint16    `ch:"ext_index"`
	ExtType      uint16    `ch:"ext_type"`
	ExtRaw       []byte    `ch:"ext_raw"`
}

func (c *IPv6ExtComponent) Kind() uint            { return ComponentIPv6Ext }
func (c *IPv6ExtComponent) Table() string         { return "pcap_ipv6_ext" }
func (c *IPv6ExtComponent) Order() uint           { return OrderL3Ext }
func (c *IPv6ExtComponent) Index() uint16         { return c.ExtIndex }
func (c *IPv6ExtComponent) SetIndex(i uint16)     { c.ExtIndex = i }
func (c *IPv6ExtComponent) FetchOrderBy() string  { return "packet_id, ext_index" }

func (c *IPv6ExtComponent) HeaderLen() int {
	if len(c.ExtRaw) < 2 {
		return len(c.ExtRaw)
	}
	return (int(c.ExtRaw[1]) + 1) * 8
}

func (c *IPv6ExtComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *IPv6ExtComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *IPv6ExtComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
}

func (c *IPv6ExtComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("ipv6 ext component missing")
	}
	if len(c.ExtRaw) < 2 {
		return errors.New("ipv6 ext too short")
	}
	if len(c.ExtRaw) != c.HeaderLen() {
		return errors.New("ipv6 ext length mismatch")
	}
	ctx.Layers = append(ctx.Layers, gopacket.Payload(c.ExtRaw))
	ctx.Offset += c.HeaderLen()
	return nil
}

func (c *IPv6ExtComponent) ScanColumns() []string {
	return []string{"packet_id", "ext_index", "ext_type", "ext_raw"}
}

func (c *IPv6ExtComponent) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	var raw string
	c.CaptureID = captureID
	err := rows.Scan(&c.PacketID, &c.ExtIndex, &c.ExtType, &raw)
	c.ExtRaw = []byte(raw)
	return c.PacketID, err
}

func (c *IPv6ExtComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	contents := layer.LayerContents()
	if len(contents) == 0 {
		return nil, ErrShortFrame
	}
	return []Component{&IPv6ExtComponent{
		CodecVersion: CodecVersionV1,
		ExtType:      uint16(layer.LayerType()),
		ExtRaw:       copyBytes(contents),
	}}, nil
}

func IPv6ExtSchema(table string) string {
	return applySchema(ipv6ExtSchemaSQL, table)
}
