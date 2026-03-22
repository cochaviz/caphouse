package components

import (
	_ "embed"
	"errors"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

//go:embed dot1q_schema.sql
var dot1qSchemaSQL string

// Dot1QComponent stores one vlan tag (repeatable).
type Dot1QComponent struct {
	CaptureID    uuid.UUID `ch:"capture_id"`
	PacketID     uint64    `ch:"packet_id"`
	CodecVersion uint16    `ch:"codec_version"`
	TagIndex     uint16    `ch:"tag_index"`
	Priority     uint8     `ch:"priority"`
	DropEligible uint8     `ch:"drop_eligible"`
	VLANID       uint16    `ch:"vlan_id"`
	EtherType    uint16    `ch:"type"`
}

func (c *Dot1QComponent) Kind() uint              { return ComponentDot1Q }
func (c *Dot1QComponent) Table() string           { return "pcap_dot1q" }
func (c *Dot1QComponent) Order() uint             { return OrderL2Tag }
func (c *Dot1QComponent) Index() uint16           { return c.TagIndex }
func (c *Dot1QComponent) SetIndex(index uint16)   { c.TagIndex = index }
func (c *Dot1QComponent) HeaderLen() int          { return 4 }
func (c *Dot1QComponent) FetchOrderBy() string    { return "packet_id, tag_index" }

func (c *Dot1QComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *Dot1QComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *Dot1QComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
}

func (c *Dot1QComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("dot1q component missing")
	}
	layer := &layers.Dot1Q{
		Priority:       c.Priority,
		DropEligible:   c.DropEligible != 0,
		VLANIdentifier: c.VLANID,
		Type:           layers.EthernetType(c.EtherType),
	}
	ctx.Layers = append(ctx.Layers, layer)
	ctx.Offset += 4
	return nil
}

func (c *Dot1QComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *Dot1QComponent) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	c.CaptureID = captureID
	err := rows.Scan(&c.PacketID, &c.TagIndex, &c.Priority, &c.DropEligible, &c.VLANID, &c.EtherType)
	return c.PacketID, err
}

func (c *Dot1QComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	tag, ok := layer.(*layers.Dot1Q)
	if !ok {
		return nil, errors.New("unsupported dot1q layer")
	}
	contents := tag.LayerContents()
	if len(contents) < 4 {
		return nil, ErrShortFrame
	}
	return []Component{&Dot1QComponent{
		CodecVersion: CodecVersionV1,
		Priority:     tag.Priority,
		DropEligible: boolToUint8(tag.DropEligible),
		VLANID:       tag.VLANIdentifier,
		EtherType:    uint16(tag.Type),
	}}, nil
}

func (c *Dot1QComponent) Schema(table string) string { return applySchema(dot1qSchemaSQL, table) }
func (c *Dot1QComponent) Indexes(_ string) []string  { return nil }
