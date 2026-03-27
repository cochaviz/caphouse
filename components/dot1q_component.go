package components

import (
	_ "embed"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed dot1q_schema.sql
var dot1qSchemaSQL string

// Dot1QComponent stores one vlan tag (repeatable).
type Dot1QComponent struct {
	SessionID    uint64 `ch:"session_id"`
	Ts           int64  `ch:"ts"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`
	TagIndex     uint16 `ch:"tag_index"`
	Priority     uint8  `ch:"priority"`
	DropEligible uint8  `ch:"drop_eligible"`
	VLANID       uint16 `ch:"vlan_id"`
	EtherType    uint16 `ch:"type"`

	// export scan buffers — populated from groupArray CTE columns
	exportTagIndex     []uint16
	exportPriority     []uint8
	exportDropEligible []uint8
	exportVLANID       []uint16
	exportEtherType    []uint16
}

func (c *Dot1QComponent) Kind() uint   { return ComponentDot1Q }
func (c *Dot1QComponent) Name() string { return "dot1q" }
func (c *Dot1QComponent) Order() uint           { return OrderL2Tag }
func (c *Dot1QComponent) Index() uint16         { return c.TagIndex }
func (c *Dot1QComponent) SetIndex(index uint16) { c.TagIndex = index }
func (c *Dot1QComponent) HeaderLen() int        { return 4 }
func (c *Dot1QComponent) FetchOrderBy() string  { return "packet_id, tag_index" }

func (c *Dot1QComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *Dot1QComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *Dot1QComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.Ts = nucleus.Timestamp.UnixNano()
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

func (c *Dot1QComponent) ExportScanTargets() []any {
	// Order matches DataColumns("dot1q"): tag_index, priority, drop_eligible, vlan_id, type
	// Each target is a slice that receives a groupArray result.
	return []any{&c.exportTagIndex, &c.exportPriority, &c.exportDropEligible, &c.exportVLANID, &c.exportEtherType}
}

func (c *Dot1QComponent) ExportExpand(sessionID uint64, packetID uint32) []Component {
	out := make([]Component, len(c.exportTagIndex))
	for i := range c.exportTagIndex {
		out[i] = &Dot1QComponent{
			SessionID:    sessionID,
			PacketID:     packetID,
			TagIndex:     c.exportTagIndex[i],
			Priority:     c.exportPriority[i],
			DropEligible: c.exportDropEligible[i],
			VLANID:       c.exportVLANID[i],
			EtherType:    c.exportEtherType[i],
		}
	}
	return out
}

func (c *Dot1QComponent) Schema(table string) string { return applySchema(dot1qSchemaSQL, table) }
func (c *Dot1QComponent) Indexes(_ string) []string  { return nil }
