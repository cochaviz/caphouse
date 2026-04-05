package components

import (
	_ "embed"
	"errors"

	"github.com/google/gopacket"
)

//go:embed ipv6_ext_schema.sql
var ipv6ExtSchemaSQL string

// IPv6ExtComponent stores one raw IPv6 extension header (repeatable).
type IPv6ExtComponent struct {
	SessionID    uint64 `ch:"session_id"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`
	LayerIndex   uint16 `ch:"layer_index"`
	ExtType      uint16 `ch:"ext_type"`
	ExtRaw       []byte `ch:"ext_raw"`

	// export scan buffers — populated from groupArray CTE columns
	exportLayerIndex []uint16
	exportExtType    []uint16
	exportExtRaw     []string // groupArray of a String column yields []string
}

func (c *IPv6ExtComponent) Kind() uint           { return ComponentIPv6Ext }
func (c *IPv6ExtComponent) Name() string         { return "ipv6_ext" }
func (c *IPv6ExtComponent) Order() uint          { return OrderL3Ext }
func (c *IPv6ExtComponent) Index() uint16        { return c.LayerIndex }
func (c *IPv6ExtComponent) SetIndex(i uint16)    { c.LayerIndex = i }
func (c *IPv6ExtComponent) FetchOrderBy() string { return "packet_id, layer_index" }

func (c *IPv6ExtComponent) LayerSize() int {
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
	c.SessionID = nucleus.SessionID
	c.PacketID = nucleus.PacketID
}

func (c *IPv6ExtComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("ipv6 ext component missing")
	}
	if len(c.ExtRaw) < 2 {
		return errors.New("ipv6 ext too short")
	}
	if len(c.ExtRaw) != c.LayerSize() {
		return errors.New("ipv6 ext length mismatch")
	}
	ctx.Layers = append(ctx.Layers, gopacket.Payload(c.ExtRaw))
	ctx.Offset += c.LayerSize()
	return nil
}

func (c *IPv6ExtComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
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

func (c *IPv6ExtComponent) ExportScanTargets() []any {
	// Order matches DataColumns("ipv6_ext"): layer_index, ext_type, ext_raw
	// Each target is a slice that receives a groupArray result.
	return []any{&c.exportLayerIndex, &c.exportExtType, &c.exportExtRaw}
}

func (c *IPv6ExtComponent) ExportExpand(sessionID uint64, packetID uint32) []Component {
	out := make([]Component, len(c.exportLayerIndex))
	for i := range c.exportLayerIndex {
		out[i] = &IPv6ExtComponent{
			SessionID:  sessionID,
			PacketID:   packetID,
			LayerIndex: c.exportLayerIndex[i],
			ExtType:    c.exportExtType[i],
			ExtRaw:     []byte(c.exportExtRaw[i]),
		}
	}
	return out
}

func (c *IPv6ExtComponent) Schema(table string) string { return applySchema(ipv6ExtSchemaSQL, table) }
