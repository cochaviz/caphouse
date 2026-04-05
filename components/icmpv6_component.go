package components

import (
	_ "embed"
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed icmpv6_schema.sql
var icmpv6SchemaSQL string

// ICMPv6Component stores the fixed 4-byte ICMPv6 header (TypeCode + Checksum).
// The variable-length body (e.g. echo Id/Seq, NDP fields) is stored in the
// packet nucleus payload.
type ICMPv6Component struct {
	SessionID    uint64 `ch:"session_id"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`
	LayerIndex   uint16 `ch:"layer_index"`

	Type     uint8  `ch:"type"`
	Code     uint8  `ch:"code"`
	Checksum uint16 `ch:"checksum"`
}

func (c *ICMPv6Component) Kind() uint           { return ComponentICMPv6 }
func (c *ICMPv6Component) Name() string         { return "icmpv6" }
func (c *ICMPv6Component) Order() uint          { return OrderL4Base }
func (c *ICMPv6Component) Index() uint16        { return c.LayerIndex }
func (c *ICMPv6Component) SetIndex(i uint16)    { c.LayerIndex = i }
func (c *ICMPv6Component) LayerSize() int       { return 4 }
func (c *ICMPv6Component) FetchOrderBy() string { return "packet_id" }

func (c *ICMPv6Component) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *ICMPv6Component) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *ICMPv6Component) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.PacketID = nucleus.PacketID
}

func (c *ICMPv6Component) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("icmpv6 component missing")
	}
	var hdr [4]byte
	hdr[0] = c.Type
	hdr[1] = c.Code
	binary.BigEndian.PutUint16(hdr[2:4], c.Checksum)
	ctx.Layers = append(ctx.Layers, gopacket.Payload(hdr[:]))
	ctx.Offset += 4
	return nil
}

func (c *ICMPv6Component) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *ICMPv6Component) Encode(layer gopacket.Layer) ([]Component, error) {
	icmp, ok := layer.(*layers.ICMPv6)
	if !ok {
		return nil, errors.New("unsupported icmpv6 layer")
	}
	if len(icmp.LayerContents()) < 4 {
		return nil, ErrShortFrame
	}
	return []Component{&ICMPv6Component{
		CodecVersion: CodecVersionV1,
		Type:         icmp.TypeCode.Type(),
		Code:         icmp.TypeCode.Code(),
		Checksum:     icmp.Checksum,
	}}, nil
}

func (c *ICMPv6Component) Schema(table string) string { return applySchema(icmpv6SchemaSQL, table) }
