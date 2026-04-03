package components

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed icmpv4_schema.sql
var icmpv4SchemaSQL string

// ICMPv4Component stores the fixed 8-byte ICMPv4 header.
// The id and seq fields correspond to bytes 4–7 of the header; for non-echo
// message types these bytes carry type-specific data but are preserved exactly.
type ICMPv4Component struct {
	SessionID    uint64 `ch:"session_id"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`
	LayerIndex   uint16 `ch:"layer_index"`

	Type     uint8  `ch:"type"`
	Code     uint8  `ch:"code"`
	Checksum uint16 `ch:"checksum"`
	Id       uint16 `ch:"id"`
	Seq      uint16 `ch:"seq"`
}

func (c *ICMPv4Component) Kind() uint           { return ComponentICMPv4 }
func (c *ICMPv4Component) Name() string         { return "icmpv4" }
func (c *ICMPv4Component) Order() uint          { return OrderL4Base }
func (c *ICMPv4Component) Index() uint16        { return c.LayerIndex }
func (c *ICMPv4Component) SetIndex(i uint16)    { c.LayerIndex = i }
func (c *ICMPv4Component) LayerSize() int       { return 8 }
func (c *ICMPv4Component) FetchOrderBy() string { return "packet_id" }

func (c *ICMPv4Component) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *ICMPv4Component) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *ICMPv4Component) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.PacketID = nucleus.PacketID
}

func (c *ICMPv4Component) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("icmpv4 component missing")
	}
	var hdr [8]byte
	hdr[0] = c.Type
	hdr[1] = c.Code
	binary.BigEndian.PutUint16(hdr[2:4], c.Checksum)
	binary.BigEndian.PutUint16(hdr[4:6], c.Id)
	binary.BigEndian.PutUint16(hdr[6:8], c.Seq)
	ctx.Layers = append(ctx.Layers, gopacket.Payload(hdr[:]))
	ctx.Offset += 8
	return nil
}

func (c *ICMPv4Component) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *ICMPv4Component) Encode(layer gopacket.Layer) ([]Component, error) {
	icmp, ok := layer.(*layers.ICMPv4)
	if !ok {
		return nil, errors.New("unsupported icmpv4 layer")
	}
	if len(icmp.LayerContents()) < 8 {
		return nil, ErrShortFrame
	}
	return []Component{&ICMPv4Component{
		CodecVersion: CodecVersionV1,
		Type:         icmp.TypeCode.Type(),
		Code:         icmp.TypeCode.Code(),
		Checksum:     icmp.Checksum,
		Id:           icmp.Id,
		Seq:          icmp.Seq,
	}}, nil
}

func (c *ICMPv4Component) Schema(table string) string { return applySchema(icmpv4SchemaSQL, table) }
func (c *ICMPv4Component) Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS layer_index UInt16 CODEC(Delta, LZ4)", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_type (type) TYPE set(256) GRANULARITY 4", table),
	}
}
