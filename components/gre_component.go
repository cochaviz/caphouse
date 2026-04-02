package components

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed gre_schema.sql
var greSchemaSQL string

// GREComponent stores parsed GRE header fields.
// Flags encodes optional-field presence as a bitmask:
//
//	bit 0 = ChecksumPresent (+4 bytes: checksum + reserved)
//	bit 1 = KeyPresent      (+4 bytes)
//	bit 2 = SeqPresent      (+4 bytes)
type GREComponent struct {
	SessionID    uint64 `ch:"session_id"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`

	Protocol uint16 `ch:"protocol"` // encapsulated EthernetType
	Flags    uint8  `ch:"flags"`
	Version  uint8  `ch:"version"`
	Checksum uint16 `ch:"checksum"`
	Key      uint32 `ch:"key"`
	Seq      uint32 `ch:"seq"`

	LayerIndex uint16 `ch:"layer_index"`
}

func (c *GREComponent) Kind() uint           { return ComponentGRE }
func (c *GREComponent) Name() string         { return "gre" }
func (c *GREComponent) Order() uint          { return OrderL3Base }
func (c *GREComponent) Index() uint16        { return c.LayerIndex }
func (c *GREComponent) SetIndex(i uint16)    { c.LayerIndex = i }
func (c *GREComponent) FetchOrderBy() string { return "packet_id" }

func (c *GREComponent) HeaderLen() int {
	n := 4
	if c.Flags&0x01 != 0 {
		n += 4 // checksum + reserved
	}
	if c.Flags&0x02 != 0 {
		n += 4 // key
	}
	if c.Flags&0x04 != 0 {
		n += 4 // seq
	}
	return n
}

func (c *GREComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *GREComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *GREComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.PacketID = nucleus.PacketID
}

func (c *GREComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("gre component missing")
	}
	n := c.HeaderLen()
	hdr := make([]byte, n)
	var word0 uint16
	if c.Flags&0x01 != 0 {
		word0 |= 0x8000
	}
	if c.Flags&0x02 != 0 {
		word0 |= 0x2000
	}
	if c.Flags&0x04 != 0 {
		word0 |= 0x1000
	}
	word0 |= uint16(c.Version) & 0x07
	binary.BigEndian.PutUint16(hdr[0:2], word0)
	binary.BigEndian.PutUint16(hdr[2:4], c.Protocol)
	off := 4
	if c.Flags&0x01 != 0 {
		binary.BigEndian.PutUint16(hdr[off:off+2], c.Checksum)
		off += 4 // checksum (2) + reserved (2)
	}
	if c.Flags&0x02 != 0 {
		binary.BigEndian.PutUint32(hdr[off:off+4], c.Key)
		off += 4
	}
	if c.Flags&0x04 != 0 {
		binary.BigEndian.PutUint32(hdr[off:off+4], c.Seq)
		off += 4
	}
	_ = off
	ctx.Layers = append(ctx.Layers, gopacket.Payload(hdr))
	ctx.Offset += n
	return nil
}

func (c *GREComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *GREComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	gre, ok := layer.(*layers.GRE)
	if !ok {
		return nil, errors.New("unsupported gre layer")
	}
	if len(gre.LayerContents()) < 4 {
		return nil, ErrShortFrame
	}
	var flags uint8
	if gre.ChecksumPresent {
		flags |= 0x01
	}
	if gre.KeyPresent {
		flags |= 0x02
	}
	if gre.SeqPresent {
		flags |= 0x04
	}
	return []Component{&GREComponent{
		CodecVersion: CodecVersionV1,
		Protocol:     uint16(gre.Protocol),
		Flags:        flags,
		Version:      gre.Version,
		Checksum:     gre.Checksum,
		Key:          gre.Key,
		Seq:          gre.Seq,
	}}, nil
}

func (c *GREComponent) Schema(table string) string { return applySchema(greSchemaSQL, table) }
func (c *GREComponent) Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS layer_index UInt16 CODEC(Delta, LZ4)", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_protocol (protocol) TYPE set(256) GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_key (key) TYPE bloom_filter GRANULARITY 4", table),
	}
}
