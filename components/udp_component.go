package components

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed udp_schema.sql
var udpSchemaSQL string

// UDPComponent stores parsed UDP header fields.
type UDPComponent struct {
	SessionID    uint64 `ch:"session_id"`
	Ts           int64  `ch:"ts"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`

	SrcPort  uint16 `ch:"src"`
	DstPort  uint16 `ch:"dst"`
	Length   uint16 `ch:"length"`
	Checksum uint16 `ch:"checksum"`
}

func (c *UDPComponent) Kind() uint   { return ComponentUDP }
func (c *UDPComponent) Name() string { return "udp" }
func (c *UDPComponent) Order() uint          { return OrderL4Base }
func (c *UDPComponent) Index() uint16        { return 0 }
func (c *UDPComponent) SetIndex(_ uint16)    {}
func (c *UDPComponent) HeaderLen() int       { return 8 }
func (c *UDPComponent) FetchOrderBy() string { return "packet_id" }

func (c *UDPComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *UDPComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *UDPComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.Ts = nucleus.Timestamp.UnixNano()
	c.PacketID = nucleus.PacketID
}

func (c *UDPComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("udp component missing")
	}
	var hdr [8]byte
	binary.BigEndian.PutUint16(hdr[0:2], c.SrcPort)
	binary.BigEndian.PutUint16(hdr[2:4], c.DstPort)
	binary.BigEndian.PutUint16(hdr[4:6], c.Length)
	binary.BigEndian.PutUint16(hdr[6:8], c.Checksum)
	ctx.Layers = append(ctx.Layers, gopacket.Payload(hdr[:]))
	ctx.Offset += 8
	return nil
}

func (c *UDPComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *UDPComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	udp, ok := layer.(*layers.UDP)
	if !ok {
		return nil, errors.New("unsupported udp layer")
	}
	if len(udp.LayerContents()) < 8 {
		return nil, ErrShortFrame
	}
	return []Component{&UDPComponent{
		CodecVersion: CodecVersionV1,
		SrcPort:      uint16(udp.SrcPort),
		DstPort:      uint16(udp.DstPort),
		Length:       udp.Length,
		Checksum:     udp.Checksum,
	}}, nil
}

func (c *UDPComponent) Schema(table string) string { return applySchema(udpSchemaSQL, table) }
func (c *UDPComponent) Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_dst (dst) TYPE bloom_filter GRANULARITY 4", table),
	}
}
