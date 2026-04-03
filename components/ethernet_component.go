package components

import (
	_ "embed"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed ethernet_schema.sql
var ethernetSchemaSQL string

// EthernetComponent stores raw ethernet header bytes.
type EthernetComponent struct {
	SessionID    uint64 `ch:"session_id"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`
	LayerIndex   uint16 `ch:"layer_index"`
	SrcMAC       []byte `ch:"src"`
	DstMAC       []byte `ch:"dst"`
	EtherType    uint16 `ch:"type"`
	Length       uint16 `ch:"len"`
}

func (c *EthernetComponent) Kind() uint           { return ComponentEthernet }
func (c *EthernetComponent) Name() string         { return "ethernet" }
func (c *EthernetComponent) Order() uint          { return OrderL2Base }
func (c *EthernetComponent) Index() uint16        { return c.LayerIndex }
func (c *EthernetComponent) SetIndex(i uint16)    { c.LayerIndex = i }
func (c *EthernetComponent) LayerSize() int       { return 14 }
func (c *EthernetComponent) FetchOrderBy() string { return "packet_id" }

func (c *EthernetComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *EthernetComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *EthernetComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.PacketID = nucleus.PacketID
}

func (c *EthernetComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("ethernet component missing")
	}
	if len(c.SrcMAC) != 6 || len(c.DstMAC) != 6 {
		return errors.New("ethernet mac length invalid")
	}
	layer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(copyBytes(c.SrcMAC)),
		DstMAC:       net.HardwareAddr(copyBytes(c.DstMAC)),
		EthernetType: layers.EthernetType(c.EtherType),
		Length:       c.Length,
	}
	ctx.Layers = append(ctx.Layers, layer)
	ctx.Offset += 14
	return nil
}

func (c *EthernetComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *EthernetComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	eth, ok := layer.(*layers.Ethernet)
	if !ok {
		return nil, errors.New("unsupported ethernet layer")
	}
	contents := eth.LayerContents()
	if len(contents) < 14 {
		return nil, ErrShortFrame
	}
	if len(eth.SrcMAC) != 6 || len(eth.DstMAC) != 6 {
		return nil, errors.New("invalid ethernet mac length")
	}
	return []Component{&EthernetComponent{
		CodecVersion: CodecVersionV1,
		SrcMAC:       copyBytes(eth.SrcMAC),
		DstMAC:       copyBytes(eth.DstMAC),
		EtherType:    uint16(eth.EthernetType),
		Length:       eth.Length,
	}}, nil
}

func (c *EthernetComponent) Schema(table string) string { return applySchema(ethernetSchemaSQL, table) }
func (c *EthernetComponent) Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS layer_index UInt16 CODEC(Delta, LZ4)", table),
	}
}
