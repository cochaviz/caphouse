package components

import (
	_ "embed"
	"errors"
	"net"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed ethernet_schema.sql
var ethernetSchemaSQL string

// EthernetComponent stores raw ethernet header bytes.
type EthernetComponent struct {
	SessionID    uint64    `ch:"session_id"`
	Ts           int64     `ch:"ts"`
	PacketID  uint32 `ch:"packet_id"`
	CodecVersion uint16    `ch:"codec_version"`
	SrcMAC    []byte `ch:"src"`
	DstMAC    []byte `ch:"dst"`
	EtherType uint16 `ch:"type"`
	Length    uint16 `ch:"len"`
}

func (c *EthernetComponent) Kind() uint        { return ComponentEthernet }
func (c *EthernetComponent) Table() string     { return "pcap_ethernet" }
func (c *EthernetComponent) Order() uint       { return OrderL2Base }
func (c *EthernetComponent) Index() uint16     { return 0 }
func (c *EthernetComponent) SetIndex(_ uint16) {}
func (c *EthernetComponent) HeaderLen() int    { return 14 }
func (c *EthernetComponent) FetchOrderBy() string { return "packet_id" }

func (c *EthernetComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *EthernetComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *EthernetComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.Ts = nucleus.Timestamp.UnixNano()
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

func (c *EthernetComponent) ScanRow(sessionID uint64, rows chdriver.Rows) (uint32, error) {
	var src, dst string
	c.SessionID = sessionID
	err := rows.Scan(&c.PacketID, &src, &dst, &c.EtherType, &c.Length)
	c.SrcMAC, c.DstMAC = []byte(src), []byte(dst)
	return c.PacketID, err
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
func (c *EthernetComponent) Indexes(_ string) []string  { return nil }
