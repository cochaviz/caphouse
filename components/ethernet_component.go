package components

import (
	_ "embed"
	"errors"
	"net"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

//go:embed ethernet_schema.sql
var ethernetSchemaSQL string

// EthernetComponent stores raw ethernet header bytes.
type EthernetComponent struct {
	CaptureID    uuid.UUID `ch:"capture_id"`
	PacketID     uint64    `ch:"packet_id"`
	CodecVersion uint16    `ch:"codec_version"`
	SrcMAC       []byte    `ch:"src_mac"`
	DstMAC       []byte    `ch:"dst_mac"`
	EtherType    uint16    `ch:"eth_type"`
	Length       uint16    `ch:"eth_len"`
}

func (c *EthernetComponent) Kind() uint        { return ComponentEthernet }
func (c *EthernetComponent) Table() string     { return "pcap_ethernet" }
func (c *EthernetComponent) Order() uint       { return OrderL2Base }
func (c *EthernetComponent) Index() uint16     { return 0 }
func (c *EthernetComponent) SetIndex(_ uint16) {}
func (c *EthernetComponent) HeaderLen() int    { return 14 }
func (c *EthernetComponent) FetchFINAL() bool  { return false }
func (c *EthernetComponent) FetchOrderBy() string { return "packet_id" }

func (c *EthernetComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *EthernetComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *EthernetComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
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

func (c *EthernetComponent) ScanColumns() []string {
	return []string{"packet_id", "src_mac", "dst_mac", "eth_type", "eth_len"}
}

func (c *EthernetComponent) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	var src, dst string
	c.CaptureID = captureID
	err := rows.Scan(&c.PacketID, &src, &dst, &c.EtherType, &c.Length)
	c.SrcMAC, c.DstMAC = []byte(src), []byte(dst)
	return c.PacketID, err
}

func (c *EthernetComponent) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
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
	return []ClickhouseMappedDecoder{&EthernetComponent{
		CodecVersion: CodecVersionV1,
		SrcMAC:       copyBytes(eth.SrcMAC),
		DstMAC:       copyBytes(eth.DstMAC),
		EtherType:    uint16(eth.EthernetType),
		Length:       eth.Length,
	}}, nil
}

func EthernetSchema(table string) string {
	return applySchema(ethernetSchemaSQL, table)
}
