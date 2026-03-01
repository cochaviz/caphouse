package components

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

// EthernetComponent stores raw ethernet header bytes.
type EthernetComponent struct {
	CaptureID    uuid.UUID
	PacketID     uint64
	CodecVersion uint16
	SrcMAC       []byte
	DstMAC       []byte
	EtherType    uint16
	Length       uint16
}

func (c *EthernetComponent) Kind() uint {
	return ComponentEthernet
}

func (c *EthernetComponent) Table() string {
	return "pcap_ethernet"
}

func (c *EthernetComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *EthernetComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *EthernetComponent) Order() uint {
	return OrderL2Base
}

func (c *EthernetComponent) Index() uint16 {
	return 0
}

func (c *EthernetComponent) SetIndex(_ uint16) {}

func (c *EthernetComponent) HeaderLen() int {
	return 14
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

func EthernetSchema(table string) string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s
(
  capture_id UUID,
  packet_id UInt64,

  codec_version UInt16,

  src_mac String CODEC(ZSTD),
  dst_mac String CODEC(ZSTD),
  eth_type UInt16,
  eth_len UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id)`, table)
}
