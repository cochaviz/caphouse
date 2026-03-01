package components

import (
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/uuid"
)

// IPv6ExtComponent stores one raw IPv6 extension header (repeatable).
type IPv6ExtComponent struct {
	CaptureID    uuid.UUID
	PacketID     uint64
	CodecVersion uint16
	ExtIndex     uint16
	ExtType      uint16
	ExtRaw       []byte
}

func (c *IPv6ExtComponent) Kind() uint {
	return ComponentIPv6Ext
}

func (c *IPv6ExtComponent) Table() string {
	return "pcap_ipv6_ext"
}

func (c *IPv6ExtComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *IPv6ExtComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *IPv6ExtComponent) Order() uint {
	return OrderL3Ext
}

func (c *IPv6ExtComponent) Index() uint16 {
	return c.ExtIndex
}

func (c *IPv6ExtComponent) SetIndex(index uint16) {
	c.ExtIndex = index
}

func (c *IPv6ExtComponent) HeaderLen() int {
	contentsLen := len(c.ExtRaw)
	if contentsLen < 2 {
		return contentsLen
	}
	extLen := int(c.ExtRaw[1]) + 1
	return extLen * 8
}

func (c *IPv6ExtComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
}

func (c *IPv6ExtComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("ipv6 ext component missing")
	}
	if len(c.ExtRaw) < 2 {
		return errors.New("ipv6 ext too short")
	}
	if len(c.ExtRaw) != c.HeaderLen() {
		return errors.New("ipv6 ext length mismatch")
	}
	ctx.Layers = append(ctx.Layers, gopacket.Payload(c.ExtRaw))
	ctx.Offset += c.HeaderLen()
	return nil
}

func IPv6ExtSchema(table string) string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s
(
  capture_id UUID,
  packet_id UInt64,

  codec_version UInt16,

  ext_index UInt16,
  ext_type UInt16,
  ext_raw String CODEC(ZSTD)
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id, ext_index)`, table)
}
