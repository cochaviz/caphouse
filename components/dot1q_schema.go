package components

import (
	"errors"
	"fmt"

	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

func Dot1QSchema(table string) string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s
(
  capture_id UUID,
  packet_id UInt64,

  codec_version UInt16,

  tag_index UInt16,
  priority UInt8,
  drop_eligible UInt8,
  vlan_id UInt16,
  eth_type UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id, tag_index)`, table)
}

// Dot1QComponent stores one vlan tag (repeatable).
type Dot1QComponent struct {
	CaptureID    uuid.UUID
	PacketID     uint64
	CodecVersion uint16
	TagIndex     uint16
	Priority     uint8
	DropEligible uint8
	VLANID       uint16
	EtherType    uint16
}

func (c *Dot1QComponent) Kind() uint {
	return ComponentDot1Q
}

func (c *Dot1QComponent) Table() string {
	return "pcap_dot1q"
}

func (c *Dot1QComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *Dot1QComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *Dot1QComponent) Order() uint {
	return OrderL2Tag
}

func (c *Dot1QComponent) Index() uint16 {
	return c.TagIndex
}

func (c *Dot1QComponent) SetIndex(index uint16) {
	c.TagIndex = index
}

func (c *Dot1QComponent) HeaderLen() int {
	return 4
}

func (c *Dot1QComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
}

func (c *Dot1QComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("dot1q component missing")
	}
	layer := &layers.Dot1Q{
		Priority:       c.Priority,
		DropEligible:   c.DropEligible != 0,
		VLANIdentifier: c.VLANID,
		Type:           layers.EthernetType(c.EtherType),
	}
	ctx.Layers = append(ctx.Layers, layer)
	ctx.Offset += 4
	return nil
}
