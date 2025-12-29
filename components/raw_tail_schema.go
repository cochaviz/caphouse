package components

import (
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/uuid"
)

// RawTailComponent stores bytes from tail_offset to the end of the frame.
type RawTailComponent struct {
	CaptureID  uuid.UUID
	PacketID   uint64
	TailOffset uint16
	Bytes      []byte
}

func (c *RawTailComponent) Kind() uint {
	return ComponentRawTail
}

func (c *RawTailComponent) Table() string {
	return "pcap_raw_tail"
}

func (c *RawTailComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *RawTailComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *RawTailComponent) Order() uint {
	return OrderTail
}

func (c *RawTailComponent) Index() uint16 {
	return 0
}

func (c *RawTailComponent) SetIndex(_ uint16) {}

func (c *RawTailComponent) HeaderLen() int {
	return 0
}

func (c *RawTailComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
}

func (c *RawTailComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("raw tail component missing")
	}
	if ctx.Nucleus.TailOffset > 0 && int(ctx.Nucleus.TailOffset) != ctx.Offset {
		return fmt.Errorf("tail_offset mismatch: %d != %d", ctx.Nucleus.TailOffset, ctx.Offset)
	}
	ctx.Layers = append(ctx.Layers, gopacket.Payload(c.Bytes))
	return nil
}

func RawTailSchema(table string) string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s
(
  capture_id UUID,
  packet_id UInt64,

  tail_offset UInt16,
  bytes String CODEC(ZSTD)
)
ENGINE = MergeTree
ORDER BY (capture_id, packet_id)`, table)
}
