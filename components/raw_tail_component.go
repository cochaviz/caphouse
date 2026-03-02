package components

import (
	_ "embed"
	"errors"
	"fmt"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/uuid"
)

//go:embed raw_tail_schema.sql
var rawTailSchemaSQL string

// RawTailComponent stores bytes from tail_offset to the end of the frame.
type RawTailComponent struct {
	CaptureID  uuid.UUID `ch:"capture_id"`
	PacketID   uint64    `ch:"packet_id"`
	TailOffset uint16    `ch:"tail_offset"`
	Bytes      []byte    `ch:"bytes"`
}

func (c *RawTailComponent) Kind() uint           { return ComponentRawTail }
func (c *RawTailComponent) Table() string        { return "pcap_raw_tail" }
func (c *RawTailComponent) Order() uint          { return OrderTail }
func (c *RawTailComponent) Index() uint16        { return 0 }
func (c *RawTailComponent) SetIndex(_ uint16)    {}
func (c *RawTailComponent) HeaderLen() int       { return 0 }
func (c *RawTailComponent) FetchFINAL() bool     { return false }
func (c *RawTailComponent) FetchOrderBy() string { return "packet_id" }

func (c *RawTailComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *RawTailComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
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

func (c *RawTailComponent) ScanColumns() []string {
	return []string{"packet_id", "tail_offset", "bytes"}
}

func (c *RawTailComponent) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	var raw string
	c.CaptureID = captureID
	err := rows.Scan(&c.PacketID, &c.TailOffset, &raw)
	c.Bytes = []byte(raw)
	return c.PacketID, err
}

// EncodeRawTail encodes the tail section of a packet frame into a RawTailComponent.
func EncodeRawTail(nucleus *PacketNucleus, frame []byte, tailOffset int) (*RawTailComponent, error) {
	if nucleus == nil {
		return nil, errors.New("missing nucleus")
	}
	if tailOffset < 0 || tailOffset > len(frame) || tailOffset > maxTailOffset {
		return nil, ErrTailOffset
	}
	nucleus.TailOffset = uint16(tailOffset)
	return &RawTailComponent{
		CaptureID:  nucleus.CaptureID,
		PacketID:   nucleus.PacketID,
		TailOffset: uint16(tailOffset),
		Bytes:      copyBytes(frame[tailOffset:]),
	}, nil
}

const maxTailOffset = 1<<16 - 1

var ErrTailOffset = errors.New("tail offset out of range")

func RawTailSchema(table string) string {
	return applySchema(rawTailSchemaSQL, table)
}
