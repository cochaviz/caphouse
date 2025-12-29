package components

import (
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/uuid"
)

// LinuxSLLComponent stores raw SLL header bytes.
type LinuxSLLComponent struct {
	CaptureID    uuid.UUID
	PacketID     uint64
	CodecVersion uint16
	L2Len        uint16
	L2HdrRaw     []byte
}

func (c *LinuxSLLComponent) Kind() uint {
	return ComponentLinuxSLL
}

func (c *LinuxSLLComponent) Table() string {
	return "pcap_linuxsll"
}

func (c *LinuxSLLComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *LinuxSLLComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *LinuxSLLComponent) Order() uint {
	return OrderL2Base
}

func (c *LinuxSLLComponent) Index() uint16 {
	return 0
}

func (c *LinuxSLLComponent) SetIndex(_ uint16) {}

func (c *LinuxSLLComponent) HeaderLen() int {
	return len(c.L2HdrRaw)
}

func (c *LinuxSLLComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
}

func (c *LinuxSLLComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("linux sll component missing")
	}
	if c.L2Len != 0 && int(c.L2Len) != len(c.L2HdrRaw) {
		return fmt.Errorf("linux sll len mismatch: %d != %d", c.L2Len, len(c.L2HdrRaw))
	}
	if len(c.L2HdrRaw) == 0 {
		return errors.New("linux sll header empty")
	}
	ctx.Layers = append(ctx.Layers, gopacket.Payload(c.L2HdrRaw))
	ctx.Offset += len(c.L2HdrRaw)
	return nil
}

func LinuxSLLSchema(table string) string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s
(
  capture_id UUID,
  packet_id UInt64,

  codec_version UInt16,

  l2_len UInt16,
  l2_hdr_raw String CODEC(ZSTD)
)
ENGINE = MergeTree
ORDER BY (capture_id, packet_id)`, table)
}
