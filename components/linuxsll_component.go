package components

import (
	_ "embed"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed linuxsll_schema.sql
var linuxsllSchemaSQL string

// LinuxSLLComponent stores raw SLL header bytes.
type LinuxSLLComponent struct {
	SessionID    uint64 `ch:"session_id"`
	Ts           int64  `ch:"ts"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`
	L2Len        uint16 `ch:"l2_len"`
	L2HdrRaw     []byte `ch:"l2_hdr_raw"`
}

func (c *LinuxSLLComponent) Kind() uint   { return ComponentLinuxSLL }
func (c *LinuxSLLComponent) Name() string { return "linuxsll" }
func (c *LinuxSLLComponent) Order() uint          { return OrderL2Base }
func (c *LinuxSLLComponent) Index() uint16        { return 0 }
func (c *LinuxSLLComponent) SetIndex(_ uint16)    {}
func (c *LinuxSLLComponent) HeaderLen() int       { return len(c.L2HdrRaw) }
func (c *LinuxSLLComponent) FetchOrderBy() string { return "packet_id" }

func (c *LinuxSLLComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *LinuxSLLComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *LinuxSLLComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.Ts = nucleus.Timestamp.UnixNano()
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

func (c *LinuxSLLComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *LinuxSLLComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	sll, ok := layer.(*layers.LinuxSLL)
	if !ok {
		return nil, errors.New("unsupported linux sll layer")
	}
	contents := sll.LayerContents()
	if len(contents) == 0 {
		return nil, ErrShortFrame
	}
	return []Component{&LinuxSLLComponent{
		CodecVersion: CodecVersionV1,
		L2Len:        uint16(len(contents)),
		L2HdrRaw:     copyBytes(contents),
	}}, nil
}

func (c *LinuxSLLComponent) Schema(table string) string { return applySchema(linuxsllSchemaSQL, table) }
func (c *LinuxSLLComponent) Indexes(_ string) []string  { return nil }
