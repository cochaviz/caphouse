package components

import (
	_ "embed"
	"errors"
	"fmt"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

//go:embed linuxsll_schema.sql
var linuxsllSchemaSQL string

// LinuxSLLComponent stores raw SLL header bytes.
type LinuxSLLComponent struct {
	CaptureID    uuid.UUID `ch:"capture_id"`
	PacketID     uint64    `ch:"packet_id"`
	CodecVersion uint16    `ch:"codec_version"`
	L2Len        uint16    `ch:"l2_len"`
	L2HdrRaw     []byte    `ch:"l2_hdr_raw"`
}

func (c *LinuxSLLComponent) Kind() uint           { return ComponentLinuxSLL }
func (c *LinuxSLLComponent) Table() string        { return "pcap_linuxsll" }
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

func (c *LinuxSLLComponent) ScanColumns() []string {
	return []string{"packet_id", "l2_len", "l2_hdr_raw"}
}

func (c *LinuxSLLComponent) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	var raw string
	c.CaptureID = captureID
	err := rows.Scan(&c.PacketID, &c.L2Len, &raw)
	c.L2HdrRaw = []byte(raw)
	return c.PacketID, err
}

func (c *LinuxSLLComponent) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
	sll, ok := layer.(*layers.LinuxSLL)
	if !ok {
		return nil, errors.New("unsupported linux sll layer")
	}
	contents := sll.LayerContents()
	if len(contents) == 0 {
		return nil, ErrShortFrame
	}
	return []ClickhouseMappedDecoder{&LinuxSLLComponent{
		CodecVersion: CodecVersionV1,
		L2Len:        uint16(len(contents)),
		L2HdrRaw:     copyBytes(contents),
	}}, nil
}

func LinuxSLLSchema(table string) string {
	return applySchema(linuxsllSchemaSQL, table)
}
