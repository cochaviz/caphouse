package components

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed tcp_schema.sql
var tcpSchemaSQL string

// TCP flag bit positions within the stored UInt16.
// Bits 0–7 map to byte 13 of the TCP header (CWR…FIN).
// Bit 8 is the NS flag from the low bit of byte 12.
const (
	TCPFlagFIN uint16 = 1 << iota
	TCPFlagSYN
	TCPFlagRST
	TCPFlagPSH
	TCPFlagACK
	TCPFlagURG
	TCPFlagECE
	TCPFlagCWR
	TCPFlagNS
)

// TCPComponent stores parsed TCP header fields.
// options_raw holds raw bytes 20..data_offset*4 from the original header,
// enabling bit-perfect frame reconstruction without checksum recomputation.
type TCPComponent struct {
	SessionID    uint64    `ch:"session_id"`
	Ts           int64     `ch:"ts"`
	PacketID  uint32 `ch:"packet_id"`
	CodecVersion uint16    `ch:"codec_version"`

	SrcPort    uint16 `ch:"src"`
	DstPort    uint16 `ch:"dst"`
	Seq        uint32 `ch:"seq"`
	Ack        uint32 `ch:"ack"`
	DataOffset uint8  `ch:"data_offset"`
	Flags      uint16 `ch:"flags"`
	Window     uint16 `ch:"window"`
	Checksum   uint16 `ch:"checksum"`
	Urgent     uint16 `ch:"urgent"`
	OptionsRaw []byte `ch:"options_raw"`
}

func (c *TCPComponent) Kind() uint           { return ComponentTCP }
func (c *TCPComponent) Table() string        { return "pcap_tcp" }
func (c *TCPComponent) Order() uint          { return OrderL4Base }
func (c *TCPComponent) Index() uint16        { return 0 }
func (c *TCPComponent) SetIndex(_ uint16)    {}
func (c *TCPComponent) HeaderLen() int       { return int(c.DataOffset) * 4 }
func (c *TCPComponent) FetchOrderBy() string { return "packet_id" }

func (c *TCPComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *TCPComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *TCPComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.Ts = nucleus.Timestamp.UnixNano()
	c.PacketID = nucleus.PacketID
}

func (c *TCPComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("tcp component missing")
	}
	headerLen := int(c.DataOffset) * 4
	if headerLen < 20 {
		return fmt.Errorf("tcp: invalid data_offset %d", c.DataOffset)
	}
	hdr := make([]byte, headerLen)
	binary.BigEndian.PutUint16(hdr[0:2], c.SrcPort)
	binary.BigEndian.PutUint16(hdr[2:4], c.DstPort)
	binary.BigEndian.PutUint32(hdr[4:8], c.Seq)
	binary.BigEndian.PutUint32(hdr[8:12], c.Ack)
	// Byte 12: high nibble = data_offset, low bit = NS flag
	hdr[12] = (c.DataOffset << 4) | uint8((c.Flags&TCPFlagNS)>>8)
	// Byte 13: CWR..FIN flags
	hdr[13] = uint8(c.Flags & 0xFF)
	binary.BigEndian.PutUint16(hdr[14:16], c.Window)
	binary.BigEndian.PutUint16(hdr[16:18], c.Checksum)
	binary.BigEndian.PutUint16(hdr[18:20], c.Urgent)
	copy(hdr[20:], c.OptionsRaw)
	ctx.Layers = append(ctx.Layers, gopacket.Payload(hdr))
	ctx.Offset += headerLen
	return nil
}

func (c *TCPComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *TCPComponent) ScanRow(sessionID uint64, rows chdriver.Rows) (uint32, error) {
	var optRaw string
	c.SessionID = sessionID
	err := rows.Scan(
		&c.PacketID,
		&c.SrcPort, &c.DstPort,
		&c.Seq, &c.Ack,
		&c.DataOffset, &c.Flags, &c.Window, &c.Checksum, &c.Urgent,
		&optRaw,
	)
	c.OptionsRaw = []byte(optRaw)
	return c.PacketID, err
}

func (c *TCPComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	tcp, ok := layer.(*layers.TCP)
	if !ok {
		return nil, errors.New("unsupported tcp layer")
	}
	contents := tcp.LayerContents()
	if len(contents) < 20 {
		return nil, ErrShortFrame
	}
	headerLen := int(tcp.DataOffset) * 4
	if headerLen < 20 || headerLen > len(contents) {
		return nil, fmt.Errorf("tcp: invalid data_offset %d", tcp.DataOffset)
	}

	var flags uint16
	if tcp.FIN {
		flags |= TCPFlagFIN
	}
	if tcp.SYN {
		flags |= TCPFlagSYN
	}
	if tcp.RST {
		flags |= TCPFlagRST
	}
	if tcp.PSH {
		flags |= TCPFlagPSH
	}
	if tcp.ACK {
		flags |= TCPFlagACK
	}
	if tcp.URG {
		flags |= TCPFlagURG
	}
	if tcp.ECE {
		flags |= TCPFlagECE
	}
	if tcp.CWR {
		flags |= TCPFlagCWR
	}
	if tcp.NS {
		flags |= TCPFlagNS
	}

	var optionsRaw []byte
	if headerLen > 20 {
		optionsRaw = copyBytes(contents[20:headerLen])
	}

	return []Component{&TCPComponent{
		CodecVersion: CodecVersionV1,
		SrcPort:      uint16(tcp.SrcPort),
		DstPort:      uint16(tcp.DstPort),
		Seq:          tcp.Seq,
		Ack:          tcp.Ack,
		DataOffset:   tcp.DataOffset,
		Flags:        flags,
		Window:       tcp.Window,
		Checksum:     tcp.Checksum,
		Urgent:       tcp.Urgent,
		OptionsRaw:   optionsRaw,
	}}, nil
}

func (c *TCPComponent) Schema(table string) string { return applySchema(tcpSchemaSQL, table) }
func (c *TCPComponent) Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_dst (dst) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_flags (flags) TYPE set(512) GRANULARITY 4", table),
	}
}
