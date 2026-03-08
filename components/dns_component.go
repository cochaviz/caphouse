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

//go:embed dns_schema.sql
var dnsSchemaSQL string

// DNSComponent stores parsed DNS header fields and questions.
// Questions are stored as parallel arrays (one element per question).
// dns_raw holds the full wire bytes for lossless reconstruction.
type DNSComponent struct {
	CaptureID    uuid.UUID `ch:"capture_id"`
	PacketID     uint64    `ch:"packet_id"`
	CodecVersion uint16    `ch:"codec_version"`

	TransactionID uint16 `ch:"transaction_id"`
	QR            uint8  `ch:"qr"`   // 0=query 1=response
	Opcode        uint8  `ch:"opcode"`
	RCode         uint8  `ch:"rcode"`
	Flags         uint8  `ch:"flags"` // AA|TC|RD|RA packed

	ANCount uint16 `ch:"an_count"`
	NSCount uint16 `ch:"ns_count"`
	ARCount uint16 `ch:"ar_count"`

	QuestionsName  []string `ch:"questions_name"`
	QuestionsType  []uint16 `ch:"questions_type"`
	QuestionsClass []uint16 `ch:"questions_class"`

	DNSRaw []byte `ch:"dns_raw"`
}

func (c *DNSComponent) Kind() uint           { return ComponentDNS }
func (c *DNSComponent) Table() string        { return "pcap_dns" }
func (c *DNSComponent) Order() uint          { return OrderL7Base }
func (c *DNSComponent) Index() uint16        { return 0 }
func (c *DNSComponent) SetIndex(_ uint16)    {}
func (c *DNSComponent) HeaderLen() int       { return len(c.DNSRaw) }
func (c *DNSComponent) FetchOrderBy() string { return "packet_id" }

func (c *DNSComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *DNSComponent) ClickhouseValues() ([]any, error) {
	return []any{
		c.CaptureID, c.PacketID, c.CodecVersion,
		c.TransactionID, c.QR, c.Opcode, c.RCode, c.Flags,
		c.ANCount, c.NSCount, c.ARCount,
		c.QuestionsName, c.QuestionsType, c.QuestionsClass,
		string(c.DNSRaw),
	}, nil
}

func (c *DNSComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
}

func (c *DNSComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("dns component missing")
	}
	ctx.Layers = append(ctx.Layers, gopacket.Payload(c.DNSRaw))
	ctx.Offset += len(c.DNSRaw)
	return nil
}

func (c *DNSComponent) ScanColumns() []string {
	return []string{
		"packet_id",
		"transaction_id", "qr", "opcode", "rcode", "flags",
		"an_count", "ns_count", "ar_count",
		"questions_name", "questions_type", "questions_class",
		"dns_raw",
	}
}

func (c *DNSComponent) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	var raw string
	c.CaptureID = captureID
	err := rows.Scan(
		&c.PacketID,
		&c.TransactionID, &c.QR, &c.Opcode, &c.RCode, &c.Flags,
		&c.ANCount, &c.NSCount, &c.ARCount,
		&c.QuestionsName, &c.QuestionsType, &c.QuestionsClass,
		&raw,
	)
	c.DNSRaw = []byte(raw)
	return c.PacketID, err
}

func (c *DNSComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	dns, ok := layer.(*layers.DNS)
	if !ok {
		return nil, errors.New("unsupported dns layer")
	}
	contents := dns.LayerContents()
	if len(contents) < 12 {
		return nil, ErrShortFrame
	}

	var qr uint8
	if dns.QR {
		qr = 1
	}

	var flags uint8
	if dns.AA {
		flags |= 0x08
	}
	if dns.TC {
		flags |= 0x04
	}
	if dns.RD {
		flags |= 0x02
	}
	if dns.RA {
		flags |= 0x01
	}

	names := make([]string, len(dns.Questions))
	types := make([]uint16, len(dns.Questions))
	classes := make([]uint16, len(dns.Questions))
	for i, q := range dns.Questions {
		names[i] = string(q.Name)
		types[i] = uint16(q.Type)
		classes[i] = uint16(q.Class)
	}

	return []Component{&DNSComponent{
		CodecVersion:   CodecVersionV1,
		TransactionID:  dns.ID,
		QR:             qr,
		Opcode:         uint8(dns.OpCode),
		RCode:          uint8(dns.ResponseCode),
		Flags:          flags,
		ANCount:        dns.ANCount,
		NSCount:        dns.NSCount,
		ARCount:        dns.ARCount,
		QuestionsName:  names,
		QuestionsType:  types,
		QuestionsClass: classes,
		DNSRaw:         copyBytes(contents),
	}}, nil
}

func DNSSchema(table string) string {
	return applySchema(dnsSchemaSQL, table)
}

func DNSIndexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_questions_name (questions_name) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_rcode (rcode) TYPE set(256) GRANULARITY 4", table),
	}
}
