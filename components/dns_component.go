package components

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

//go:embed dns_schema.sql
var dnsSchemaSQL string

// DNSComponent stores parsed DNS header fields, questions, and all answer/authority/additional
// resource records as flat parallel arrays. Reconstruction uses a custom DNS wire encoder
// so no raw frame bytes need to be stored. Reconstructed packets are semantically identical
// to the originals but will not use DNS name compression (RFC 1035 §4.1.4).
type DNSComponent struct {
	CaptureID    uuid.UUID `ch:"capture_id"`
	PacketID     uint64    `ch:"packet_id"`
	CodecVersion uint16    `ch:"codec_version"`

	TransactionID uint16 `ch:"transaction_id"`
	QR            uint8  `ch:"qr"`     // 0=query 1=response
	Opcode        uint8  `ch:"opcode"`
	RCode         uint8  `ch:"rcode"`
	Flags         uint8  `ch:"flags"` // AA|TC|RD|RA packed

	ANCount uint16 `ch:"an_count"`
	NSCount uint16 `ch:"ns_count"`
	ARCount uint16 `ch:"ar_count"`

	QuestionsName  []string `ch:"questions_name"`
	QuestionsType  []uint16 `ch:"questions_type"`
	QuestionsClass []uint16 `ch:"questions_class"`

	// Answer section — one entry per RR.
	AnswersName  []string `ch:"answers_name"`
	AnswersType  []uint16 `ch:"answers_type"`
	AnswersClass []uint16 `ch:"answers_class"`
	AnswersTTL   []uint32 `ch:"answers_ttl"`
	AnswersRdata []string `ch:"answers_rdata"` // raw RDATA bytes stored as string
	AnswersIP    []string `ch:"answers_ip"`    // dotted IP for A/AAAA, "" otherwise

	// Authority section.
	AuthorityName  []string `ch:"authority_name"`
	AuthorityType  []uint16 `ch:"authority_type"`
	AuthorityClass []uint16 `ch:"authority_class"`
	AuthorityTTL   []uint32 `ch:"authority_ttl"`
	AuthorityRdata []string `ch:"authority_rdata"`

	// Additional section.
	AdditionalName  []string `ch:"additional_name"`
	AdditionalType  []uint16 `ch:"additional_type"`
	AdditionalClass []uint16 `ch:"additional_class"`
	AdditionalTTL   []uint32 `ch:"additional_ttl"`
	AdditionalRdata []string `ch:"additional_rdata"`
}

func (c *DNSComponent) Kind() uint           { return ComponentDNS }
func (c *DNSComponent) Table() string        { return "pcap_dns" }
func (c *DNSComponent) Order() uint          { return OrderL7Base }
func (c *DNSComponent) Index() uint16        { return 0 }
func (c *DNSComponent) SetIndex(_ uint16)    {}
func (c *DNSComponent) HeaderLen() int       { return len(c.buildDNSWire()) }
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
		c.AnswersName, c.AnswersType, c.AnswersClass, c.AnswersTTL, c.AnswersRdata, c.AnswersIP,
		c.AuthorityName, c.AuthorityType, c.AuthorityClass, c.AuthorityTTL, c.AuthorityRdata,
		c.AdditionalName, c.AdditionalType, c.AdditionalClass, c.AdditionalTTL, c.AdditionalRdata,
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
	wire := c.buildDNSWire()
	ctx.Layers = append(ctx.Layers, gopacket.Payload(wire))
	ctx.Offset += len(wire)
	return nil
}

func (c *DNSComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *DNSComponent) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	c.CaptureID = captureID
	err := rows.Scan(
		&c.PacketID,
		&c.TransactionID, &c.QR, &c.Opcode, &c.RCode, &c.Flags,
		&c.ANCount, &c.NSCount, &c.ARCount,
		&c.QuestionsName, &c.QuestionsType, &c.QuestionsClass,
		&c.AnswersName, &c.AnswersType, &c.AnswersClass, &c.AnswersTTL, &c.AnswersRdata, &c.AnswersIP,
		&c.AuthorityName, &c.AuthorityType, &c.AuthorityClass, &c.AuthorityTTL, &c.AuthorityRdata,
		&c.AdditionalName, &c.AdditionalType, &c.AdditionalClass, &c.AdditionalTTL, &c.AdditionalRdata,
	)
	return c.PacketID, err
}

func (c *DNSComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	dns, ok := layer.(*layers.DNS)
	if !ok {
		return nil, errors.New("unsupported dns layer")
	}
	if len(dns.LayerContents()) < 12 {
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

	aN, aT, aC, aTTL, aR, aIP := encodeRRSection(dns.Answers)
	auN, auT, auC, auTTL, auR, _ := encodeRRSection(dns.Authorities)
	adN, adT, adC, adTTL, adR, _ := encodeRRSection(dns.Additionals)

	return []Component{&DNSComponent{
		CodecVersion:  CodecVersionV1,
		TransactionID: dns.ID,
		QR:            qr,
		Opcode:        uint8(dns.OpCode),
		RCode:         uint8(dns.ResponseCode),
		Flags:         flags,
		ANCount:       dns.ANCount,
		NSCount:       dns.NSCount,
		ARCount:       dns.ARCount,

		QuestionsName:  names,
		QuestionsType:  types,
		QuestionsClass: classes,

		AnswersName:  aN,
		AnswersType:  aT,
		AnswersClass: aC,
		AnswersTTL:   aTTL,
		AnswersRdata: aR,
		AnswersIP:    aIP,

		AuthorityName:  auN,
		AuthorityType:  auT,
		AuthorityClass: auC,
		AuthorityTTL:   auTTL,
		AuthorityRdata: auR,

		AdditionalName:  adN,
		AdditionalType:  adT,
		AdditionalClass: adC,
		AdditionalTTL:   adTTL,
		AdditionalRdata: adR,
	}}, nil
}

func (c *DNSComponent) Schema(table string) string { return applySchema(dnsSchemaSQL, table) }
func (c *DNSComponent) Indexes(table string) []string {
	return []string{
		// Drop the old invalid bloom filter on the nested-array column (if it exists).
		fmt.Sprintf("ALTER TABLE %s DROP INDEX IF EXISTS idx_answers_ip", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_questions_name (questions_name) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_rcode (rcode) TYPE set(256) GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_answers_name (answers_name) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_answers_ip (answers_ip) TYPE bloom_filter GRANULARITY 4", table),
	}
}

// encodeRRSection converts a slice of DNS resource records into parallel arrays.
// The returned ip slice is populated only for A/AAAA records; other types get "".
func encodeRRSection(rrs []layers.DNSResourceRecord) (names []string, types, classes []uint16, ttls []uint32, rdatas, ips []string) {
	for _, rr := range rrs {
		names = append(names, string(rr.Name))
		types = append(types, uint16(rr.Type))
		classes = append(classes, uint16(rr.Class))
		ttls = append(ttls, rr.TTL)
		rdatas = append(rdatas, string(rr.Data))
		ip := ""
		if rr.IP != nil {
			ip = rr.IP.String()
		}
		ips = append(ips, ip)
	}
	return
}

// buildDNSWire encodes the DNS message to wire format without name compression.
func (c *DNSComponent) buildDNSWire() []byte {
	buf := make([]byte, 0, 512)

	var dnsFlags uint16
	if c.QR == 1 {
		dnsFlags |= 0x8000
	}
	dnsFlags |= uint16(c.Opcode&0x0f) << 11
	if c.Flags&0x08 != 0 {
		dnsFlags |= 0x0400 // AA
	}
	if c.Flags&0x04 != 0 {
		dnsFlags |= 0x0200 // TC
	}
	if c.Flags&0x02 != 0 {
		dnsFlags |= 0x0100 // RD
	}
	if c.Flags&0x01 != 0 {
		dnsFlags |= 0x0080 // RA
	}
	dnsFlags |= uint16(c.RCode & 0x0f)

	buf = binary.BigEndian.AppendUint16(buf, c.TransactionID)
	buf = binary.BigEndian.AppendUint16(buf, dnsFlags)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.QuestionsName)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.AnswersName)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.AuthorityName)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.AdditionalName)))

	for i, name := range c.QuestionsName {
		buf = append(buf, encodeDNSName(name)...)
		buf = binary.BigEndian.AppendUint16(buf, c.QuestionsType[i])
		buf = binary.BigEndian.AppendUint16(buf, c.QuestionsClass[i])
	}
	for i, name := range c.AnswersName {
		buf = appendDNSRR(buf, name, c.AnswersType[i], c.AnswersClass[i], c.AnswersTTL[i], c.AnswersRdata[i])
	}
	for i, name := range c.AuthorityName {
		buf = appendDNSRR(buf, name, c.AuthorityType[i], c.AuthorityClass[i], c.AuthorityTTL[i], c.AuthorityRdata[i])
	}
	for i, name := range c.AdditionalName {
		buf = appendDNSRR(buf, name, c.AdditionalType[i], c.AdditionalClass[i], c.AdditionalTTL[i], c.AdditionalRdata[i])
	}
	return buf
}

// encodeDNSName encodes a DNS name as uncompressed wire-format labels.
func encodeDNSName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0x00}
	}
	name = strings.TrimSuffix(name, ".")
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00)
	return buf
}

// appendDNSRR appends one resource record in wire format to buf.
func appendDNSRR(buf []byte, name string, typ, class uint16, ttl uint32, rdata string) []byte {
	buf = append(buf, encodeDNSName(name)...)
	buf = binary.BigEndian.AppendUint16(buf, typ)
	buf = binary.BigEndian.AppendUint16(buf, class)
	buf = binary.BigEndian.AppendUint32(buf, ttl)
	rd := []byte(rdata)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(rd)))
	buf = append(buf, rd...)
	return buf
}
