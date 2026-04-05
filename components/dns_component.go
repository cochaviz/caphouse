package components

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed dns_schema.sql
var dnsSchemaSQL string

// DNSComponent stores parsed DNS header fields, questions, and all answer/authority/additional
// resource records as flat parallel arrays. Reconstruction uses a custom DNS wire encoder
// so no raw frame bytes need to be stored. Reconstructed packets are semantically identical
// to the originals but will not use DNS name compression (RFC 1035 §4.1.4).
type DNSComponent struct {
	SessionID    uint64 `ch:"session_id"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`
	LayerIndex   uint16 `ch:"layer_index"`
	RawLen       uint16 `ch:"raw_len"`

	TransactionID uint16 `ch:"transaction_id"`
	QR            uint8  `ch:"qr"` // 0=query 1=response
	Opcode        uint8  `ch:"opcode"`
	RCode         uint8  `ch:"rcode"`
	Flags         uint8  `ch:"flags"` // Z<<4 | AA<<3 | TC<<2 | RD<<1 | RA

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

const (
	dnsFlagRA uint8 = 0x01
	dnsFlagRD uint8 = 0x02
	dnsFlagTC uint8 = 0x04
	dnsFlagAA uint8 = 0x08

	dnsFlagZMask  uint8 = 0x70
	dnsFlagZShift       = 4
)

func (c *DNSComponent) Kind() uint           { return ComponentDNS }
func (c *DNSComponent) Name() string         { return "dns" }
func (c *DNSComponent) Order() uint          { return OrderL7Base }
func (c *DNSComponent) Index() uint16        { return c.LayerIndex }
func (c *DNSComponent) SetIndex(i uint16)    { c.LayerIndex = i }
func (c *DNSComponent) LayerSize() int       { return int(c.RawLen) }
func (c *DNSComponent) FetchOrderBy() string { return "packet_id" }

func (c *DNSComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *DNSComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *DNSComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.PacketID = nucleus.PacketID
}

func (c *DNSComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("dns component missing")
	}
	wire := c.buildDNSWire()
	if len(wire) > int(c.RawLen) {
		// Original used name compression; rebuild with compression so the wire
		// is semantically equivalent and within the expected size.
		wire = c.buildCompressedDNSWire()
	}
	ctx.Layers = append(ctx.Layers, gopacket.Payload(wire))
	ctx.Offset += c.LayerSize()
	return nil
}

func (c *DNSComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
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

	flags := (dns.Z & 0x07) << dnsFlagZShift
	if dns.AA {
		flags |= dnsFlagAA
	}
	if dns.TC {
		flags |= dnsFlagTC
	}
	if dns.RD {
		flags |= dnsFlagRD
	}
	if dns.RA {
		flags |= dnsFlagRA
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

	comp := &DNSComponent{
		CodecVersion:  CodecVersionV1,
		RawLen:        uint16(len(dns.LayerContents())),
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
	}
	return []Component{comp}, nil
}

func (c *DNSComponent) Schema(table string) string { return applySchema(dnsSchemaSQL, table) }

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
	if c.Flags&dnsFlagAA != 0 {
		dnsFlags |= 0x0400 // AA
	}
	if c.Flags&dnsFlagTC != 0 {
		dnsFlags |= 0x0200 // TC
	}
	if c.Flags&dnsFlagRD != 0 {
		dnsFlags |= 0x0100 // RD
	}
	if c.Flags&dnsFlagRA != 0 {
		dnsFlags |= 0x0080 // RA
	}
	dnsFlags |= uint16((c.Flags&dnsFlagZMask)>>dnsFlagZShift) << 4
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

// buildCompressedDNSWire encodes the DNS message using name compression (RFC 1035 §4.1.4).
// A map tracks the byte offset of every name suffix written so far; when a suffix is seen
// again a 2-byte pointer (0xC000 | offset) is emitted instead of repeating the labels.
func (c *DNSComponent) buildCompressedDNSWire() []byte {
	buf := make([]byte, 0, int(c.RawLen))
	offsets := make(map[string]uint16) // suffix → byte offset in buf

	// header (identical to buildDNSWire)
	var dnsFlags uint16
	if c.QR == 1 {
		dnsFlags |= 0x8000
	}
	dnsFlags |= uint16(c.Opcode&0x0f) << 11
	if c.Flags&dnsFlagAA != 0 {
		dnsFlags |= 0x0400
	}
	if c.Flags&dnsFlagTC != 0 {
		dnsFlags |= 0x0200
	}
	if c.Flags&dnsFlagRD != 0 {
		dnsFlags |= 0x0100
	}
	if c.Flags&dnsFlagRA != 0 {
		dnsFlags |= 0x0080
	}
	dnsFlags |= uint16((c.Flags&dnsFlagZMask)>>dnsFlagZShift) << 4
	dnsFlags |= uint16(c.RCode & 0x0f)

	buf = binary.BigEndian.AppendUint16(buf, c.TransactionID)
	buf = binary.BigEndian.AppendUint16(buf, dnsFlags)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.QuestionsName)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.AnswersName)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.AuthorityName)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.AdditionalName)))

	for i, name := range c.QuestionsName {
		buf = appendCompressedName(buf, name, offsets)
		buf = binary.BigEndian.AppendUint16(buf, c.QuestionsType[i])
		buf = binary.BigEndian.AppendUint16(buf, c.QuestionsClass[i])
	}
	for i, name := range c.AnswersName {
		buf = appendCompressedRR(buf, name, c.AnswersType[i], c.AnswersClass[i], c.AnswersTTL[i], c.AnswersRdata[i], offsets)
	}
	for i, name := range c.AuthorityName {
		buf = appendCompressedRR(buf, name, c.AuthorityType[i], c.AuthorityClass[i], c.AuthorityTTL[i], c.AuthorityRdata[i], offsets)
	}
	for i, name := range c.AdditionalName {
		buf = appendCompressedRR(buf, name, c.AdditionalType[i], c.AdditionalClass[i], c.AdditionalTTL[i], c.AdditionalRdata[i], offsets)
	}
	return buf
}

// appendCompressedName writes a DNS name into buf using compression pointers where possible.
// offsets maps each name suffix (dot-separated, no trailing dot) to its byte offset in buf.
func appendCompressedName(buf []byte, name string, offsets map[string]uint16) []byte {
	if name == "" || name == "." {
		return append(buf, 0x00)
	}
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	for i, label := range labels {
		suffix := strings.Join(labels[i:], ".")
		if off, ok := offsets[suffix]; ok {
			// Emit compression pointer and stop.
			return append(buf, byte(0xC0|(off>>8)), byte(off))
		}
		// Record this suffix at its current position (only offsets ≤ 0x3FFF are valid pointers).
		if len(buf) <= 0x3FFF {
			offsets[suffix] = uint16(len(buf))
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0x00) // root label
}

// appendCompressedRR appends one resource record using name compression.
func appendCompressedRR(buf []byte, name string, typ, class uint16, ttl uint32, rdata string, offsets map[string]uint16) []byte {
	buf = appendCompressedName(buf, name, offsets)
	buf = binary.BigEndian.AppendUint16(buf, typ)
	buf = binary.BigEndian.AppendUint16(buf, class)
	buf = binary.BigEndian.AppendUint32(buf, ttl)
	rd := []byte(rdata)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(rd)))
	buf = append(buf, rd...)
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
