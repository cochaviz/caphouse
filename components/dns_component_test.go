package components

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// dnsCompressedResponseWire returns a hand-crafted DNS response wire that uses name
// compression pointers (RFC 1035 §4.1.4).  The message contains one question and two
// A-record answers whose owner names are compressed back to the question name:
//
//	Question: example.com  A IN
//	Answer 1: example.com  A IN TTL=300 1.2.3.4   (name = pointer to offset 12)
//	Answer 2: www.example.com A IN TTL=300 5.6.7.8 (name = \3www + pointer to offset 12)
//
// The total wire is 65 bytes; the uncompressed equivalent is 87 bytes.
func dnsCompressedResponseWire() []byte {
	return []byte{
		// Header
		0x12, 0x34, // ID
		0x85, 0x80, // flags: QR=1 AA=1 RD=1 RA=1
		0x00, 0x01, // QDCount = 1
		0x00, 0x02, // ANCount = 2
		0x00, 0x00, // NSCount = 0
		0x00, 0x00, // ARCount = 0
		// Question (offset 12): example.com A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		// Answer 1 (offset 29): name = ptr→12, A IN TTL=300 1.2.3.4
		0xC0, 0x0C, // compression pointer to offset 12 (example.com)
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x01, 0x2C, // TTL = 300
		0x00, 0x04, // RDLENGTH = 4
		0x01, 0x02, 0x03, 0x04, // 1.2.3.4
		// Answer 2 (offset 45): name = \3www ptr→12, A IN TTL=300 5.6.7.8
		0x03, 'w', 'w', 'w',
		0xC0, 0x0C, // pointer to offset 12 (example.com)
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x01, 0x2C, // TTL = 300
		0x00, 0x04, // RDLENGTH = 4
		0x05, 0x06, 0x07, 0x08, // 5.6.7.8
	} // total: 65 bytes
}

func parseDNSLayer(t *testing.T, data []byte) *layers.DNS {
	t.Helper()
	pkt := gopacket.NewPacket(data, layers.LayerTypeDNS, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeDNS)
	if l == nil {
		t.Fatalf("failed to parse dns layer")
	}
	return l.(*layers.DNS)
}

func buildDNSBytes(t *testing.T, dns *layers.DNS) []byte {
	t.Helper()
	return mustSerializeFixLengths(t, dns)
}

func TestDNSEncodeBasic(t *testing.T) {
	dns := &layers.DNS{
		ID:     0x1234,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		RD:     true,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
			{Name: []byte("www.example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		},
	}
	data := buildDNSBytes(t, dns)
	parsed := parseDNSLayer(t, data)

	enc := &DNSComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*DNSComponent)

	if got.TransactionID != 0x1234 {
		t.Errorf("TransactionID: got 0x%x want 0x1234", got.TransactionID)
	}
	if got.QR != 0 {
		t.Errorf("QR: got %d want 0 (query)", got.QR)
	}
	if got.Flags&0x02 == 0 {
		t.Error("RD flag not set in flags byte")
	}
	if len(got.QuestionsName) != 2 {
		t.Fatalf("QuestionsName length: got %d want 2", len(got.QuestionsName))
	}
	if got.QuestionsName[0] != "example.com" {
		t.Errorf("QuestionsName[0]: got %q want %q", got.QuestionsName[0], "example.com")
	}
	if got.QuestionsName[1] != "www.example.com" {
		t.Errorf("QuestionsName[1]: got %q want %q", got.QuestionsName[1], "www.example.com")
	}
	if got.QuestionsType[0] != uint16(layers.DNSTypeA) {
		t.Errorf("QuestionsType[0]: got %d", got.QuestionsType[0])
	}
	if got.QuestionsType[1] != uint16(layers.DNSTypeAAAA) {
		t.Errorf("QuestionsType[1]: got %d", got.QuestionsType[1])
	}
}

func TestDNSEncodeFlags(t *testing.T) {
	dns := &layers.DNS{
		ID: 0xabcd,
		QR: true, // response
		AA: true, // authoritative
		TC: true, // truncated
		RD: true, // recursion desired
		RA: true, // recursion available
		Z:  0x02,
	}
	data := buildDNSBytes(t, dns)
	parsed := parseDNSLayer(t, data)

	enc := &DNSComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got := comps[0].(*DNSComponent)

	if got.QR != 1 {
		t.Errorf("QR: got %d want 1 (response)", got.QR)
	}
	if got.Flags&dnsFlagAA == 0 {
		t.Error("AA flag not set")
	}
	if got.Flags&dnsFlagTC == 0 {
		t.Error("TC flag not set")
	}
	if got.Flags&dnsFlagRD == 0 {
		t.Error("RD flag not set")
	}
	if got.Flags&dnsFlagRA == 0 {
		t.Error("RA flag not set")
	}
	if (got.Flags&dnsFlagZMask)>>dnsFlagZShift != 0x02 {
		t.Errorf("Z bits in flags: got %d want 2", (got.Flags&dnsFlagZMask)>>dnsFlagZShift)
	}
}

func TestDNSEncodeWrongLayer(t *testing.T) {
	enc := &DNSComponent{}
	_, err := enc.Encode(&layers.UDP{})
	if err == nil {
		t.Fatal("expected error for wrong layer type")
	}
}

func TestDNSRoundTrip(t *testing.T) {
	dns := &layers.DNS{
		ID:     0x5678,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{Name: []byte("test.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}
	data := buildDNSBytes(t, dns)
	parsed := parseDNSLayer(t, data)

	enc := &DNSComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// DNS reconstructs from stored fields without name compression; for a simple query built
	// the same way, the output is byte-identical to the original.
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}

func TestDNSEncodeAnswers(t *testing.T) {
	ip := net.ParseIP("1.2.3.4").To4()
	dns := &layers.DNS{
		ID: 0xbeef,
		QR: true,
		AA: true,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
		Answers: []layers.DNSResourceRecord{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: ip},
		},
		Authorities: []layers.DNSResourceRecord{
			{Name: []byte("example.com"), Type: layers.DNSTypeNS, Class: layers.DNSClassIN, TTL: 3600, NS: []byte("ns1.example.com")},
		},
	}
	data := buildDNSBytes(t, dns)
	parsed := parseDNSLayer(t, data)

	enc := &DNSComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got := comps[0].(*DNSComponent)

	if len(got.AnswersName) != 1 {
		t.Fatalf("AnswersName length: got %d want 1", len(got.AnswersName))
	}
	if got.AnswersName[0] != "example.com" {
		t.Errorf("AnswersName[0]: got %q want %q", got.AnswersName[0], "example.com")
	}
	if got.AnswersType[0] != uint16(layers.DNSTypeA) {
		t.Errorf("AnswersType[0]: got %d", got.AnswersType[0])
	}
	if got.AnswersTTL[0] != 300 {
		t.Errorf("AnswersTTL[0]: got %d want 300", got.AnswersTTL[0])
	}
	if got.AnswersIP[0] != "1.2.3.4" {
		t.Errorf("AnswersIP[0]: got %q want %q", got.AnswersIP[0], "1.2.3.4")
	}
	if len(got.AuthorityName) != 1 {
		t.Fatalf("AuthorityName length: got %d want 1", len(got.AuthorityName))
	}
	if got.AuthorityType[0] != uint16(layers.DNSTypeNS) {
		t.Errorf("AuthorityType[0]: got %d", got.AuthorityType[0])
	}

	// Reconstruct and re-parse to verify semantic equivalence.
	ctx := &DecodeContext{}
	if err := comps[0].(LayerDecoder).Reconstruct(ctx); err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, ctx.Layers...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	reparsed := parseDNSLayer(t, buf.Bytes())
	if reparsed.ID != 0xbeef {
		t.Errorf("reparsed ID: got 0x%x want 0xbeef", reparsed.ID)
	}
	if len(reparsed.Answers) != 1 {
		t.Fatalf("reparsed Answers length: got %d want 1", len(reparsed.Answers))
	}
	if !reparsed.Answers[0].IP.Equal(ip) {
		t.Errorf("reparsed answer IP: got %v want %v", reparsed.Answers[0].IP, ip)
	}
	if len(reparsed.Authorities) != 1 {
		t.Fatalf("reparsed Authorities length: got %d want 1", len(reparsed.Authorities))
	}
}

// ---------------------------------------------------------------------------
// buildDNSWire tests
// ---------------------------------------------------------------------------

// TestBuildDNSWireParses verifies that buildDNSWire produces a wire that gopacket
// can parse back to the same header fields, questions, and answers.
func TestBuildDNSWireParses(t *testing.T) {
	comp := &DNSComponent{
		TransactionID:  0xABCD,
		QR:             1,
		Flags:          0x08 | 0x02, // AA + RD
		QuestionsName:  []string{"example.com"},
		QuestionsType:  []uint16{uint16(layers.DNSTypeA)},
		QuestionsClass: []uint16{uint16(layers.DNSClassIN)},
		AnswersName:    []string{"example.com"},
		AnswersType:    []uint16{uint16(layers.DNSTypeA)},
		AnswersClass:   []uint16{uint16(layers.DNSClassIN)},
		AnswersTTL:     []uint32{60},
		AnswersRdata:   []string{"\x0a\x00\x00\x01"},
		AnswersIP:      []string{"10.0.0.1"},
	}

	wire := comp.buildDNSWire()
	dns := parseDNSLayer(t, wire)

	if dns.ID != 0xABCD {
		t.Errorf("ID: got 0x%x want 0xABCD", dns.ID)
	}
	if !dns.QR {
		t.Error("QR: want response (true)")
	}
	if !dns.AA {
		t.Error("AA flag not set")
	}
	if !dns.RD {
		t.Error("RD flag not set")
	}
	if len(dns.Questions) != 1 || string(dns.Questions[0].Name) != "example.com" {
		t.Errorf("Questions: got %v", dns.Questions)
	}
	if len(dns.Answers) != 1 || string(dns.Answers[0].Name) != "example.com" {
		t.Errorf("Answers: got %v", dns.Answers)
	}
	if dns.Answers[0].TTL != 60 {
		t.Errorf("answer TTL: got %d want 60", dns.Answers[0].TTL)
	}
}

// TestBuildDNSWireNoCompression verifies that buildDNSWire does not emit compression
// pointers even when names repeat — every name is written as full uncompressed labels.
func TestBuildDNSWireNoCompression(t *testing.T) {
	comp := &DNSComponent{
		QuestionsName:  []string{"example.com"},
		QuestionsType:  []uint16{uint16(layers.DNSTypeA)},
		QuestionsClass: []uint16{uint16(layers.DNSClassIN)},
		AnswersName:    []string{"example.com", "example.com"},
		AnswersType:    []uint16{uint16(layers.DNSTypeA), uint16(layers.DNSTypeA)},
		AnswersClass:   []uint16{uint16(layers.DNSClassIN), uint16(layers.DNSClassIN)},
		AnswersTTL:     []uint32{300, 300},
		AnswersRdata:   []string{"\x01\x02\x03\x04", "\x05\x06\x07\x08"},
		AnswersIP:      []string{"1.2.3.4", "5.6.7.8"},
	}
	wire := comp.buildDNSWire()

	// No byte >= 0xC0 should appear outside the fixed 12-byte header; compression
	// pointers always have the top two bits set (0xC0–0xFF).
	for i, b := range wire[12:] {
		if b >= 0xC0 {
			t.Errorf("compression pointer byte 0x%02x at wire offset %d in uncompressed wire", b, i+12)
		}
	}
}

// ---------------------------------------------------------------------------
// buildCompressedDNSWire tests
// ---------------------------------------------------------------------------

// TestBuildCompressedDNSWireShorter verifies that for a response with repeated owner
// names, the compressed wire is strictly shorter than the uncompressed wire.
func TestBuildCompressedDNSWireShorter(t *testing.T) {
	comp := &DNSComponent{
		QuestionsName:  []string{"example.com"},
		QuestionsType:  []uint16{uint16(layers.DNSTypeA)},
		QuestionsClass: []uint16{uint16(layers.DNSClassIN)},
		AnswersName:    []string{"example.com", "example.com", "example.com"},
		AnswersType:    []uint16{uint16(layers.DNSTypeA), uint16(layers.DNSTypeA), uint16(layers.DNSTypeA)},
		AnswersClass:   []uint16{uint16(layers.DNSClassIN), uint16(layers.DNSClassIN), uint16(layers.DNSClassIN)},
		AnswersTTL:     []uint32{300, 300, 300},
		AnswersRdata:   []string{"\x01\x01\x01\x01", "\x02\x02\x02\x02", "\x03\x03\x03\x03"},
		AnswersIP:      []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
	}

	uncompressed := comp.buildDNSWire()
	compressed := comp.buildCompressedDNSWire()
	if len(compressed) >= len(uncompressed) {
		t.Errorf("expected compressed (%d) < uncompressed (%d)", len(compressed), len(uncompressed))
	}
}

// TestBuildCompressedDNSWireSemantics verifies that the compressed wire parses back
// to the same DNS content as the original structured fields.
func TestBuildCompressedDNSWireSemantics(t *testing.T) {
	comp := &DNSComponent{
		TransactionID:  0x1234,
		QR:             1,
		Flags:          0x08, // AA
		QuestionsName:  []string{"example.com"},
		QuestionsType:  []uint16{uint16(layers.DNSTypeA)},
		QuestionsClass: []uint16{uint16(layers.DNSClassIN)},
		AnswersName:    []string{"example.com", "www.example.com"},
		AnswersType:    []uint16{uint16(layers.DNSTypeA), uint16(layers.DNSTypeA)},
		AnswersClass:   []uint16{uint16(layers.DNSClassIN), uint16(layers.DNSClassIN)},
		AnswersTTL:     []uint32{300, 300},
		AnswersRdata:   []string{"\x01\x02\x03\x04", "\x05\x06\x07\x08"},
		AnswersIP:      []string{"1.2.3.4", "5.6.7.8"},
	}

	wire := comp.buildCompressedDNSWire()
	dns := parseDNSLayer(t, wire)

	if dns.ID != 0x1234 {
		t.Errorf("ID: got 0x%x want 0x1234", dns.ID)
	}
	if !dns.QR {
		t.Error("QR: want response")
	}
	if !dns.AA {
		t.Error("AA flag not set")
	}
	if len(dns.Questions) != 1 || string(dns.Questions[0].Name) != "example.com" {
		t.Errorf("Questions: %v", dns.Questions)
	}
	if len(dns.Answers) != 2 {
		t.Fatalf("Answers count: got %d want 2", len(dns.Answers))
	}
	if string(dns.Answers[0].Name) != "example.com" {
		t.Errorf("Answers[0].Name: got %q want %q", string(dns.Answers[0].Name), "example.com")
	}
	if string(dns.Answers[1].Name) != "www.example.com" {
		t.Errorf("Answers[1].Name: got %q want %q", string(dns.Answers[1].Name), "www.example.com")
	}
}

// TestBuildCompressedDNSWireSuffixSharing verifies that a common domain suffix shared
// across multiple answer names is compressed via back-pointers.  Both "sub1.example.com"
// and "sub2.example.com" share the ".example.com" suffix already written for the question.
func TestBuildCompressedDNSWireSuffixSharing(t *testing.T) {
	comp := &DNSComponent{
		QuestionsName:  []string{"example.com"},
		QuestionsType:  []uint16{uint16(layers.DNSTypeA)},
		QuestionsClass: []uint16{uint16(layers.DNSClassIN)},
		AnswersName:    []string{"sub1.example.com", "sub2.example.com"},
		AnswersType:    []uint16{uint16(layers.DNSTypeA), uint16(layers.DNSTypeA)},
		AnswersClass:   []uint16{uint16(layers.DNSClassIN), uint16(layers.DNSClassIN)},
		AnswersTTL:     []uint32{300, 300},
		AnswersRdata:   []string{"\x0a\x00\x00\x01", "\x0a\x00\x00\x02"},
		AnswersIP:      []string{"10.0.0.1", "10.0.0.2"},
	}

	uncompressed := comp.buildDNSWire()
	compressed := comp.buildCompressedDNSWire()
	if len(compressed) >= len(uncompressed) {
		t.Errorf("expected compressed (%d) < uncompressed (%d)", len(compressed), len(uncompressed))
	}

	// Re-parse and verify answer names survive the round-trip.
	dns := parseDNSLayer(t, compressed)
	if len(dns.Answers) != 2 {
		t.Fatalf("Answers count: got %d want 2", len(dns.Answers))
	}
	if string(dns.Answers[0].Name) != "sub1.example.com" {
		t.Errorf("Answers[0].Name: got %q want %q", dns.Answers[0].Name, "sub1.example.com")
	}
	if string(dns.Answers[1].Name) != "sub2.example.com" {
		t.Errorf("Answers[1].Name: got %q want %q", dns.Answers[1].Name, "sub2.example.com")
	}
}

// ---------------------------------------------------------------------------
// Reconstruct path-selection tests
// ---------------------------------------------------------------------------

// TestReconstructUsesUncompressedPath verifies that a query built without name
// compression encodes and reconstructs byte-identically (uncompressed path taken).
func TestReconstructUsesUncompressedPath(t *testing.T) {
	dns := &layers.DNS{
		ID: 0x0001,
		QR: false,
		Z:  0x02,
		Questions: []layers.DNSQuestion{
			{Name: []byte("simple.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}
	data := buildDNSBytes(t, dns)
	parsed := parseDNSLayer(t, data)

	comps, err := (&DNSComponent{}).Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// gopacket serializes without compression so the rebuild must be identical.
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}

// TestReconstructUsesCompressedPath verifies that when the stored RawLen is smaller
// than the uncompressed rebuild length, Reconstruct selects buildCompressedDNSWire.
// The hand-crafted wire (65 bytes) triggers this path because its uncompressed
// equivalent is 87 bytes.
func TestReconstructUsesCompressedPath(t *testing.T) {
	original := dnsCompressedResponseWire()
	parsed := parseDNSLayer(t, original)

	comps, err := (&DNSComponent{}).Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	comp := comps[0].(*DNSComponent)

	// Precondition: uncompressed rebuild must be larger than the original.
	if int(comp.RawLen) >= len(comp.buildDNSWire()) {
		t.Fatalf("precondition failed: RawLen=%d uncompressed=%d — compression not detected",
			comp.RawLen, len(comp.buildDNSWire()))
	}

	ctx := &DecodeContext{}
	if err := comp.Reconstruct(ctx); err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, ctx.Layers...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	rebuilt := parseDNSLayer(t, buf.Bytes())

	if rebuilt.ID != parsed.ID {
		t.Errorf("ID: got 0x%x want 0x%x", rebuilt.ID, parsed.ID)
	}
	if len(rebuilt.Questions) != len(parsed.Questions) {
		t.Fatalf("Questions count: got %d want %d", len(rebuilt.Questions), len(parsed.Questions))
	}
	if string(rebuilt.Questions[0].Name) != string(parsed.Questions[0].Name) {
		t.Errorf("Question name: got %q want %q", rebuilt.Questions[0].Name, parsed.Questions[0].Name)
	}
	if len(rebuilt.Answers) != len(parsed.Answers) {
		t.Fatalf("Answers count: got %d want %d", len(rebuilt.Answers), len(parsed.Answers))
	}
	for i, a := range parsed.Answers {
		if string(rebuilt.Answers[i].Name) != string(a.Name) {
			t.Errorf("Answers[%d].Name: got %q want %q", i, rebuilt.Answers[i].Name, a.Name)
		}
		if !rebuilt.Answers[i].IP.Equal(a.IP) {
			t.Errorf("Answers[%d].IP: got %v want %v", i, rebuilt.Answers[i].IP, a.IP)
		}
	}

	// The compressed rebuild must not exceed the original wire size.
	if len(buf.Bytes()) > len(original) {
		t.Errorf("compressed rebuild (%d bytes) exceeds original (%d bytes)", len(buf.Bytes()), len(original))
	}
}
