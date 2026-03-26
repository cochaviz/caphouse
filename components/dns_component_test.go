package components

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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
	if got.Flags&0x08 == 0 {
		t.Error("AA flag not set")
	}
	if got.Flags&0x04 == 0 {
		t.Error("TC flag not set")
	}
	if got.Flags&0x02 == 0 {
		t.Error("RD flag not set")
	}
	if got.Flags&0x01 == 0 {
		t.Error("RA flag not set")
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
