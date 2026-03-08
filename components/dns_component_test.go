package components

import (
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
	if len(got.DNSRaw) == 0 {
		t.Error("DNSRaw is empty")
	}
}

func TestDNSEncodeFlags(t *testing.T) {
	dns := &layers.DNS{
		ID: 0xabcd,
		QR: true,  // response
		AA: true,  // authoritative
		TC: true,  // truncated
		RD: true,  // recursion desired
		RA: true,  // recursion available
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
	// DNS reconstruct replays DNSRaw verbatim, so the output equals the original wire bytes.
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}
