package components

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseNTPLayer(t *testing.T, data []byte) *layers.NTP {
	t.Helper()
	pkt := gopacket.NewPacket(data, layers.LayerTypeNTP, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeNTP)
	if l == nil {
		t.Fatalf("failed to parse ntp layer")
	}
	return l.(*layers.NTP)
}

func buildNTPBytes(t *testing.T, ntp *layers.NTP) []byte {
	t.Helper()
	return mustSerializeFixLengths(t, ntp)
}

func TestNTPEncodeBasic(t *testing.T) {
	ntp := &layers.NTP{
		LeapIndicator:     0,
		Version:           4,
		Mode:              3, // client
		Stratum:           0,
		Poll:              3,
		Precision:         -6,
		RootDelay:         0x00010000,
		RootDispersion:    0x00020000,
		ReferenceID:       0x4c4f434c,
		ReferenceTimestamp: 0xE63B_7B00_00000000,
		TransmitTimestamp:  0xE63B_7C00_12345678,
	}
	data := buildNTPBytes(t, ntp)
	parsed := parseNTPLayer(t, data)

	enc := &NTPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	got := comps[0].(*NTPComponent)

	if got.Version != 4 {
		t.Errorf("Version: got %d want 4", got.Version)
	}
	if got.Mode != 3 {
		t.Errorf("Mode: got %d want 3 (client)", got.Mode)
	}
	if got.LeapIndicator != 0 {
		t.Errorf("LeapIndicator: got %d want 0", got.LeapIndicator)
	}
	if got.TransmitTS != 0xE63B_7C00_12345678 {
		t.Errorf("TransmitTS: got 0x%x", got.TransmitTS)
	}
	if got.ReferenceTS != 0xE63B_7B00_00000000 {
		t.Errorf("ReferenceTS: got 0x%x", got.ReferenceTS)
	}
	if got.RootDelay != 0x00010000 {
		t.Errorf("RootDelay: got 0x%x", got.RootDelay)
	}
	if len(got.NTPRaw) != 48 {
		t.Errorf("NTPRaw length: got %d want 48", len(got.NTPRaw))
	}
}

func TestNTPEncodeWrongLayer(t *testing.T) {
	enc := &NTPComponent{}
	_, err := enc.Encode(&layers.UDP{})
	if err == nil {
		t.Fatal("expected error for wrong layer type")
	}
}

func TestNTPRoundTrip(t *testing.T) {
	ntp := &layers.NTP{
		Version:           4,
		Mode:              4, // server
		Stratum:           2,
		Poll:              6,
		TransmitTimestamp: 0xDEADBEEF_CAFEBABE,
	}
	data := buildNTPBytes(t, ntp)
	parsed := parseNTPLayer(t, data)

	enc := &NTPComponent{}
	comps, err := enc.Encode(parsed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// NTP reconstruct replays NTPRaw verbatim, so the output equals the original wire bytes.
	assertReconstructBytes(t, comps[0].(LayerDecoder), parsed.LayerContents())
}
