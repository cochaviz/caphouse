package components

import (
	"bytes"
	"testing"

	"github.com/google/gopacket"
)

// mustSerialize serializes gopacket layers with FixLengths and ComputeChecksums.
// Use this when building test input frames that need correct lengths and checksums.
func mustSerialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("mustSerialize: %v", err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

// mustSerializeFixLengths serializes with FixLengths but without computing checksums.
// Use when serializing standalone layers that lack a network layer for pseudoheader checksums.
func mustSerializeFixLengths(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("mustSerializeFixLengths: %v", err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

// assertReconstructBytes calls Reconstruct on comp and verifies the serialized
// output equals want. SerializeOptions are kept at defaults (no FixLengths, no
// ComputeChecksums) so stored checksums/lengths are preserved verbatim.
func assertReconstructBytes(t *testing.T, comp LayerDecoder, want []byte) {
	t.Helper()
	ctx := &DecodeContext{}
	if err := comp.Reconstruct(ctx); err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, ctx.Layers...); err != nil {
		t.Fatalf("serialize reconstructed: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("reconstructed bytes mismatch:\n  got:  %x\n  want: %x", buf.Bytes(), want)
	}
}
