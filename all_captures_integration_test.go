//go:build integration

package caphouse

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
)

// buildSimplePCAP creates an in-memory classic LE/µs Ethernet PCAP from the
// given (timestamp, frame) pairs.
func buildSimplePCAP(t *testing.T, pkts []struct {
	ts    time.Time
	frame []byte
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	for _, p := range pkts {
		ci := gopacket.CaptureInfo{
			Timestamp:     p.ts,
			CaptureLength: len(p.frame),
			Length:        len(p.frame),
		}
		if err := w.WritePacket(ci, p.frame); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// mockMultiCapture: an in-process multi-capture store for integration tests.
// It simulates the cross-capture sort without needing a real ClickHouse.
// ---------------------------------------------------------------------------

type captureEntry struct {
	meta    CaptureMeta
	packets map[uint64]reconstructedPkt
}

type mockMultiCapture struct {
	captures map[uuid.UUID]*captureEntry
}

func newMockMultiCapture(t *testing.T) *mockMultiCapture {
	t.Helper()
	return &mockMultiCapture{captures: make(map[uuid.UUID]*captureEntry)}
}

// ingest ingests pcapData and returns the assigned capture ID.
func (m *mockMultiCapture) ingest(t *testing.T, pcapData []byte, filename string) uuid.UUID {
	t.Helper()
	if len(pcapData) < 24 {
		t.Fatalf("ingest %s: pcap too short", filename)
	}
	meta, err := ParseGlobalHeader(pcapData[:24])
	if err != nil {
		t.Fatalf("ingest %s: ParseGlobalHeader: %v", filename, err)
	}
	meta.CaptureID = uuid.New()
	meta.SensorID = "test"

	r, err := pcapgo.NewReader(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("ingest %s: new reader: %v", filename, err)
	}

	type rawPkt struct {
		ts    time.Time
		frame []byte
	}
	var rawPkts []rawPkt
	for {
		frame, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		rawPkts = append(rawPkts, rawPkt{ci.Timestamp, append([]byte(nil), frame...)})
	}
	if len(rawPkts) == 0 {
		t.Fatalf("ingest %s: no packets", filename)
	}
	meta.CreatedAt = rawPkts[0].ts

	entry := &captureEntry{
		meta:    meta,
		packets: make(map[uint64]reconstructedPkt, len(rawPkts)),
	}
	for i, p := range rawPkts {
		entry.packets[uint64(i)] = reconstructedPkt{
			ts:    p.ts,
			incl:  uint32(len(p.frame)),
			orig:  uint32(len(p.frame)),
			frame: p.frame,
		}
	}
	m.captures[meta.CaptureID] = entry
	return meta.CaptureID
}

func (m *mockMultiCapture) captureMap() map[uuid.UUID]CaptureMeta {
	cm := make(map[uuid.UUID]CaptureMeta, len(m.captures))
	for id, e := range m.captures {
		cm[id] = e.meta
	}
	return cm
}

// sortedRefs returns timedPacketRefs for all packets whose absolute time falls
// in [from, to], sorted by the merge key.
func (m *mockMultiCapture) sortedRefs(from, to time.Time) []timedPacketRef {
	var refs []timedPacketRef
	for captureID, entry := range m.captures {
		for packetID, pkt := range entry.packets {
			absNs := pkt.ts.UnixNano()
			if absNs < from.UnixNano() || absNs > to.UnixNano() {
				continue
			}
			refs = append(refs, timedPacketRef{
				captureID:        captureID,
				packetID:         packetID,
				absNs:            absNs,
				captureCreatedAt: entry.meta.CreatedAt,
			})
		}
	}
	sortTimedRefs(refs)
	return refs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestExportAllSortOrder verifies that packets from multiple captures are
// sorted by absolute time, with captures interleaved correctly.
func TestExportAllSortOrder(t *testing.T) {
	epoch := time.Unix(1_700_000_000, 0).UTC()

	frame := func(b byte) []byte { return []byte{b, b, b, b} }

	// capA: packets at epoch+0s, epoch+2s, epoch+4s.
	// capB: packets at epoch+1s, epoch+3s, epoch+5s.
	// Expected merged order: 0s(A), 1s(B), 2s(A), 3s(B), 4s(A), 5s(B).

	pcapA := buildSimplePCAP(t, []struct {
		ts    time.Time
		frame []byte
	}{
		{epoch, frame(0xAA)},
		{epoch.Add(2 * time.Second), frame(0xAB)},
		{epoch.Add(4 * time.Second), frame(0xAC)},
	})
	pcapB := buildSimplePCAP(t, []struct {
		ts    time.Time
		frame []byte
	}{
		{epoch.Add(1 * time.Second), frame(0xBA)},
		{epoch.Add(3 * time.Second), frame(0xBB)},
		{epoch.Add(5 * time.Second), frame(0xBC)},
	})

	mc := newMockMultiCapture(t)
	mc.ingest(t, pcapA, "capA.pcap")
	mc.ingest(t, pcapB, "capB.pcap")

	from := epoch.Add(-time.Second)
	to := epoch.Add(6 * time.Second)
	refs := mc.sortedRefs(from, to)

	wantFrames := [][]byte{
		frame(0xAA), frame(0xBA), frame(0xAB), frame(0xBB), frame(0xAC), frame(0xBC),
	}
	if len(refs) != len(wantFrames) {
		t.Fatalf("got %d refs, want %d", len(refs), len(wantFrames))
	}

	captureMap := mc.captureMap()
	for i, ref := range refs {
		entry := mc.captures[ref.captureID]
		if entry == nil {
			t.Fatalf("ref %d: unknown capture %s", i, ref.captureID)
		}
		pkt := entry.packets[ref.packetID]
		if !bytes.Equal(pkt.frame, wantFrames[i]) {
			t.Errorf("refs[%d] (cap=%s, pkt=%d): frame %x, want %x",
				i, ref.captureID, ref.packetID, pkt.frame, wantFrames[i])
		}
		_ = captureMap
	}
}

// TestExportAllTieBreakByCaptureStart verifies that when two packets have the
// same absolute timestamp, the one from the earlier-started capture appears
// first.
func TestExportAllTieBreakByCaptureStart(t *testing.T) {
	epoch := time.Unix(1_700_001_000, 0).UTC()
	frame := func(b byte) []byte { return []byte{b, b, b, b} }

	// capEarly starts at epoch-2s; it has a packet AT epoch (offset = 2s).
	// capLate  starts at epoch-1s; it has a packet AT epoch (offset = 1s).
	// Both tie at epoch. capEarly's CreatedAt is earlier, so its packet wins.
	pcapEarly := buildSimplePCAP(t, []struct {
		ts    time.Time
		frame []byte
	}{
		{epoch.Add(-2 * time.Second), frame(0x10)},
		{epoch, frame(0x11)},
	})
	pcapLate := buildSimplePCAP(t, []struct {
		ts    time.Time
		frame []byte
	}{
		{epoch.Add(-1 * time.Second), frame(0x20)},
		{epoch, frame(0x21)},
	})

	mc := newMockMultiCapture(t)
	mc.ingest(t, pcapEarly, "early.pcap")
	mc.ingest(t, pcapLate, "late.pcap")

	from := epoch.Add(-3 * time.Second)
	to := epoch.Add(time.Second)
	refs := mc.sortedRefs(from, to)

	if len(refs) != 4 {
		t.Fatalf("got %d refs, want 4", len(refs))
	}

	// refs[0]: epoch-2s (capEarly anchor), refs[1]: epoch-1s (capLate anchor),
	// refs[2]: epoch (capEarly tie), refs[3]: epoch (capLate tie).
	capMap := mc.captureMap()
	thirdCap := capMap[refs[2].captureID]
	fourthCap := capMap[refs[3].captureID]

	if !thirdCap.CreatedAt.Before(fourthCap.CreatedAt) {
		t.Errorf("tie-break failed: refs[2] from capture starting at %v, refs[3] from %v; want refs[2] earlier",
			thirdCap.CreatedAt, fourthCap.CreatedAt)
	}
}

// TestExportAllStabilityWithinCapture verifies that packets from the same
// capture retain their original relative order in the merged output.
func TestExportAllStabilityWithinCapture(t *testing.T) {
	epoch := time.Unix(1_700_002_000, 0).UTC()
	frame := func(b byte) []byte { return []byte{b, b, b, b} }

	// Single capture with 5 packets in sequential time order.
	pcapA := buildSimplePCAP(t, []struct {
		ts    time.Time
		frame []byte
	}{
		{epoch, frame(0x01)},
		{epoch.Add(1 * time.Second), frame(0x02)},
		{epoch.Add(2 * time.Second), frame(0x03)},
		{epoch.Add(3 * time.Second), frame(0x04)},
		{epoch.Add(4 * time.Second), frame(0x05)},
	})

	mc := newMockMultiCapture(t)
	mc.ingest(t, pcapA, "single.pcap")

	from := epoch.Add(-time.Second)
	to := epoch.Add(5 * time.Second)
	refs := mc.sortedRefs(from, to)

	if len(refs) != 5 {
		t.Fatalf("got %d refs, want 5", len(refs))
	}
	for i := range refs {
		if refs[i].packetID != uint64(i) {
			t.Errorf("refs[%d].packetID = %d, want %d", i, refs[i].packetID, i)
		}
	}
}

// TestExportAllRequiresTimeRange is an integration-level check that the
// ExportAllCapturesFiltered function rejects a query without a time node.
func TestExportAllRequiresTimeRangeIntegration(t *testing.T) {
	c := &Client{}
	q, _ := ParseQuery("host 1.2.3.4")
	_, _, err := c.ExportAllCapturesFiltered(context.Background(), q, nil)
	if err == nil {
		t.Fatal("expected error for query without time range, got nil")
	}
}
