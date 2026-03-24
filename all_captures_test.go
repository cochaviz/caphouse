package caphouse

import (
	"sort"
	"testing"
	"time"
)

// sortTimedRefs sorts a slice of timedPacketRef by the merge key:
// (absNs ASC, sessionID ASC, packetID ASC).
// This mirrors the ORDER BY in fetchSortedPacketRefs and is exported here
// for use in tests.
func sortTimedRefs(refs []timedPacketRef) {
	sort.SliceStable(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.absNs != b.absNs {
			return a.absNs < b.absNs
		}
		if a.sessionID != b.sessionID {
			return a.sessionID < b.sessionID
		}
		return a.packetID < b.packetID
	})
}

// TestTimedRefSortOrder verifies the cross-capture sort key rules:
// 1. Packets are sorted by absolute time first.
// 2. Within the same absolute time, sorted by session ID.
// 3. Within the same session, original relative order (packetID) is preserved.
func TestTimedRefSortOrder(t *testing.T) {
	epoch := time.Unix(1_700_000_000, 0)

	var capA uint64 = 0xAAAAAAAA00000000
	var capB uint64 = 0xBBBBBBBB00000000
	var capC uint64 = 0xCCCCCCCC00000000

	refs := []timedPacketRef{
		// capB packet at epoch+5s
		{sessionID: capB, packetID: 0, absNs: epoch.Add(5 * time.Second).UnixNano()},
		// capA packet at epoch+3s
		{sessionID: capA, packetID: 2, absNs: epoch.Add(3 * time.Second).UnixNano()},
		// capA packet at epoch+1s
		{sessionID: capA, packetID: 0, absNs: epoch.Add(1 * time.Second).UnixNano()},
		// capA packet at epoch+2s
		{sessionID: capA, packetID: 1, absNs: epoch.Add(2 * time.Second).UnixNano()},
		// capC packet at same time as capA's packet 1; capA < capC numerically.
		{sessionID: capC, packetID: 0, absNs: epoch.Add(2 * time.Second).UnixNano()},
		// capB packet at epoch+4s
		{sessionID: capB, packetID: 1, absNs: epoch.Add(4 * time.Second).UnixNano()},
	}

	sortTimedRefs(refs)

	want := []struct {
		sessionID uint64
		packetID  uint32
	}{
		{capA, 0}, // epoch+1s
		{capA, 1}, // epoch+2s — capA before capC (same absNs, capA < capC numerically)
		{capC, 0}, // epoch+2s
		{capA, 2}, // epoch+3s
		{capB, 1}, // epoch+4s
		{capB, 0}, // epoch+5s
	}

	if len(refs) != len(want) {
		t.Fatalf("got %d refs, want %d", len(refs), len(want))
	}
	for i, w := range want {
		if refs[i].sessionID != w.sessionID || refs[i].packetID != w.packetID {
			t.Errorf("refs[%d] = {%d, pkt=%d}, want {%d, pkt=%d}",
				i, refs[i].sessionID, refs[i].packetID, w.sessionID, w.packetID)
		}
	}
}

// TestTimedRefStabilityWithinCapture verifies that packets from the same
// session maintain their original relative order when absolute times differ.
func TestTimedRefStabilityWithinCapture(t *testing.T) {
	epoch := time.Unix(1_700_000_000, 0)
	var capA uint64 = 0xAAAAAAAA00000000

	refs := []timedPacketRef{
		{sessionID: capA, packetID: 4, absNs: epoch.Add(4 * time.Second).UnixNano()},
		{sessionID: capA, packetID: 0, absNs: epoch.Add(0 * time.Second).UnixNano()},
		{sessionID: capA, packetID: 2, absNs: epoch.Add(2 * time.Second).UnixNano()},
		{sessionID: capA, packetID: 1, absNs: epoch.Add(1 * time.Second).UnixNano()},
		{sessionID: capA, packetID: 3, absNs: epoch.Add(3 * time.Second).UnixNano()},
	}

	sortTimedRefs(refs)

	for i, ref := range refs {
		if ref.packetID != uint32(i) {
			t.Errorf("refs[%d].packetID = %d, want %d", i, ref.packetID, i)
		}
	}
}
