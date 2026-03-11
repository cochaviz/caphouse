package caphouse

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestTimeRangeExtraction verifies that TimeRange correctly extracts bounds
// from simple and compound query expressions.
func TestTimeRangeExtraction(t *testing.T) {
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2024, 1, 4, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		expr      string
		wantOk    bool
		wantFrom  int64
		wantTo    int64
	}{
		{
			name:     "simple time range",
			expr:     "time 2024-01-01T00:00:00Z to 2024-01-02T00:00:00Z",
			wantOk:   true,
			wantFrom: t0.UnixNano(),
			wantTo:   t1.UnixNano(),
		},
		{
			name:   "no time node",
			expr:   "host 1.2.3.4",
			wantOk: false,
		},
		{
			name:     "time AND host extracts time",
			expr:     "time 2024-01-01T00:00:00Z to 2024-01-02T00:00:00Z and host 1.2.3.4",
			wantOk:   true,
			wantFrom: t0.UnixNano(),
			wantTo:   t1.UnixNano(),
		},
		{
			name: "AND of two time ranges uses intersection",
			// from = max(t0, t1) = t1; to = min(t2, t3) = t2
			expr:     "time 2024-01-01T00:00:00Z to 2024-01-03T00:00:00Z and time 2024-01-02T00:00:00Z to 2024-01-04T00:00:00Z",
			wantOk:   true,
			wantFrom: t1.UnixNano(),
			wantTo:   t2.UnixNano(),
		},
		{
			name: "OR of two time ranges uses union",
			// from = min(t0, t2) = t0; to = max(t1, t3) = t3
			expr:     "time 2024-01-01T00:00:00Z to 2024-01-02T00:00:00Z or time 2024-01-03T00:00:00Z to 2024-01-04T00:00:00Z",
			wantOk:   true,
			wantFrom: t0.UnixNano(),
			wantTo:   t3.UnixNano(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q, err := ParseQuery(tc.expr)
			if err != nil {
				t.Fatalf("ParseQuery: %v", err)
			}
			from, to, ok := q.TimeRange()
			if ok != tc.wantOk {
				t.Fatalf("TimeRange ok = %v, want %v", ok, tc.wantOk)
			}
			if !tc.wantOk {
				return
			}
			if from != tc.wantFrom {
				t.Errorf("from = %d, want %d", from, tc.wantFrom)
			}
			if to != tc.wantTo {
				t.Errorf("to = %d, want %d", to, tc.wantTo)
			}
		})
	}
}

// sortTimedRefs sorts a slice of timedPacketRef by the merge key:
// (absNs ASC, captureCreatedAt ASC, captureID ASC, packetID ASC).
// This mirrors the ORDER BY in fetchSortedPacketRefs and is exported here
// for use in tests.
func sortTimedRefs(refs []timedPacketRef) {
	sort.SliceStable(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.absNs != b.absNs {
			return a.absNs < b.absNs
		}
		if !a.captureCreatedAt.Equal(b.captureCreatedAt) {
			return a.captureCreatedAt.Before(b.captureCreatedAt)
		}
		ac := a.captureID.String()
		bc := b.captureID.String()
		if ac != bc {
			return ac < bc
		}
		return a.packetID < b.packetID
	})
}

// TestTimedRefSortOrder verifies the cross-capture sort key rules:
// 1. Packets are sorted by absolute time first.
// 2. Within the same absolute time, sorted by capture start time.
// 3. Within the same absolute time and capture start, sorted by capture ID.
// 4. Within the same capture, original relative order (packetID) is preserved.
func TestTimedRefSortOrder(t *testing.T) {
	epoch := time.Unix(1_700_000_000, 0)

	capA := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000000")
	capB := uuid.MustParse("bbbbbbbb-0000-0000-0000-000000000000")
	capC := uuid.MustParse("cccccccc-0000-0000-0000-000000000000")

	startA := epoch
	startB := epoch.Add(time.Second) // starts 1 s later
	startC := epoch                  // same start as A but different UUID

	refs := []timedPacketRef{
		// capB packet at epoch+5s (absNs = startB + 4s = epoch+5s)
		{captureID: capB, packetID: 0, absNs: epoch.Add(5 * time.Second).UnixNano(), captureCreatedAt: startB},
		// capA packet at epoch+3s
		{captureID: capA, packetID: 2, absNs: epoch.Add(3 * time.Second).UnixNano(), captureCreatedAt: startA},
		// capA packet at epoch+1s
		{captureID: capA, packetID: 0, absNs: epoch.Add(1 * time.Second).UnixNano(), captureCreatedAt: startA},
		// capA packet at epoch+2s
		{captureID: capA, packetID: 1, absNs: epoch.Add(2 * time.Second).UnixNano(), captureCreatedAt: startA},
		// capC packet at same time as capA's packet 1 (tie: capA starts before capC? No, same start)
		// capA < capC lexicographically, so capA wins the tie.
		{captureID: capC, packetID: 0, absNs: epoch.Add(2 * time.Second).UnixNano(), captureCreatedAt: startC},
		// capB packet at epoch+4s
		{captureID: capB, packetID: 1, absNs: epoch.Add(4 * time.Second).UnixNano(), captureCreatedAt: startB},
	}

	sortTimedRefs(refs)

	want := []struct {
		captureID uuid.UUID
		packetID  uint64
	}{
		{capA, 0}, // epoch+1s
		{capA, 1}, // epoch+2s — capA before capC (same absNs, same startTime, capA < capC by UUID)
		{capC, 0}, // epoch+2s
		{capA, 2}, // epoch+3s
		{capB, 1}, // epoch+4s
		{capB, 0}, // epoch+5s
	}

	if len(refs) != len(want) {
		t.Fatalf("got %d refs, want %d", len(refs), len(want))
	}
	for i, w := range want {
		if refs[i].captureID != w.captureID || refs[i].packetID != w.packetID {
			t.Errorf("refs[%d] = {%s, pkt=%d}, want {%s, pkt=%d}",
				i, refs[i].captureID, refs[i].packetID, w.captureID, w.packetID)
		}
	}
}

// TestTimedRefStabilityWithinCapture verifies that packets from the same
// capture maintain their original relative order when absolute times differ.
func TestTimedRefStabilityWithinCapture(t *testing.T) {
	epoch := time.Unix(1_700_000_000, 0)
	capA := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000000")

	refs := []timedPacketRef{
		{captureID: capA, packetID: 4, absNs: epoch.Add(4 * time.Second).UnixNano()},
		{captureID: capA, packetID: 0, absNs: epoch.Add(0 * time.Second).UnixNano()},
		{captureID: capA, packetID: 2, absNs: epoch.Add(2 * time.Second).UnixNano()},
		{captureID: capA, packetID: 1, absNs: epoch.Add(1 * time.Second).UnixNano()},
		{captureID: capA, packetID: 3, absNs: epoch.Add(3 * time.Second).UnixNano()},
	}

	sortTimedRefs(refs)

	for i, ref := range refs {
		if ref.packetID != uint64(i) {
			t.Errorf("refs[%d].packetID = %d, want %d", i, ref.packetID, i)
		}
	}
}

// TestExportAllRequiresTimeRange verifies that ExportAllCapturesFiltered
// rejects queries that do not contain a time filter.
func TestExportAllRequiresTimeRange(t *testing.T) {
	c := &Client{} // no real connection needed; we expect early failure
	q, err := ParseQuery("host 1.2.3.4")
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	_, _, err = c.ExportAllCapturesFiltered(context.Background(), q, nil)
	if err == nil {
		t.Fatal("expected error for query without time range, got nil")
	}
}
