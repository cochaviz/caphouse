package caphouse

import (
	"context"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"caphouse/components"
)

type idRange struct{ lo, hi uint32 }

// toRanges compresses packet IDs into the minimal set of contiguous ranges.
func toRanges(ids []uint32) []idRange {
	if len(ids) == 0 {
		return nil
	}
	sorted := make([]uint32, len(ids))
	copy(sorted, ids)
	slices.Sort(sorted)

	ranges := []idRange{{sorted[0], sorted[0]}}
	for _, id := range sorted[1:] {
		if id == ranges[len(ranges)-1].hi+1 {
			ranges[len(ranges)-1].hi = id
		} else {
			ranges = append(ranges, idRange{id, id})
		}
	}
	return ranges
}

// rangeArgs returns the WHERE clause fragment and args for a set of id ranges.
// args[0] is sessionID; subsequent pairs are (lo, hi) per range.
func rangeArgs(sessionID uint64, ranges []idRange) (string, []any) {
	var b strings.Builder
	args := make([]any, 1+2*len(ranges))
	args[0] = sessionID
	b.WriteByte('(')
	for i, r := range ranges {
		if i > 0 {
			b.WriteString(" OR ")
		}
		b.WriteString("packet_id BETWEEN ? AND ?")
		args[1+2*i] = r.lo
		args[2+2*i] = r.hi
	}
	b.WriteByte(')')
	return b.String(), args
}

// maxRangesPerQuery caps the BETWEEN clauses per query so that even degenerate
// (fully non-contiguous) ID sets stay within ClickHouse's max_query_size.
const maxRangesPerQuery = 1000

func (c *Client) fetchComponentBatch(
	ctx context.Context, sessionID uint64, packetIDs []uint32,
	ctor func() components.Component,
) (map[uint32][]components.Component, error) {
	m := make(map[uint32][]components.Component)
	ranges := toRanges(packetIDs)
	for len(ranges) > 0 {
		chunk := ranges
		if len(chunk) > maxRangesPerQuery {
			chunk = ranges[:maxRangesPerQuery]
		}
		ranges = ranges[len(chunk):]

		proto := ctor()
		whereClause, args := rangeArgs(sessionID, chunk)
		scanCols, err := proto.DataColumns("")
		if err != nil {
			return nil, fmt.Errorf("data columns for %s: %w", proto.Name(), err)
		}
		q := fmt.Sprintf(
			"SELECT %s FROM %s FINAL WHERE session_id = ? AND %s ORDER BY %s ASC",
			strings.Join(scanCols, ", "),
			c.tableRef(components.ComponentTable(proto)), whereClause, proto.FetchOrderBy(),
		)
		rows, err := c.conn.Query(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", proto.Name(), err)
		}
		for rows.Next() {
			item := ctor()
			sb, sbErr := components.NewScanBuf(item, false)
			if sbErr != nil {
				rows.Close()
				return nil, fmt.Errorf("scan buf %s: %w", proto.Name(), sbErr)
			}
			var pid uint32
			if err := rows.Scan(append([]any{&pid}, sb.Targets...)...); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan %s: %w", proto.Name(), err)
			}
			sb.Apply()
			item.ApplyNucleus(components.PacketNucleus{SessionID: sessionID, PacketID: pid})
			m[pid] = append(m[pid], item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return m, nil
}

type fetchResult struct {
	kind uint
	rows map[uint32][]components.Component
	err  error
}

func (c *Client) fetchComponentsForBatch(
	ctx context.Context, sessionID uint64, packetIDs []uint32,
) (map[uint]map[uint32][]components.Component, error) {
	n := len(components.ComponentFactories)
	results := make(chan fetchResult, n)
	for kind, ctor := range components.ComponentFactories {
		go func() {
			rows, err := c.fetchComponentBatch(ctx, sessionID, packetIDs, ctor)
			results <- fetchResult{kind, rows, err}
		}()
	}
	all := make(map[uint]map[uint32][]components.Component, n)
	for range n {
		r := <-results
		if r.err != nil {
			return nil, r.err
		}
		all[r.kind] = r.rows
	}
	return all, nil
}

// resolveComponents builds the component list for one packet from a pre-fetched batch map.
func resolveComponents(
	nucleus components.PacketNucleus,
	all map[uint]map[uint32][]components.Component,
) ([]components.Component, error) {
	var list []components.Component
	for _, kind := range components.KnownComponentKinds {
		if !components.ComponentHas(nucleus.Components, kind) {
			continue
		}
		rows := all[kind][nucleus.PacketID]
		if len(rows) == 0 {
			return nil, fmt.Errorf("missing component %d for session %d/%d", kind, nucleus.SessionID, nucleus.PacketID)
		}
		list = append(list, rows...)
	}
	return list, nil
}

// reconstructedPkt holds a single reconstructed packet ready for export.
type reconstructedPkt struct {
	ts   time.Time
	incl uint32
	orig uint32
	frame []byte
}

// fetchReconstructedPackets fetches nucleus data and all components for the
// given packet IDs in sessionID, then returns reconstructed packets keyed by packetID.
func (c *Client) fetchReconstructedPackets(ctx context.Context, sessionID uint64, packetIDs []uint32) (map[uint32]reconstructedPkt, error) {
	if len(packetIDs) == 0 {
		return nil, nil
	}
	ranges := toRanges(packetIDs)
	const selectCols = "SELECT packet_id, ts, incl_len, trunc_extra, components, payload"
	type nucleusRow struct {
		packetID      uint32
		tsNs          int64
		incl          uint32
		truncExtra    uint32
		componentMask *big.Int
		payload      string
	}
	var nuclei []nucleusRow
	for start := 0; start < len(ranges); start += maxRangesPerQuery {
		end := min(start+maxRangesPerQuery, len(ranges))
		chunk := ranges[start:end]
		whereClause, whereArgs := rangeArgs(sessionID, chunk)
		q := fmt.Sprintf("%s FROM %s FINAL WHERE session_id = ? AND %s ORDER BY packet_id ASC",
			selectCols, c.packetsTable(), whereClause)
		rows, err := c.conn.Query(ctx, q, whereArgs...)
		if err != nil {
			return nil, fmt.Errorf("fetch nuclei for session %d: %w", sessionID, err)
		}
		for rows.Next() {
			componentMask := new(big.Int)
			var row nucleusRow
			row.componentMask = componentMask
			if err := rows.Scan(&row.packetID, &row.tsNs, &row.incl, &row.truncExtra, componentMask, &row.payload); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan nucleus: %w", err)
			}
			nuclei = append(nuclei, row)
		}
		iterErr := rows.Err()
		rows.Close()
		if iterErr != nil {
			return nil, fmt.Errorf("iterate nuclei: %w", iterErr)
		}
	}

	all, err := c.fetchComponentsForBatch(ctx, sessionID, packetIDs)
	if err != nil {
		return nil, err
	}

	result := make(map[uint32]reconstructedPkt, len(nuclei))
	for _, row := range nuclei {
		ts := time.Unix(0, row.tsNs)
		nucleus := components.PacketNucleus{
			SessionID:  sessionID,
			PacketID:   row.packetID,
			Timestamp:  ts,
			InclLen:    row.incl,
			OrigLen:    row.incl + row.truncExtra,
			Components: row.componentMask,
			Payload:    []byte(row.payload),
		}
		componentList, err := resolveComponents(nucleus, all)
		if err != nil {
			return nil, err
		}
		frame, err := reconstructFrame(nucleus, componentList)
		if err != nil {
			return nil, fmt.Errorf("reconstruct packet %d in session %d: %w", row.packetID, sessionID, err)
		}
		result[row.packetID] = reconstructedPkt{
			ts:    ts,
			incl:  row.incl,
			orig:  row.incl + row.truncExtra,
			frame: frame,
		}
	}
	return result, nil
}
