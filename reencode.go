package caphouse

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"caphouse/components"
)

// ReEncodeResult summarises a re-encoding run.
type ReEncodeResult struct {
	Candidates int64 `json:"candidates"` // packets matched (no L4+ component)
	ReEncoded  int64 `json:"re_encoded"` // packets successfully written back
	Upgraded   int64 `json:"upgraded"`   // packets that gained at least one new component
}

// l4AndAboveMask returns the bitmask covering every component whose layer
// order is OrderL4Base or higher. Packets that carry none of these bits have
// no L4-level component and are candidates for re-encoding.
func l4AndAboveMask() uint64 {
	var mask uint64
	for _, kind := range components.KnownComponentKinds {
		comp := components.ComponentFactories[kind]()
		if comp.Order() >= components.OrderL4Base {
			mask |= 1 << kind
		}
	}
	return mask
}

// ReEncodePackets re-encodes all packets that were stored without any L4-or-
// above component (e.g. ICMPv4/ICMPv6 packets ingested before those components
// were registered). For each candidate the original frame is reconstructed,
// re-encoded with the current component registry, and written back — the
// ReplacingMergeTree engine deduplicates the updated rows on the next merge.
//
// If sessionIDs is non-empty only packets from those sessions are considered;
// otherwise all sessions are scanned.
func (c *Client) ReEncodePackets(ctx context.Context, sessionIDs []uint64) (ReEncodeResult, error) {
	l4mask := l4AndAboveMask()

	// Build the candidate inner query: packets with no L4+ bits.
	var innerWhere string
	if len(sessionIDs) > 0 {
		innerWhere = fmt.Sprintf(
			"bitAnd(toUInt64(components), %d) = 0 AND %s",
			l4mask, sessionInSQL(sessionIDs),
		)
	} else {
		innerWhere = fmt.Sprintf("bitAnd(toUInt64(components), %d) = 0", l4mask)
	}
	innerSQL := fmt.Sprintf(
		"SELECT session_id, packet_id FROM %s FINAL WHERE %s ORDER BY session_id ASC, packet_id ASC",
		c.packetsTable(), innerWhere,
	)

	// Count candidates first so we can populate the result.
	var total uint64
	if err := c.conn.QueryRow(ctx, "SELECT count() FROM ("+innerSQL+")").Scan(&total); err != nil {
		return ReEncodeResult{}, fmt.Errorf("count candidates: %w", err)
	}
	if total == 0 {
		return ReEncodeResult{}, nil
	}

	// Fetch capture meta for all affected sessions so we know each linktype.
	var affectedSessions []uint64
	{
		rows, err := c.conn.Query(ctx,
			fmt.Sprintf("SELECT DISTINCT session_id FROM (%s)", innerSQL))
		if err != nil {
			return ReEncodeResult{}, fmt.Errorf("fetch session ids: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var sid uint64
			if err := rows.Scan(&sid); err != nil {
				return ReEncodeResult{}, fmt.Errorf("scan session id: %w", err)
			}
			affectedSessions = append(affectedSessions, sid)
		}
		if err := rows.Err(); err != nil {
			return ReEncodeResult{}, fmt.Errorf("iterate session ids: %w", err)
		}
	}

	metaMap, err := c.fetchCaptureMetaMap(ctx, affectedSessions)
	if err != nil {
		return ReEncodeResult{}, fmt.Errorf("fetch capture meta: %w", err)
	}

	// Build the wide-JOIN SQL that fetches nucleus + all component columns.
	exportSQL, err := c.buildExportSQL(innerSQL)
	if err != nil {
		return ReEncodeResult{}, fmt.Errorf("build export sql: %w", err)
	}

	rows, err := c.conn.Query(ctx, exportSQL)
	if err != nil {
		return ReEncodeResult{}, fmt.Errorf("re-encode query: %w", err)
	}
	defer rows.Close()

	// Pre-allocate scan buffers (mirrors streamExport).
	type scanEntry struct {
		comp       components.Component
		scanBuf    *components.ScanBuf
		repeatable components.RepeatableExporter
	}
	entries := make([]scanEntry, len(components.KnownComponentKinds))
	for i, kind := range components.KnownComponentKinds {
		comp := components.ComponentFactories[kind]()
		e := scanEntry{comp: comp}
		if re, ok := comp.(components.RepeatableExporter); ok {
			e.repeatable = re
		} else {
			sb, err := components.NewScanBuf(comp, false)
			if err != nil {
				return ReEncodeResult{}, fmt.Errorf("build scan buf for %s: %w", comp.Name(), err)
			}
			e.scanBuf = sb
		}
		entries[i] = e
	}

	var (
		sessionID           uint64
		packetID            uint32
		tsNs                int64
		inclLen, truncExtra uint32
		componentMask       = new(big.Int)
		payload             string
	)
	nucleusTargets := []any{
		&sessionID, &packetID, &tsNs,
		&inclLen, &truncExtra,
		componentMask,
		&payload,
	}

	var result ReEncodeResult
	result.Candidates = int64(total)

	var pending []codecPacket

	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		if err := c.insertBatch(ctx, pending); err != nil {
			return err
		}
		pending = pending[:0]
		return nil
	}

	for rows.Next() {
		componentMask.SetInt64(0)

		targets := nucleusTargets
		for _, e := range entries {
			if e.repeatable != nil {
				targets = append(targets, e.repeatable.ExportScanTargets()...)
			} else {
				targets = append(targets, e.scanBuf.Targets...)
			}
		}
		if err := rows.Scan(targets...); err != nil {
			return result, fmt.Errorf("scan re-encode row: %w", err)
		}
		for _, e := range entries {
			if e.scanBuf != nil {
				e.scanBuf.Apply()
			}
		}

		ts := time.Unix(0, tsNs)
		nucleus := components.PacketNucleus{
			SessionID:  sessionID,
			PacketID:   packetID,
			Timestamp:  ts,
			InclLen:    inclLen,
			OrigLen:    inclLen + truncExtra,
			Components: componentMask,
			Payload:    []byte(payload),
		}

		var compList []components.Component
		for i, kind := range components.KnownComponentKinds {
			if components.ComponentHas(nucleus.Components, kind) {
				e := entries[i]
				if e.repeatable != nil {
					compList = append(compList, e.repeatable.ExportExpand(sessionID, packetID)...)
				} else {
					compList = append(compList, components.ExpandOne(e.comp, sessionID, packetID)...)
				}
			}
		}

		frame, err := reconstructFrame(nucleus, compList)
		if err != nil {
			c.log.Warn("re-encode: skip packet (reconstruct failed)",
				"session", sessionID, "packet", packetID, "err", err)
			continue
		}

		meta := metaMap[sessionID]
		newEncoded := encodePacket(meta.LinkType, Packet{
			SessionID: sessionID,
			PacketID:  packetID,
			Timestamp: ts,
			InclLen:   inclLen,
			OrigLen:   inclLen + truncExtra,
			Frame:     frame,
		})

		// Check whether the re-encoding gained any new components.
		oldL4bits := new(big.Int).And(nucleus.Components, big.NewInt(0).SetUint64(l4mask))
		newL4bits := new(big.Int).And(newEncoded.Nucleus.Components, big.NewInt(0).SetUint64(l4mask))
		if newL4bits.Cmp(oldL4bits) != 0 {
			result.Upgraded++
		}

		pending = append(pending, newEncoded)
		result.ReEncoded++

		if len(pending) >= 1000 {
			if err := flush(); err != nil {
				return result, fmt.Errorf("flush re-encode batch: %w", err)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate re-encode rows: %w", err)
	}
	if err := flush(); err != nil {
		return result, fmt.Errorf("flush final batch: %w", err)
	}

	// Log a summary.
	sessionStrs := make([]string, len(affectedSessions))
	for i, id := range affectedSessions {
		sessionStrs[i] = fmt.Sprintf("%d", id)
	}
	c.log.Info("re-encode complete",
		"candidates", result.Candidates,
		"re_encoded", result.ReEncoded,
		"upgraded", result.Upgraded,
		"sessions", strings.Join(sessionStrs, ","),
	)

	return result, nil
}
