package query

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// PacketRef identifies a single packet within a capture.
type PacketRef struct {
	CaptureID uuid.UUID
	PacketID  uint64
}

// Query is a compiled packet filter expression ready to translate into
// ClickHouse SQL. Obtain one via [ParseQuery].
type Query struct {
	root queryNode
}

// Subquery returns the SQL fragment and bind args for this filter. The
// fragment selects (capture_id, packet_id) rows and can be embedded inside
// a larger query with IN or INTERSECT/UNION/EXCEPT operators.
func (q Query) Subquery(t Tables, captureIDs []uuid.UUID) (sql string, args []any, err error) {
	return q.root.subquery(t, captureIDs)
}

// TimeRange extracts the time bounds from a query. Returns (from, to) as Unix
// nanoseconds and ok=true when the query contains at least one time node. For
// AND queries, the intersection of both sides is returned. For OR queries, the
// union. ok is false when the query contains no time filter.
func (q Query) TimeRange() (from, to int64, ok bool) {
	return extractTimeRange(q.root)
}

func extractTimeRange(n queryNode) (from, to int64, ok bool) {
	switch t := n.(type) {
	case *timeNode:
		return t.from, t.to, true
	case *andNode:
		lf, lt, lok := extractTimeRange(t.left)
		rf, rt, rok := extractTimeRange(t.right)
		if lok && rok {
			return max(lf, rf), min(lt, rt), true
		}
		if lok {
			return lf, lt, true
		}
		return rf, rt, rok
	case *orNode:
		lf, lt, lok := extractTimeRange(t.left)
		rf, rt, rok := extractTimeRange(t.right)
		if lok && rok {
			return min(lf, rf), max(lt, rt), true
		}
		if lok {
			return lf, lt, true
		}
		return rf, rt, rok
	default:
		return 0, 0, false
	}
}

// SQL generates a full SELECT statement equivalent to this filter, with all
// bind parameters inlined. It selects p.* from pcap_packets plus any
// requested component columns via LEFT JOIN. This is the human-readable form
// used by GenerateSQL / GenerateSQLForCaptures.
// When captureIDs is nil or empty, the query covers all captures.
func (q Query) SQL(t Tables, captureIDs []uuid.UUID, comps []string) (string, error) {
	for _, comp := range comps {
		if _, ok := t.Components[comp]; !ok {
			return "", fmt.Errorf("unknown component %q", comp)
		}
	}

	sub, args, err := q.root.subquery(t, captureIDs)
	if err != nil {
		return "", err
	}
	inlinedSub := inlineArgs(sub, args)

	// SELECT list: p.* plus component columns (excluding shared keys).
	selectParts := []string{"p.*"}
	for _, comp := range comps {
		info := t.Components[comp]
		selectParts = append(selectParts,
			fmt.Sprintf("%s.* EXCEPT (capture_id, packet_id, codec_version)", info.Alias),
		)
	}

	// FROM clause + optional component LEFT JOINs.
	fromClause := fmt.Sprintf("FROM %s AS p FINAL", t.Packets)
	var joins []string
	for _, comp := range comps {
		info := t.Components[comp]
		joins = append(joins,
			fmt.Sprintf("LEFT JOIN %s AS %s FINAL USING (capture_id, packet_id)", info.TableRef, info.Alias),
		)
	}

	var sb strings.Builder
	sb.WriteString("SELECT\n    ")
	sb.WriteString(strings.Join(selectParts, ",\n    "))
	sb.WriteString("\n")
	sb.WriteString(fromClause)
	for _, j := range joins {
		sb.WriteString("\n")
		sb.WriteString(j)
	}
	sb.WriteString("\nWHERE (p.capture_id, p.packet_id) IN (\n")
	sb.WriteString(inlinedSub)
	sb.WriteString("\n)")

	return sb.String(), nil
}

// CountsSQL generates the SQL for a packet-count histogram. Packets matched
// by the filter are bucketed into fixed-width time bins of binSizeNs
// nanoseconds. Returns rows of (bin_start_ns int64, count uint64) ordered by
// bin start. When captureIDs is nil or empty, the query covers all captures.
func (q Query) CountsSQL(t Tables, captureIDs []uuid.UUID, binSizeNs int64) (string, error) {
	sub, args, err := q.root.subquery(t, captureIDs)
	if err != nil {
		return "", err
	}
	inlinedSub := inlineArgs(sub, args)

	capScope := CaptureScope(captureIDs)
	var capScopeClause string
	if capScope != "" {
		capScopeClause = " " + capScope
	}

	sql := fmt.Sprintf(
		`SELECT
    intDiv(toInt64(toUnixTimestamp64Nano(cap.created_at)) + toInt64(p.ts), %d) * %d AS bin_start_ns,
    count() AS count
FROM %s AS p FINAL
INNER JOIN (SELECT capture_id, created_at FROM %s FINAL%s) cap ON p.capture_id = cap.capture_id
WHERE (p.capture_id, p.packet_id) IN (
%s
)
GROUP BY bin_start_ns
ORDER BY bin_start_ns ASC`,
		binSizeNs, binSizeNs,
		t.Packets, t.Captures, capScopeClause,
		inlinedSub,
	)
	return sql, nil
}

// SearchSQL generates the SQL used by the JSON search API. Unlike SQL, it
// selects a clean set of metadata columns (capture_id, packet_id,
// timestamp_ns, incl_len, orig_len) plus requested component fields, and
// orders results by capture then time. All bind parameters are inlined.
// When captureIDs is nil or empty, the query covers all captures.
func (q Query) SearchSQL(t Tables, captureIDs []uuid.UUID, comps []string, limit, offset int) (string, error) {
	for _, comp := range comps {
		if _, ok := t.Components[comp]; !ok {
			return "", fmt.Errorf("unknown component %q", comp)
		}
	}

	sub, args, err := q.root.subquery(t, captureIDs)
	if err != nil {
		return "", err
	}
	inlinedSub := inlineArgs(sub, args)

	capScope := CaptureScope(captureIDs)
	var capScopeClause string
	if capScope != "" {
		capScopeClause = " " + capScope
	}

	selectParts := []string{
		"p.capture_id AS capture_id",
		"p.packet_id AS packet_id",
		"toInt64(toUnixTimestamp64Nano(cap.created_at)) + toInt64(p.ts) AS timestamp_ns",
		"p.incl_len AS incl_len",
		"p.incl_len + p.trunc_extra AS orig_len",
		"toUInt64(p.components) AS components",
	}
	for _, comp := range comps {
		info := t.Components[comp]
		selectParts = append(selectParts,
			fmt.Sprintf("%s.* EXCEPT (capture_id, packet_id, codec_version)", info.Alias),
		)
	}

	fromClause := fmt.Sprintf(
		"FROM %s AS p FINAL\nINNER JOIN (SELECT capture_id, created_at FROM %s FINAL%s) cap ON p.capture_id = cap.capture_id",
		t.Packets, t.Captures, capScopeClause,
	)
	var joins []string
	for _, comp := range comps {
		info := t.Components[comp]
		joins = append(joins,
			fmt.Sprintf("LEFT JOIN %s AS %s FINAL ON %s.capture_id = p.capture_id AND %s.packet_id = p.packet_id", info.TableRef, info.Alias, info.Alias, info.Alias),
		)
	}

	var sb strings.Builder
	sb.WriteString("SELECT\n    ")
	sb.WriteString(strings.Join(selectParts, ",\n    "))
	sb.WriteString("\n")
	sb.WriteString(fromClause)
	for _, j := range joins {
		sb.WriteString("\n")
		sb.WriteString(j)
	}
	sb.WriteString("\nWHERE (p.capture_id, p.packet_id) IN (\n")
	sb.WriteString(inlinedSub)
	sb.WriteString("\n)\nORDER BY p.capture_id ASC, timestamp_ns ASC")
	if limit > 0 {
		sb.WriteString(fmt.Sprintf("\nLIMIT %d", limit))
	}
	if offset > 0 {
		sb.WriteString(fmt.Sprintf(" OFFSET %d", offset))
	}

	return sb.String(), nil
}
