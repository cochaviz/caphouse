// Package query provides a raw-SQL WHERE clause query type for filtering
// network packet captures stored in ClickHouse.
//
// Users write standard ClickHouse SQL predicates referencing component tables
// by name (e.g. ipv4.dst = '1.1.1.1', tcp.src = 80). The package detects
// which component tables are needed and INNER JOINs them automatically.
//
// # Query syntax
//
// A query is a raw ClickHouse WHERE clause body. Component tables are
// referenced as "component.field", e.g.:
//
//	ipv4.dst = '1.1.1.1' and udp.dst = 53
//	tcp.flags & 2 != 0
//	dns
//
// A bare component name (no dot) is a presence check: packets are filtered
// to those that have that component (via INNER JOIN with no extra condition).
//
// # Aliases
//
// Short component name: eth → ethernet
//
// Field aliases that expand to src/dst pairs (= operator only):
//
//	ipv4.addr    → (ipv4.src = val OR ipv4.dst = val)
//	ipv6.addr    → (ipv6.src = val OR ipv6.dst = val)
//	tcp.port     → (tcp.src = val OR tcp.dst = val)
//	udp.port     → (udp.src = val OR udp.dst = val)
//	ethernet.mac → (ethernet.src = val OR ethernet.dst = val)
package query

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// knownComponents is the set of valid component table aliases (pcap_ prefix stripped).
var knownComponents = map[string]bool{
	"ethernet": true,
	"dot1q":    true,
	"linuxsll": true,
	"ipv4":     true,
	"ipv6":     true,
	"ipv6_ext": true,
	"tcp":      true,
	"udp":      true,
	"dns":      true,
	"ntp":      true,
	"arp":      true,
}

// componentShortNames maps short aliases to canonical component names.
var componentShortNames = map[string]string{
	"eth": "ethernet",
}

// knownComponentList is the sorted list of canonical component names,
// used in regex alternations. Must be longest-first to avoid partial matches.
var knownComponentList = []string{
	"ethernet", "linuxsll", "ipv6_ext", "dot1q", "ipv6", "ipv4",
	"tcp", "udp", "dns", "ntp", "arp",
}

// Precompiled regexes.
var (
	// ethDotRe rewrites "eth." → "ethernet."
	ethDotRe = regexp.MustCompile(`\beth\.`)
	// ethBareRe rewrites bare "eth" → "ethernet" (not followed by dot or word char)
	ethBareRe = regexp.MustCompile(`\beth\b`)

	// fieldAliasRe matches component.alias = value for expansion.
	// Groups: 1=component, 2=alias, 3=value
	fieldAliasRe = regexp.MustCompile(
		`\b(ethernet|ipv4|ipv6|tcp|udp|arp)\.(addr|port|mac|ip)\s*=\s*('[^']*'|[^\s)]+)`,
	)

	// betweenAliasRe matches component.alias BETWEEN lo AND hi.
	// Groups: 1=component, 2=alias, 3=lo, 4=hi
	betweenAliasRe = regexp.MustCompile(
		`(?i)\b(ethernet|ipv4|ipv6|tcp|udp|arp)\.(addr|port|mac|ip)\s+between\s+('[^']*'|[^\s]+)\s+and\s+('[^']*'|[^\s]+)`,
	)

	// inAliasRe matches component.alias IN (...).
	// Groups: 1=component, 2=alias, 3=list contents
	inAliasRe = regexp.MustCompile(
		`(?i)\b(ethernet|ipv4|ipv6|tcp|udp|arp)\.(addr|port|mac|ip)\s+in\s+\(([^)]+)\)`,
	)

	// componentDotRe extracts "component." prefixes from the clause.
	componentDotRe = regexp.MustCompile(
		`\b(ethernet|dot1q|linuxsll|ipv4|ipv6_ext|ipv6|tcp|udp|dns|ntp|arp)\.`,
	)

	// bareComponentRe matches standalone component names (no dot context checked separately).
	bareComponentRe = regexp.MustCompile(
		`\b(ethernet|dot1q|linuxsll|ipv4|ipv6_ext|ipv6|tcp|udp|dns|ntp|arp)\b`,
	)
)

// fieldAliasExpansions maps "component.alias" to the two fields it expands to.
var fieldAliasExpansions = map[string][2]string{
	"ipv4.addr":    {"src", "dst"},
	"ipv6.addr":    {"src", "dst"},
	"tcp.port":     {"src", "dst"},
	"udp.port":     {"src", "dst"},
	"ethernet.mac": {"src", "dst"},
	"arp.ip":       {"sender_ip", "target_ip"},
	"arp.mac":      {"sender_mac", "target_mac"},
}

// PacketRef identifies a single packet within a capture.
type PacketRef struct {
	CaptureID uuid.UUID
	PacketID  uint64
}

// Query wraps a raw ClickHouse WHERE clause. Component tables referenced as
// "component.field" or as bare component names are detected and INNER JOINed
// automatically when the query is executed.
type Query struct {
	// Clause is the processed WHERE clause ready for embedding in SQL.
	Clause string

	// components is the sorted, deduplicated list of component names referenced.
	components []string
}

// Components returns the sorted list of component table aliases referenced by
// this query. These are the tables that will be INNER JOINed when executing.
func (q Query) Components() []string { return q.components }

// ParseQuery parses a raw ClickHouse WHERE clause and prepares it for
// execution. It applies component name aliases (eth→ethernet), expands field
// aliases (ipv4.addr, udp.port, etc.), and detects which component tables
// must be INNER JOINed.
//
// An empty clause is valid and selects all packets (subject to captureIDs).
func ParseQuery(clause string) (Query, error) {
	// Apply short name aliases (eth → ethernet).
	expanded := ethDotRe.ReplaceAllString(clause, "ethernet.")
	expanded = ethBareRe.ReplaceAllString(expanded, "ethernet")

	// Expand field aliases (e.g., ipv4.addr = '1.1.1.1').
	expanded = expandFieldAliases(expanded)

	// Collect components from "component." prefixes.
	compSet := make(map[string]bool)
	for _, m := range componentDotRe.FindAllStringSubmatch(expanded, -1) {
		compSet[m[1]] = true
	}

	// Collect and remove bare component names (presence checks).
	expanded = extractBareComponents(expanded, compSet)

	// Validate.
	for c := range compSet {
		if !knownComponents[c] {
			return Query{}, fmt.Errorf("unknown component %q in query", c)
		}
	}

	components := make([]string, 0, len(compSet))
	for c := range compSet {
		components = append(components, c)
	}
	sort.Strings(components)

	return Query{
		Clause:     strings.TrimSpace(expanded),
		components: components,
	}, nil
}

// Subquery returns a SQL fragment selecting (capture_id, packet_id) rows that
// match this query. It can be embedded in a larger query via IN (...).
func (q Query) Subquery(t Tables, captureIDs []uuid.UUID) (string, []any, error) {
	if err := q.validateComponents(t); err != nil {
		return "", nil, err
	}

	var sb strings.Builder
	sb.WriteString("SELECT p.capture_id, p.packet_id\nFROM ")
	sb.WriteString(t.Packets)
	sb.WriteString(" AS p FINAL")

	for _, comp := range q.components {
		info := t.Components[comp]
		sb.WriteString("\nINNER JOIN ")
		sb.WriteString(info.TableRef)
		sb.WriteString(" AS ")
		sb.WriteString(info.Alias)
		sb.WriteString(" FINAL USING (capture_id, packet_id)")
	}

	var conditions []string
	if len(captureIDs) > 0 {
		conditions = append(conditions, "p."+CaptureInSQL(captureIDs))
	}
	if q.Clause != "" {
		conditions = append(conditions, q.Clause)
	}
	if len(conditions) > 0 {
		sb.WriteString("\nWHERE ")
		sb.WriteString(strings.Join(conditions, " AND "))
	}

	return sb.String(), nil, nil
}

// SQL generates a full SELECT statement equivalent to this filter, with bind
// parameters inlined. It selects p.* from pcap_packets plus any requested
// component columns via LEFT JOIN.
func (q Query) SQL(t Tables, captureIDs []uuid.UUID, comps []string) (string, error) {
	if err := q.validateComponents(t); err != nil {
		return "", err
	}
	for _, comp := range comps {
		if _, ok := t.Components[comp]; !ok {
			return "", fmt.Errorf("unknown component %q", comp)
		}
	}

	sub, _, err := q.Subquery(t, captureIDs)
	if err != nil {
		return "", err
	}

	selectParts := []string{"p.*"}
	for _, comp := range comps {
		info := t.Components[comp]
		selectParts = append(selectParts,
			fmt.Sprintf("%s.* EXCEPT (capture_id, packet_id, codec_version)", info.Alias),
		)
	}

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
	sb.WriteString(sub)
	sb.WriteString("\n)")
	return sb.String(), nil
}

// absTimeExpr is the ClickHouse expression for the absolute packet timestamp
// in nanoseconds, referencing the "cap" captures alias already in scope.
const absTimeExpr = "toInt64(toUnixTimestamp64Nano(cap.created_at)) + toInt64(p.ts)"

// SearchSQL generates the SQL used by the JSON search API.
// fromNs and toNs are optional Unix-nanosecond bounds on the absolute packet
// timestamp (0 = unset). When set, only packets within [fromNs, toNs] are returned.
func (q Query) SearchSQL(t Tables, captureIDs []uuid.UUID, comps []string, limit, offset int, fromNs, toNs int64) (string, error) {
	if err := q.validateComponents(t); err != nil {
		return "", err
	}
	for _, comp := range comps {
		if _, ok := t.Components[comp]; !ok {
			return "", fmt.Errorf("unknown component %q", comp)
		}
	}

	sub, _, err := q.Subquery(t, captureIDs)
	if err != nil {
		return "", err
	}

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
		selectParts = append(selectParts, info.Columns...)
	}

	fromClause := fmt.Sprintf(
		"FROM %s AS p FINAL\nINNER JOIN (SELECT capture_id, created_at FROM %s FINAL%s) cap ON p.capture_id = cap.capture_id",
		t.Packets, t.Captures, capScopeClause,
	)
	var joins []string
	for _, comp := range comps {
		info := t.Components[comp]
		joins = append(joins,
			fmt.Sprintf("LEFT JOIN %s AS %s FINAL ON %s.capture_id = p.capture_id AND %s.packet_id = p.packet_id",
				info.TableRef, info.Alias, info.Alias, info.Alias),
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
	sb.WriteString(sub)
	sb.WriteString("\n)")
	if fromNs != 0 || toNs != 0 {
		sb.WriteString(fmt.Sprintf("\nAND %s BETWEEN %d AND %d", absTimeExpr, fromNs, toNs))
	}
	sb.WriteString("\nORDER BY p.capture_id ASC, timestamp_ns ASC")
	if limit > 0 {
		sb.WriteString(fmt.Sprintf("\nLIMIT %d", limit))
	}
	if offset > 0 {
		sb.WriteString(fmt.Sprintf(" OFFSET %d", offset))
	}
	return sb.String(), nil
}

// CountsSQL generates the SQL for a packet-count histogram.
// fromNs and toNs are optional Unix-nanosecond bounds (0 = unset).
// tzOffsetNs is the client's UTC offset in nanoseconds (e.g. 7200e9 for UTC+2),
// used to align bins to local midnight rather than UTC midnight.
func (q Query) CountsSQL(t Tables, captureIDs []uuid.UUID, binSizeNs int64, fromNs, toNs int64, tzOffsetNs int64) (string, error) {
	if err := q.validateComponents(t); err != nil {
		return "", err
	}

	sub, _, err := q.Subquery(t, captureIDs)
	if err != nil {
		return "", err
	}

	capScope := CaptureScope(captureIDs)
	var capScopeClause string
	if capScope != "" {
		capScopeClause = " " + capScope
	}

	var timeFilter string
	if fromNs != 0 || toNs != 0 {
		timeFilter = fmt.Sprintf("\nAND %s BETWEEN %d AND %d", absTimeExpr, fromNs, toNs)
	}

	sql := fmt.Sprintf(
		`SELECT
    intDiv(toInt64(toUnixTimestamp64Nano(cap.created_at)) + toInt64(p.ts) + %d, %d) * %d - %d AS bin_start_ns,
    count() AS count
FROM %s AS p FINAL
INNER JOIN (SELECT capture_id, created_at FROM %s FINAL%s) cap ON p.capture_id = cap.capture_id
WHERE (p.capture_id, p.packet_id) IN (
%s
)%s
GROUP BY bin_start_ns
ORDER BY bin_start_ns ASC`,
		tzOffsetNs, binSizeNs, binSizeNs, tzOffsetNs,
		t.Packets, t.Captures, capScopeClause,
		sub, timeFilter,
	)
	return sql, nil
}

// validateComponents checks that all components referenced are present in Tables.
func (q Query) validateComponents(t Tables) error {
	for _, comp := range q.components {
		if _, ok := t.Components[comp]; !ok {
			return fmt.Errorf("component %q is not available in this context", comp)
		}
	}
	return nil
}

// expandFieldAliases rewrites field alias patterns (=, BETWEEN, IN) so that
// "component.alias op ..." expands to "(component.field1 op ... or component.field2 op ...)".
func expandFieldAliases(clause string) string {
	// = value
	clause = fieldAliasRe.ReplaceAllStringFunc(clause, func(match string) string {
		parts := fieldAliasRe.FindStringSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		comp, alias, val := parts[1], parts[2], parts[3]
		fields, ok := fieldAliasExpansions[comp+"."+alias]
		if !ok {
			return match
		}
		return fmt.Sprintf("(%s.%s = %s or %s.%s = %s)",
			comp, fields[0], val, comp, fields[1], val)
	})

	// BETWEEN lo AND hi
	clause = betweenAliasRe.ReplaceAllStringFunc(clause, func(match string) string {
		parts := betweenAliasRe.FindStringSubmatch(match)
		if len(parts) < 5 {
			return match
		}
		comp, alias, lo, hi := parts[1], parts[2], parts[3], parts[4]
		fields, ok := fieldAliasExpansions[comp+"."+alias]
		if !ok {
			return match
		}
		return fmt.Sprintf("(%s.%s between %s and %s or %s.%s between %s and %s)",
			comp, fields[0], lo, hi, comp, fields[1], lo, hi)
	})

	// IN (list)
	clause = inAliasRe.ReplaceAllStringFunc(clause, func(match string) string {
		parts := inAliasRe.FindStringSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		comp, alias, list := parts[1], parts[2], parts[3]
		fields, ok := fieldAliasExpansions[comp+"."+alias]
		if !ok {
			return match
		}
		return fmt.Sprintf("(%s.%s in (%s) or %s.%s in (%s))",
			comp, fields[0], list, comp, fields[1], list)
	})

	return clause
}

// extractBareComponents finds standalone component names (not followed by '.'),
// adds them to compSet, and replaces them in the clause with "1 = 1".
func extractBareComponents(clause string, compSet map[string]bool) string {
	locs := bareComponentRe.FindAllStringIndex(clause, -1)
	if len(locs) == 0 {
		return clause
	}

	var sb strings.Builder
	prev := 0
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		// If immediately followed by '.', it's a component.field ref — keep as-is.
		if end < len(clause) && clause[end] == '.' {
			sb.WriteString(clause[prev:end])
			prev = end
			continue
		}
		name := clause[start:end]
		compSet[name] = true
		sb.WriteString(clause[prev:start])
		sb.WriteString("1 = 1")
		prev = end
	}
	sb.WriteString(clause[prev:])
	return sb.String()
}
