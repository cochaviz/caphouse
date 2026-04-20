package caphouse

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cochaviz/caphouse/components"
)

// registryComponents is the set of valid component names, populated from the
// component registry in init so it stays in sync automatically.
var registryComponents map[string]bool

// Precompiled regexes, built in init from the registry.
var (
	// fieldAliasRe matches component.alias = value or component.alias != value for expansion.
	// Groups: 1=component, 2=alias, 3=operator (= or !=), 4=value
	fieldAliasRe *regexp.Regexp

	// betweenAliasRe matches component.alias BETWEEN lo AND hi.
	// Groups: 1=component, 2=alias, 3=lo, 4=hi
	betweenAliasRe *regexp.Regexp

	// inAliasRe matches component.alias IN (...).
	// Groups: 1=component, 2=alias, 3=list contents
	inAliasRe *regexp.Regexp

	// funcAliasRe matches func(component.alias, ...) where the alias is the first argument.
	// Groups: 1=function name, 2=component, 3=alias, 4=remaining arguments (after the comma)
	funcAliasRe *regexp.Regexp

	// componentDotRe extracts "component." prefixes from the clause.
	componentDotRe *regexp.Regexp

	// bareComponentRe matches standalone component names (no dot context checked separately).
	bareComponentRe *regexp.Regexp

	// componentBits maps component name → its bit in the p.components bitmask.
	componentBits map[string]uint64

	// packetDotRe rewrites "packet." → "p." so callers can reference pcap_packets
	// columns (e.g. packet.payload, packet.ts) without knowing the SQL alias.
	packetDotRe = regexp.MustCompile(`\bpacket\.`)

	// captureSensorRe matches capture.sensor (which lives in pcap_captures, not
	// pcap_packets) so it can be rewritten to the SQL alias before execution.
	// The table is aliased as "captures" to match the naming convention used for
	// component tables (ipv4, tcp, dns, …).
	captureSensorRe = regexp.MustCompile(`\bcapture\.sensor\b`)
)

func init() {
	// Build registry set, name list, and bitmask map.
	registryComponents = make(map[string]bool, len(components.KnownComponentKinds))
	componentBits = make(map[string]uint64, len(components.KnownComponentKinds))
	names := make([]string, 0, len(components.KnownComponentKinds))
	for _, kind := range components.KnownComponentKinds {
		name := components.ComponentFactories[kind]().Name()
		registryComponents[name] = true
		componentBits[name] = uint64(1) << kind
		names = append(names, name)
	}

	// Sort longest-first so the regex engine prefers the longer match (e.g.
	// ipv6_ext before ipv6, linuxsll before any shorter name).
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}
		return names[i] < names[j]
	})
	alt := strings.Join(names, "|")

	componentDotRe = regexp.MustCompile(`\b(` + alt + `)\.`)
	bareComponentRe = regexp.MustCompile(`\b(` + alt + `)\b`)

	// Field alias regexes only cover components that have entries in
	// fieldAliasExpansions. Derive the alternation from that map's keys.
	faSet := make(map[string]bool)
	for key := range fieldAliasExpansions {
		faSet[key[:strings.Index(key, ".")]] = true
	}
	faNames := make([]string, 0, len(faSet))
	for c := range faSet {
		faNames = append(faNames, c)
	}
	sort.Strings(faNames)
	fa := strings.Join(faNames, "|")

	fieldAliasRe = regexp.MustCompile(
		`\b(` + fa + `)\.(addr|port|mac|ip)\s*(!=|=)\s*('[^']*'|[^\s)]+)`,
	)
	betweenAliasRe = regexp.MustCompile(
		`(?i)\b(` + fa + `)\.(addr|port|mac|ip)\s+between\s+('[^']*'|[^\s]+)\s+and\s+('[^']*'|[^\s]+)`,
	)
	inAliasRe = regexp.MustCompile(
		`(?i)\b(` + fa + `)\.(addr|port|mac|ip)\s+in\s+\(([^)]+)\)`,
	)
	funcAliasRe = regexp.MustCompile(
		`(?i)\b(\w+)\(\s*(` + fa + `)\.(addr|port|mac|ip)\s*,\s*([^)]*)\)`,
	)
}

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

// PacketRef identifies a single packet within a session.
type PacketRef struct {
	SessionID uint64
	PacketID  uint32
}

// BreakdownField describes a resolved GROUP BY expression for histogram breakdowns.
type BreakdownField struct {
	Component string // component alias to JOIN (e.g. "ipv4")
	SQLExpr   string // SQL expression for GROUP BY (e.g. "ipv4.src" or "arrayJoin([ipv4.src, ipv4.dst])")
}

// ParseBreakdownFields parses a comma-separated list of field expressions
// (e.g. "ipv4.src, tcp.dst") into a slice of BreakdownFields.
// Returns an error if any individual field is invalid.
func ParseBreakdownFields(input string) ([]BreakdownField, error) {
	parts := strings.Split(input, ",")
	fields := make([]BreakdownField, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		bf, err := ParseBreakdownField(p)
		if err != nil {
			return nil, err
		}
		fields = append(fields, bf)
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("no valid breakdown fields provided")
	}
	return fields, nil
}

// ParseBreakdownField parses a single field expression like "ipv4.src" or "ipv4.addr"
// into a BreakdownField ready for use in CountsSQL. Alias fields (addr, port, mac, ip)
// expand to arrayJoin expressions that emit one row per address/port per packet.
// Returns an error for unknown components or missing dots.
// The special "proto" keyword is not handled here; use ParseBreakdownSpec on the
// caphouse.Client, which resolves it dynamically from the component registry.
func ParseBreakdownField(field string) (BreakdownField, error) {
	field = strings.TrimSpace(field)
	dotIdx := strings.Index(field, ".")
	if dotIdx < 0 {
		return BreakdownField{}, fmt.Errorf("breakdown field must be in component.field format (e.g. ipv4.src), got %q", field)
	}
	comp := field[:dotIdx]
	attr := field[dotIdx+1:]
	if !registryComponents[comp] {
		return BreakdownField{}, fmt.Errorf("unknown component %q in breakdown field", comp)
	}
	// Check alias expansion
	if fields, ok := fieldAliasExpansions[comp+"."+attr]; ok {
		return BreakdownField{
			Component: comp,
			SQLExpr:   fmt.Sprintf("arrayJoin([%s.%s, %s.%s])", comp, fields[0], comp, fields[1]),
		}, nil
	}
	return BreakdownField{
		Component: comp,
		SQLExpr:   comp + "." + attr,
	}, nil
}

// Filter wraps a raw ClickHouse WHERE clause. Component tables referenced as
// "component.field" or as bare component names are detected and INNER JOINed
// automatically when the filter is executed.
type Filter struct {
	// Clause is the processed WHERE clause ready for embedding in SQL.
	Clause string

	// components is the sorted, deduplicated list of component names referenced.
	components []string

	// captures is true when the filter references capture.sensor, requiring a
	// JOIN with pcap_captures AS cap.
	captures bool
}

// Components returns the sorted list of component table aliases referenced by
// this filter. These are the tables that will be INNER JOINed when executing.
func (f Filter) Components() []string { return f.components }

// Parse parses a raw ClickHouse WHERE clause and prepares it for execution.
// It expands field aliases (ipv4.addr, udp.port, etc.) and detects which
// component tables must be INNER JOINed.
//
// An empty clause is valid and selects all packets (subject to sessionIDs).
func Parse(clause string) (Filter, error) {
	// Rewrite "capture.sensor" → "cap.sensor" before the generic packet. pass,
	// since sensor lives in pcap_captures (aliased as "cap"), not pcap_packets.
	needsCaptures := captureSensorRe.MatchString(clause)
	expanded := captureSensorRe.ReplaceAllString(clause, "captures.sensor")

	// Rewrite "packet." → "p." so callers can use packet.payload, packet.ts, etc.
	expanded = packetDotRe.ReplaceAllString(expanded, "p.")

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
		if !registryComponents[c] {
			return Filter{}, fmt.Errorf("unknown component %q in filter", c)
		}
	}

	comps := make([]string, 0, len(compSet))
	for c := range compSet {
		comps = append(comps, c)
	}
	sort.Strings(comps)

	return Filter{
		Clause:     strings.TrimSpace(expanded),
		components: comps,
		captures:   needsCaptures,
	}, nil
}

// IDsSQL returns a SQL SELECT (session_id, packet_id) fragment that can be
// used as a subquery or executed directly as a streaming cursor.
//
// When limit > 0 the query includes ORDER BY ts and LIMIT/OFFSET, producing a
// paginated set (viewing mode). When limit == 0 there is no LIMIT clause and
// the caller is responsible for ordering (streaming/export mode).
//
// fromNs and toNs are optional Unix-nanosecond time bounds (0 = unset).
// asc controls the ORDER BY direction; ignored when limit == 0.
//
// cursor enables keyset pagination: when non-zero the query adds a
// (p.ts, p.session_id, p.packet_id) > (cursor.Ts, cursor.SessionID, cursor.PacketID)
// WHERE condition instead of OFFSET, so each page is O(log N) rather than O(N).
func (f Filter) IDsSQL(
	tableRef func(string) string,
	packets string,
	sessionIDs []uint64,
	limit, offset int,
	fromNs, toNs int64,
	asc bool,
	cursor *exportCursor,
) (string, error) {
	if err := f.validateComponents(); err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString("SELECT p.session_id, p.packet_id\nFROM ")
	sb.WriteString(packets)
	sb.WriteString(" AS p")

	for _, comp := range f.components {
		sb.WriteString("\nINNER JOIN ")
		sb.WriteString(tableRef("pcap_" + comp))
		sb.WriteString(" AS ")
		sb.WriteString(comp)
		sb.WriteString(" USING (session_id, packet_id)")
	}
	if f.captures {
		sb.WriteString("\nINNER JOIN ")
		sb.WriteString(tableRef("pcap_captures"))
		sb.WriteString(" AS captures USING (session_id)")
	}

	var conditions []string
	if len(sessionIDs) > 0 {
		conditions = append(conditions, "p."+sessionInSQL(sessionIDs))
	}
	if f.Clause != "" {
		conditions = append(conditions, f.Clause)
	}
	if fromNs != 0 || toNs != 0 {
		conditions = append(conditions, fmt.Sprintf("p.ts BETWEEN %d AND %d", fromNs, toNs))
	}
	if cursor != nil {
		conditions = append(conditions, fmt.Sprintf(
			"(p.ts, p.session_id, p.packet_id) > (%d, %d, %d)",
			cursor.Ts, cursor.SessionID, cursor.PacketID))
	}
	if len(conditions) > 0 {
		sb.WriteString("\nWHERE ")
		sb.WriteString(strings.Join(conditions, " AND "))
	}
	if limit > 0 {
		if asc {
			sb.WriteString("\nORDER BY p.ts ASC, p.session_id ASC, p.packet_id ASC")
		} else {
			sb.WriteString("\nORDER BY p.ts DESC, p.session_id DESC, p.packet_id DESC")
		}
	}
	sb.WriteString("\nLIMIT 1 BY p.session_id, p.packet_id")
	if limit > 0 {
		sb.WriteString(fmt.Sprintf("\nLIMIT %d", limit))
		if cursor == nil && offset > 0 {
			sb.WriteString(fmt.Sprintf(" OFFSET %d", offset))
		}
	}

	return sb.String(), nil
}

// SQL generates a full SELECT statement equivalent to this filter, with bind
// parameters inlined. It selects p.* from pcap_packets plus any requested
// component columns via LEFT JOIN.
func (f Filter) SQL(tableRef func(string) string, packets string, sessionIDs []uint64, comps []string) (string, error) {
	if err := f.validateComponents(); err != nil {
		return "", err
	}
	for _, comp := range comps {
		if !registryComponents[comp] {
			return "", fmt.Errorf("unknown component %q", comp)
		}
	}

	sub, err := f.IDsSQL(tableRef, packets, sessionIDs, 0, 0, 0, 0, false, nil)
	if err != nil {
		return "", err
	}

	selectParts := []string{"p.*"}
	for _, comp := range comps {
		selectParts = append(selectParts,
			fmt.Sprintf("%s.* EXCEPT (session_id, packet_id, codec_version)", comp),
		)
	}

	fromClause := fmt.Sprintf("FROM %s AS p", packets)
	var joins []string
	for _, comp := range comps {
		joins = append(joins,
			fmt.Sprintf("LEFT JOIN %s AS %s USING (session_id, packet_id)", tableRef("pcap_"+comp), comp),
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
	sb.WriteString("\nWHERE (p.session_id, p.packet_id) IN (\n")
	sb.WriteString(sub)
	sb.WriteString("\n)")
	sb.WriteString("\nLIMIT 1 BY p.session_id, p.packet_id")
	return sb.String(), nil
}

// CountsSQL generates the SQL for a packet-count histogram.
// fromNs and toNs are optional Unix-nanosecond bounds (0 = unset).
// tzOffsetNs is the client's UTC offset in nanoseconds (e.g. 7200e9 for UTC+2),
// used to align bins to local midnight rather than UTC midnight.
//
// The query is a flat GROUP BY directly over pcap_packets, with no subquery.
// When the filter clause is empty, no JOINs are added and ClickHouse only reads
// the ts column — the leading ORDER BY key — enabling a fast sparse-index range
// scan. LIMIT 1 BY is omitted: for a histogram, approximate counts during the
// brief pre-merge window of ReplacingMergeTree are acceptable.
func (f Filter) CountsSQL(tableRef func(string) string, packets string, sessionIDs []uint64, binSizeNs int64, fromNs, toNs int64, tzOffsetNs int64, breakdown []BreakdownField) (string, error) {
	if err := f.validateComponents(); err != nil {
		return "", err
	}

	binExpr := fmt.Sprintf("intDiv(p.ts + %d, %d) * %d - %d", tzOffsetNs, binSizeNs, binSizeNs, tzOffsetNs)

	var sb strings.Builder
	if len(breakdown) > 0 {
		var bdExpr string
		if len(breakdown) == 1 {
			bdExpr = fmt.Sprintf("toString(%s)", breakdown[0].SQLExpr)
		} else {
			parts := make([]string, len(breakdown))
			for i, bf := range breakdown {
				parts[i] = fmt.Sprintf("toString(%s)", bf.SQLExpr)
			}
			bdExpr = "concat(" + strings.Join(parts, ", ' / ', ") + ")"
		}
		sb.WriteString(fmt.Sprintf(
			"SELECT %s AS bin_start_ns, %s AS breakdown_value, count() AS count",
			binExpr, bdExpr,
		))
	} else {
		sb.WriteString(fmt.Sprintf(
			"SELECT %s AS bin_start_ns, count() AS count",
			binExpr,
		))
	}
	sb.WriteString(fmt.Sprintf("\nFROM %s AS p", packets))

	// Build sorted, deduplicated component list for JOINs.
	compSet := make(map[string]bool)
	for _, c := range f.components {
		compSet[c] = true
	}
	for _, bf := range breakdown {
		if bf.Component != "" {
			compSet[bf.Component] = true
		}
	}
	joinComps := make([]string, 0, len(compSet))
	for c := range compSet {
		joinComps = append(joinComps, c)
	}
	sort.Strings(joinComps)

	for _, comp := range joinComps {
		sb.WriteString("\nINNER JOIN ")
		sb.WriteString(tableRef("pcap_" + comp))
		sb.WriteString(" AS ")
		sb.WriteString(comp)
		sb.WriteString(" USING (session_id, packet_id)")
	}
	if f.captures {
		sb.WriteString("\nINNER JOIN ")
		sb.WriteString(tableRef("pcap_captures"))
		sb.WriteString(" AS captures USING (session_id)")
	}

	var conditions []string
	if len(sessionIDs) > 0 {
		conditions = append(conditions, "p."+sessionInSQL(sessionIDs))
	}
	if f.Clause != "" {
		conditions = append(conditions, f.Clause)
	}
	if fromNs != 0 || toNs != 0 {
		conditions = append(conditions, fmt.Sprintf("p.ts BETWEEN %d AND %d", fromNs, toNs))
	}
	if len(conditions) > 0 {
		sb.WriteString("\nWHERE ")
		sb.WriteString(strings.Join(conditions, " AND "))
	}
	if len(breakdown) > 0 {
		sb.WriteString("\nGROUP BY bin_start_ns, breakdown_value\nORDER BY bin_start_ns ASC")
	} else {
		sb.WriteString("\nGROUP BY bin_start_ns\nORDER BY bin_start_ns ASC")
	}
	return sb.String(), nil
}

// validateComponents checks that all components referenced by this filter are in the registry.
func (f Filter) validateComponents() error {
	for _, comp := range f.components {
		if !registryComponents[comp] {
			return fmt.Errorf("component %q is not available in this context", comp)
		}
	}
	return nil
}

// sessionInSQL returns a SQL IN predicate with session IDs inlined as integers.
func sessionInSQL(ids []uint64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d", id)
	}
	return "session_id IN (" + strings.Join(parts, ",") + ")"
}

// expandFieldAliases rewrites field alias patterns (=, BETWEEN, IN) so that
// "component.alias op ..." expands to "(component.field1 op ... or component.field2 op ...)".
func expandFieldAliases(clause string) string {
	// = value  or  != value
	clause = fieldAliasRe.ReplaceAllStringFunc(clause, func(match string) string {
		parts := fieldAliasRe.FindStringSubmatch(match)
		if len(parts) < 5 {
			return match
		}
		comp, alias, op, val := parts[1], parts[2], parts[3], parts[4]
		fields, ok := fieldAliasExpansions[comp+"."+alias]
		if !ok {
			return match
		}
		// = expands with OR (matches either src or dst)
		// != expands with AND (neither src nor dst matches)
		join := "or"
		if op == "!=" {
			join = "and"
		}
		return fmt.Sprintf("(%s.%s %s %s %s %s.%s %s %s)",
			comp, fields[0], op, val, join, comp, fields[1], op, val)
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

	// func(component.alias, args) — alias as first function argument
	clause = funcAliasRe.ReplaceAllStringFunc(clause, func(match string) string {
		parts := funcAliasRe.FindStringSubmatch(match)
		if len(parts) < 5 {
			return match
		}
		fn, comp, alias, args := parts[1], parts[2], parts[3], parts[4]
		fields, ok := fieldAliasExpansions[comp+"."+alias]
		if !ok {
			return match
		}
		return fmt.Sprintf("(%s(%s.%s, %s) or %s(%s.%s, %s))",
			fn, comp, fields[0], args, fn, comp, fields[1], args)
	})

	return clause
}

// extractBareComponents finds standalone component names (not followed by '.') and
// replaces each with a bitmask presence check on p.components, e.g.
// "tcp" → "bitAnd(toUInt64(p.components), 512) != 0".
// This allows bare names to be combined with OR without requiring an INNER JOIN.
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
		bit := componentBits[name]
		sb.WriteString(clause[prev:start])
		sb.WriteString(fmt.Sprintf("bitAnd(toUInt64(p.components), %d) != 0", bit))
		prev = end
	}
	sb.WriteString(clause[prev:])
	return sb.String()
}
