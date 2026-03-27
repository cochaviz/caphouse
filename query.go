package caphouse

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"caphouse/components"
)

// queryJSON executes a raw SQL string and returns all rows as JSON-serialisable maps.
func (c *Client) queryJSON(ctx context.Context, sql string) ([]map[string]any, error) {
	rows, err := c.conn.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := rows.Columns()
	colTypes := rows.ColumnTypes()
	var result []map[string]any
	for rows.Next() {
		ptrs := make([]any, len(colTypes))
		for i, ct := range colTypes {
			ptrs[i] = reflect.New(ct.ScanType()).Interface()
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			v := reflect.ValueOf(ptrs[i]).Elem().Interface()
			switch tv := v.(type) {
			case uint64:
				// Serialize as string to avoid JS precision loss for values > 2^53.
				row[col] = strconv.FormatUint(tv, 10)
			case string:
				// FixedString columns (e.g. MAC addresses) are raw bytes — encode as hex.
				if strings.HasPrefix(colTypes[i].DatabaseTypeName(), "FixedString") {
					row[col] = hex.EncodeToString([]byte(tv))
				} else {
					row[col] = tv
				}
			default:
				row[col] = v
			}
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// searchSQL builds the two-phase SQL used by QueryJSON: an inner IDsSQL subquery
// for pagination, wrapped in an outer SELECT with LEFT JOINs for display columns.
func (c *Client) searchSQL(f Filter, sessionIDs []uint64, comps []string, limit, offset int, fromNs, toNs int64, asc bool) (string, error) {
	for _, comp := range comps {
		if !registryComponents[comp] {
			return "", fmt.Errorf("unknown component %q", comp)
		}
	}

	idSQL, err := f.IDsSQL(c.tableRef, c.packetsTable(), sessionIDs, limit, offset, fromNs, toNs, asc)
	if err != nil {
		return "", err
	}

	selectParts := []string{
		"p.session_id AS session_id",
		"p.packet_id AS packet_id",
		"p.ts AS timestamp_ns",
		"p.incl_len AS incl_len",
		"p.incl_len + p.trunc_extra AS orig_len",
		"toUInt64(p.components) AS components",
	}
	for _, comp := range comps {
		proto := componentByName(comp)
		cols, _ := proto.DataColumns(comp)
		selectParts = append(selectParts, cols...)
	}
	var joins []string
	for _, comp := range comps {
		tableRef := c.tableRef("pcap_" + comp)
		joins = append(joins,
			fmt.Sprintf("LEFT JOIN %s AS %s ON %s.session_id = p.session_id AND %s.packet_id = p.packet_id",
				tableRef, comp, comp, comp),
		)
	}

	var sb strings.Builder
	sb.WriteString("SELECT\n    ")
	sb.WriteString(strings.Join(selectParts, ",\n    "))
	sb.WriteString(fmt.Sprintf("\nFROM %s AS p", c.packetsTable()))
	for _, j := range joins {
		sb.WriteString("\n")
		sb.WriteString(j)
	}
	sb.WriteString("\nWHERE (p.session_id, p.packet_id) IN (\n")
	sb.WriteString(idSQL)
	sb.WriteString("\n)")
	if asc {
		sb.WriteString("\nORDER BY timestamp_ns ASC")
	} else {
		sb.WriteString("\nORDER BY timestamp_ns DESC")
	}
	return sb.String(), nil
}

// QueryJSON executes a search and returns matching packet rows with basic
// metadata and the requested component fields as JSON-serializable maps.
// Each map key is a column name; values are native Go types (string, uint64,
// int64, etc.) that marshal cleanly to JSON.
// When sessionIDs is nil or empty, all sessions are searched.
// fromNs and toNs are optional Unix-nanosecond timestamp bounds (0 = unset).
func (c *Client) QueryJSON(ctx context.Context, sessionIDs []uint64, q Filter, comps []string, limit, offset int, fromNs, toNs int64, asc bool) ([]map[string]any, error) {
	sql, err := c.searchSQL(q, sessionIDs, comps, limit, offset, fromNs, toNs, asc)
	if err != nil {
		return nil, err
	}
	rows, err := c.queryJSON(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("execute search: %w", err)
	}
	return rows, nil
}

// QueryPacketComponents fetches all parsed component fields for a single packet,
// joining every registered component table. Returns nil when the packet is not found.
func (c *Client) QueryPacketComponents(ctx context.Context, sessionID uint64, packetID uint32) (map[string]any, error) {
	selectParts := []string{
		"p.session_id AS session_id",
		"p.packet_id AS packet_id",
		"p.ts AS timestamp_ns",
		"p.incl_len AS incl_len",
		"p.incl_len + p.trunc_extra AS orig_len",
		"toUInt64(p.components) AS components",
		"lower(hex(p.payload)) AS payload",
		"captures.sensor AS sensor",
	}
	joins := []string{
		fmt.Sprintf("LEFT JOIN %s AS captures ON captures.session_id = p.session_id", c.capturesTable()),
	}
	for _, kind := range components.KnownComponentKinds {
		proto := components.ComponentFactories[kind]()
		alias := proto.Name()
		cols, _ := proto.DataColumns(alias)
		selectParts = append(selectParts, cols...)
		joins = append(joins,
			fmt.Sprintf("LEFT JOIN %s AS %s ON %s.session_id = p.session_id AND %s.packet_id = p.packet_id",
				c.tableRef(components.ComponentTable(proto)), alias, alias, alias),
		)
	}

	var sb strings.Builder
	sb.WriteString("SELECT\n    ")
	sb.WriteString(strings.Join(selectParts, ",\n    "))
	fmt.Fprintf(&sb, "\nFROM %s AS p", c.packetsTable())
	for _, j := range joins {
		sb.WriteString("\n")
		sb.WriteString(j)
	}
	fmt.Fprintf(&sb, "\nWHERE p.session_id = %d AND p.packet_id = %d", sessionID, packetID)
	sb.WriteString("\nLIMIT 1")

	rows, err := c.queryJSON(ctx, sb.String())
	if err != nil {
		return nil, fmt.Errorf("execute packet components: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

// QueryPacketFrame reconstructs the original frame bytes for a single packet.
// Returns nil when the packet is not found.
func (c *Client) QueryPacketFrame(ctx context.Context, sessionID uint64, packetID uint32) ([]byte, error) {
	q := fmt.Sprintf(
		"SELECT incl_len, trunc_extra, components, payload FROM %s WHERE session_id = ? AND packet_id = ? LIMIT 1",
		c.packetsTable(),
	)
	row := c.conn.QueryRow(ctx, q, sessionID, packetID)

	var (
		inclLen    uint32
		truncExtra uint32
		payload   string
	)
	componentMask := new(big.Int)
	if err := row.Scan(&inclLen, &truncExtra, componentMask, &payload); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, fmt.Errorf("scan packet frame: %w", err)
	}

	nucleus := components.PacketNucleus{
		SessionID:  sessionID,
		PacketID:   packetID,
		InclLen:    inclLen,
		OrigLen:    inclLen + truncExtra,
		Components: componentMask,
		Payload:    []byte(payload),
	}

	all, err := c.fetchComponentsForBatch(ctx, sessionID, []uint32{packetID})
	if err != nil {
		return nil, fmt.Errorf("fetch components: %w", err)
	}
	componentList, err := resolveComponents(nucleus, all)
	if err != nil {
		return nil, fmt.Errorf("resolve components: %w", err)
	}
	frame, err := reconstructFrame(nucleus, componentList)
	if err != nil {
		return nil, fmt.Errorf("reconstruct frame: %w", err)
	}
	return frame, nil
}

// CountBin holds the packet count for a single time bin.
type CountBin struct {
	// BinStartNs is the Unix nanosecond timestamp of the bin's start.
	BinStartNs int64 `json:"bin_start_ns"`
	// Count is the number of packets in this bin.
	Count uint64 `json:"count"`
}

// BreakdownBin holds the packet count for a single (time bin, breakdown value) pair.
type BreakdownBin struct {
	BinStartNs int64  `json:"bin_start_ns"`
	Value      string `json:"value"`
	Count      uint64 `json:"count"`
}

// QueryCounts executes a packet-count histogram. Packets matched by f are
// bucketed into fixed-width time bins of binSizeSeconds seconds.
// When sessionIDs is nil or empty, all sessions are searched.
// fromNs and toNs are optional Unix-nanosecond timestamp bounds (0 = unset).
func (c *Client) QueryCounts(
	ctx context.Context,
	sessionIDs []uint64,
	f Filter,
	binSizeSeconds int64,
	fromNs, toNs int64,
	tzOffsetSeconds int64,
) ([]CountBin, error) {
	sql, err := f.CountsSQL(
		c.tableRef,
		c.packetsTable(),
		sessionIDs,
		binSizeSeconds*int64(1e9),
		fromNs,
		toNs,
		tzOffsetSeconds*int64(1e9),
		nil,
	)
	if err != nil {
		return nil, err
	}
	rows, err := c.conn.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("execute counts: %w", err)
	}
	defer rows.Close()
	var bins []CountBin
	for rows.Next() {
		var b CountBin
		if err := rows.Scan(&b.BinStartNs, &b.Count); err != nil {
			return nil, fmt.Errorf("scan count bin: %w", err)
		}
		bins = append(bins, b)
	}
	return bins, rows.Err()
}

// QueryCountsBreakdown executes a breakdown histogram. Returns one entry per
// (time bin, breakdown value) pair. When sessionIDs is nil or empty, all sessions
// are searched. fromNs and toNs are optional Unix-nanosecond bounds (0 = unset).
func (c *Client) QueryCountsBreakdown(
	ctx context.Context,
	sessionIDs []uint64,
	f Filter,
	binSizeSeconds int64,
	fromNs, toNs int64,
	tzOffsetSeconds int64,
	breakdown []BreakdownField,
) ([]BreakdownBin, error) {
	sql, err := f.CountsSQL(
		c.tableRef,
		c.packetsTable(),
		sessionIDs,
		binSizeSeconds*int64(1e9),
		fromNs,
		toNs,
		tzOffsetSeconds*int64(1e9),
		breakdown,
	)
	if err != nil {
		return nil, err
	}
	rows, err := c.conn.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("execute breakdown counts: %w", err)
	}
	defer rows.Close()
	var bins []BreakdownBin
	for rows.Next() {
		var b BreakdownBin
		if err := rows.Scan(&b.BinStartNs, &b.Value, &b.Count); err != nil {
			return nil, fmt.Errorf("scan breakdown bin: %w", err)
		}
		bins = append(bins, b)
	}
	return bins, rows.Err()
}

// GenerateSQLForSessions is like GenerateSQL but scoped to multiple sessions.
// When sessionIDs is nil or empty, the generated SQL covers all sessions.
func (c *Client) GenerateSQLForSessions(sessionIDs []uint64, q Filter, comps []string) (string, error) {
	return q.SQL(c.tableRef, c.packetsTable(), sessionIDs, comps)
}

// ParseBreakdownSpec parses a comma-separated breakdown specification into a slice
// of BreakdownFields. It handles the special "proto" keyword by building the SQL
// expression dynamically from the component registry, so adding a new component
// automatically includes it in proto breakdowns.
func (c *Client) ParseBreakdownSpec(spec string) ([]BreakdownField, error) {
	parts := strings.Split(spec, ",")
	fields := make([]BreakdownField, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "proto" {
			fields = append(fields, c.protoBreakdownField())
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

// protoBreakdownField builds a BreakdownField that converts the p.components
// bitmask into a slash-separated protocol string (e.g. "eth/ipv4/tcp").
// The expression is derived from the live component registry so that adding a
// new component automatically updates the proto breakdown.
func (c *Client) protoBreakdownField() BreakdownField {
	parts := make([]string, 0, len(components.KnownComponentKinds))
	for _, kind := range components.KnownComponentKinds {
		comp := components.ComponentFactories[kind]()
		label := comp.Name()
		bitVal := uint64(1) << kind
		parts = append(parts,
			fmt.Sprintf("if(bitAnd(toUInt64(p.components), %d) != 0, '%s', '')", bitVal, label),
		)
	}
	sqlExpr := "arrayStringConcat(arrayFilter(x -> notEmpty(x), [" +
		strings.Join(parts, ", ") + "]), '/')"
	return BreakdownField{Component: "", SQLExpr: sqlExpr}
}

// componentByName returns the Component prototype for the given name, or nil.
func componentByName(name string) components.Component {
	for _, kind := range components.KnownComponentKinds {
		c := components.ComponentFactories[kind]()
		if c.Name() == name {
			return c
		}
	}
	return nil
}
