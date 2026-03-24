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
	"sync/atomic"

	"caphouse/components"
	"caphouse/query"
)

// tables returns a query.Tables pre-populated with this client's fully-
// qualified ClickHouse table references. All component tables registered in
// the component registry are included.
func (c *Client) tables() query.Tables {
	comps := make(map[string]query.ComponentInfo, len(components.ComponentFactories))
	for _, ctor := range components.ComponentFactories {
		proto := ctor()
		table := proto.Table()
		alias := strings.TrimPrefix(table, "pcap_")
		cols, _ := proto.DataColumns(alias)
		comps[alias] = query.ComponentInfo{
			TableRef: c.tableRef(table),
			Alias:    alias,
			Columns:  cols,
		}
	}
	return query.Tables{
		Packets:    c.packetsTable(),
		Captures:   c.capturesTable(),
		Components: comps,
	}
}

// QueryPackets returns the packet references within the given sessions that
// match f, ordered by (session_id, packet_id). When sessionIDs is nil or
// empty, all sessions are searched.
func (c *Client) QueryPackets(ctx context.Context, sessionIDs []uint64, f query.Query) ([]query.PacketRef, error) {
	sub, args, err := f.Subquery(c.tables(), sessionIDs)
	if err != nil {
		return nil, err
	}
	sql := "SELECT session_id, packet_id FROM (" + sub + ") ORDER BY session_id ASC, packet_id ASC"
	rows, err := c.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("execute filter: %w", err)
	}
	defer rows.Close()
	var refs []query.PacketRef
	for rows.Next() {
		var r query.PacketRef
		if err := rows.Scan(&r.SessionID, &r.PacketID); err != nil {
			return nil, fmt.Errorf("scan packet ref: %w", err)
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}

// ExportCaptureFiltered runs f against sessionID to resolve matching packet
// IDs, then streams those packets as a classic PCAP file. packetsWritten is
// incremented after each packet (may be nil). Returns the total matched packet
// count alongside the reader so callers can use it for progress reporting.
func (c *Client) ExportCaptureFiltered(ctx context.Context, sessionID uint64, f query.Query, packetsWritten *atomic.Int64) (rc io.ReadCloser, total int64, err error) {
	meta, err := c.fetchCaptureMeta(ctx, sessionID)
	if err != nil {
		return nil, 0, err
	}
	refs, err := c.QueryPackets(ctx, []uint64{sessionID}, f)
	if err != nil {
		return nil, 0, err
	}
	ids := make([]uint32, len(refs))
	for i, r := range refs {
		ids[i] = r.PacketID
	}
	ranges := toRanges(ids)
	pr, pw := io.Pipe()
	go func() {
		if err := c.streamCapture(ctx, meta, sessionID, ranges, pw, packetsWritten); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	return pr, int64(len(refs)), nil
}

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

// QueryJSON executes a search and returns matching packet rows with basic
// metadata and the requested component fields as JSON-serializable maps.
// Each map key is a column name; values are native Go types (string, uint64,
// int64, etc.) that marshal cleanly to JSON.
// When sessionIDs is nil or empty, all sessions are searched.
// fromNs and toNs are optional Unix-nanosecond timestamp bounds (0 = unset).
func (c *Client) QueryJSON(ctx context.Context, sessionIDs []uint64, q query.Query, comps []string, limit, offset int, fromNs, toNs int64, asc bool) ([]map[string]any, error) {
	sql, err := q.SearchSQL(c.tables(), sessionIDs, comps, limit, offset, fromNs, toNs, asc)
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
	t := c.tables()

	// All registered component aliases, sorted for stable SQL generation.
	allComps := make([]string, 0, len(t.Components))
	for alias := range t.Components {
		allComps = append(allComps, alias)
	}

	selectParts := []string{
		"p.session_id AS session_id",
		"p.packet_id AS packet_id",
		"p.ts AS timestamp_ns",
		"p.incl_len AS incl_len",
		"p.incl_len + p.trunc_extra AS orig_len",
		"toUInt64(p.components) AS components",
		"lower(hex(p.frame_raw)) AS frame_raw",
	}
	for _, alias := range allComps {
		info := t.Components[alias]
		selectParts = append(selectParts, info.Columns...)
	}

	var joins []string
	for _, alias := range allComps {
		info := t.Components[alias]
		joins = append(joins,
			fmt.Sprintf("LEFT JOIN %s AS %s ON %s.session_id = p.session_id AND %s.packet_id = p.packet_id",
				info.TableRef, alias, alias, alias),
		)
	}

	var sb strings.Builder
	sb.WriteString("SELECT\n    ")
	sb.WriteString(strings.Join(selectParts, ",\n    "))
	fmt.Fprintf(&sb, "\nFROM %s AS p", t.Packets)
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
		"SELECT incl_len, trunc_extra, components, frame_raw, frame_hash FROM %s WHERE session_id = ? AND packet_id = ? LIMIT 1",
		c.packetsTable(),
	)
	row := c.conn.QueryRow(ctx, q, sessionID, packetID)

	var (
		inclLen    uint32
		truncExtra uint32
		frameRaw   string
		frameHash  string
	)
	componentMask := new(big.Int)
	if err := row.Scan(&inclLen, &truncExtra, componentMask, &frameRaw, &frameHash); err != nil {
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
		FrameRaw:   []byte(frameRaw),
		FrameHash:  []byte(frameHash),
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
	f query.Query,
	binSizeSeconds int64,
	fromNs, toNs int64,
	tzOffsetSeconds int64,
) ([]CountBin, error) {
	sql, err := f.CountsSQL(
		c.tables(),
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
	f query.Query,
	binSizeSeconds int64,
	fromNs, toNs int64,
	tzOffsetSeconds int64,
	breakdown []query.BreakdownField,
) ([]BreakdownBin, error) {
	sql, err := f.CountsSQL(
		c.tables(),
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

// GenerateSQL returns a SELECT statement equivalent to the filter query with
// all bind parameters inlined, scoped to a single session.
func (c *Client) GenerateSQL(sessionID uint64, q query.Query, comps []string) (string, error) {
	return q.SQL(c.tables(), []uint64{sessionID}, comps)
}

// GenerateSQLForSessions is like GenerateSQL but scoped to multiple sessions.
// When sessionIDs is nil or empty, the generated SQL covers all sessions.
func (c *Client) GenerateSQLForSessions(sessionIDs []uint64, q query.Query, comps []string) (string, error) {
	return q.SQL(c.tables(), sessionIDs, comps)
}

// ParseBreakdownSpec parses a comma-separated breakdown specification into a slice
// of BreakdownFields. It handles the special "proto" keyword by building the SQL
// expression dynamically from the component registry, so adding a new component
// automatically includes it in proto breakdowns.
func (c *Client) ParseBreakdownSpec(spec string) ([]query.BreakdownField, error) {
	parts := strings.Split(spec, ",")
	fields := make([]query.BreakdownField, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "proto" {
			fields = append(fields, c.protoBreakdownField())
			continue
		}
		bf, err := query.ParseBreakdownField(p)
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
func (c *Client) protoBreakdownField() query.BreakdownField {
	parts := make([]string, 0, len(components.KnownComponentKinds))
	for _, kind := range components.KnownComponentKinds {
		comp := components.ComponentFactories[kind]()
		label := strings.TrimPrefix(comp.Table(), "pcap_")
		bitVal := uint64(1) << kind
		parts = append(parts,
			fmt.Sprintf("if(bitAnd(toUInt64(p.components), %d) != 0, '%s', '')", bitVal, label),
		)
	}
	sqlExpr := "arrayStringConcat(arrayFilter(x -> notEmpty(x), [" +
		strings.Join(parts, ", ") + "]), '/')"
	return query.BreakdownField{Component: "", SQLExpr: sqlExpr}
}
