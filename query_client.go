package caphouse

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"

	"caphouse/components"
	"caphouse/query"

	"github.com/google/uuid"
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
		comps[alias] = query.ComponentInfo{
			TableRef: c.tableRef(table),
			Alias:    alias,
		}
	}
	return query.Tables{
		Packets:    c.packetsTable(),
		Captures:   c.capturesTable(),
		Components: comps,
	}
}

// QueryPackets returns the packet references within the given captures that
// match f, ordered by (capture_id, packet_id). When captureIDs is nil or
// empty, all captures are searched.
func (c *Client) QueryPackets(ctx context.Context, captureIDs []uuid.UUID, f query.Query) ([]query.PacketRef, error) {
	sub, args, err := f.Subquery(c.tables(), captureIDs)
	if err != nil {
		return nil, err
	}
	sql := "SELECT capture_id, packet_id FROM (" + sub + ") ORDER BY capture_id ASC, packet_id ASC"
	rows, err := c.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("execute filter: %w", err)
	}
	defer rows.Close()
	var refs []query.PacketRef
	for rows.Next() {
		var r query.PacketRef
		if err := rows.Scan(&r.CaptureID, &r.PacketID); err != nil {
			return nil, fmt.Errorf("scan packet ref: %w", err)
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}

// ExportCaptureFiltered runs f against captureID to resolve matching packet
// IDs, then streams those packets as a classic PCAP file. packetsWritten is
// incremented after each packet (may be nil). Returns the total matched packet
// count alongside the reader so callers can use it for progress reporting.
func (c *Client) ExportCaptureFiltered(ctx context.Context, captureID uuid.UUID, f query.Query, packetsWritten *atomic.Int64) (rc io.ReadCloser, total int64, err error) {
	meta, err := c.fetchCaptureMeta(ctx, captureID)
	if err != nil {
		return nil, 0, err
	}
	refs, err := c.QueryPackets(ctx, []uuid.UUID{captureID}, f)
	if err != nil {
		return nil, 0, err
	}
	ids := make([]uint64, len(refs))
	for i, r := range refs {
		ids[i] = r.PacketID
	}
	ranges := toRanges(ids)
	pr, pw := io.Pipe()
	go func() {
		if err := c.streamCapture(ctx, meta, captureID, ranges, pw, packetsWritten); err != nil {
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
			case uuid.UUID:
				row[col] = tv.String()
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
// When captureIDs is nil or empty, all captures are searched.
func (c *Client) QueryJSON(ctx context.Context, captureIDs []uuid.UUID, q query.Query, comps []string, limit, offset int) ([]map[string]any, error) {
	sql, err := q.SearchSQL(c.tables(), captureIDs, comps, limit, offset)
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
func (c *Client) QueryPacketComponents(ctx context.Context, captureID uuid.UUID, packetID uint64) (map[string]any, error) {
	t := c.tables()

	// All registered component aliases, sorted for stable SQL generation.
	allComps := make([]string, 0, len(t.Components))
	for alias := range t.Components {
		allComps = append(allComps, alias)
	}

	selectParts := []string{
		"p.capture_id AS capture_id",
		"p.packet_id AS packet_id",
		"toInt64(toUnixTimestamp64Nano(cap.created_at)) + toInt64(p.ts) AS timestamp_ns",
		"p.incl_len AS incl_len",
		"p.incl_len + p.trunc_extra AS orig_len",
		"toUInt64(p.components) AS components",
		"lower(hex(p.frame_raw)) AS frame_raw",
	}
	for _, alias := range allComps {
		selectParts = append(selectParts,
			fmt.Sprintf("%s.* EXCEPT (capture_id, packet_id, codec_version)", alias),
		)
	}

	var joins []string
	for _, alias := range allComps {
		info := t.Components[alias]
		joins = append(joins,
			fmt.Sprintf("LEFT JOIN %s AS %s FINAL ON %s.capture_id = p.capture_id AND %s.packet_id = p.packet_id",
				info.TableRef, alias, alias, alias),
		)
	}

	var sb strings.Builder
	sb.WriteString("SELECT\n    ")
	sb.WriteString(strings.Join(selectParts, ",\n    "))
	sb.WriteString(fmt.Sprintf("\nFROM %s AS p FINAL", t.Packets))
	sb.WriteString(fmt.Sprintf("\nINNER JOIN (SELECT capture_id, created_at FROM %s FINAL) cap ON p.capture_id = cap.capture_id", t.Captures))
	for _, j := range joins {
		sb.WriteString("\n")
		sb.WriteString(j)
	}
	sb.WriteString(fmt.Sprintf("\nWHERE p.capture_id = '%s' AND p.packet_id = %d", captureID, packetID))
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

// CountBin holds the packet count for a single time bin.
type CountBin struct {
	// BinStartNs is the Unix nanosecond timestamp of the bin's start.
	BinStartNs int64 `json:"bin_start_ns"`
	// Count is the number of packets in this bin.
	Count uint64 `json:"count"`
}

// QueryCounts executes a packet-count histogram. Packets matched by f are
// bucketed into fixed-width time bins of binSizeSeconds seconds.
// When captureIDs is nil or empty, all captures are searched.
func (c *Client) QueryCounts(ctx context.Context, captureIDs []uuid.UUID, f query.Query, binSizeSeconds int64) ([]CountBin, error) {
	sql, err := f.CountsSQL(c.tables(), captureIDs, binSizeSeconds*int64(1e9))
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

// GenerateSQL returns a SELECT statement equivalent to the filter query with
// all bind parameters inlined, scoped to a single capture. comps is a list of
// protocol component names (e.g. "ipv4", "tcp") to LEFT JOIN.
func (c *Client) GenerateSQL(captureID uuid.UUID, q query.Query, comps []string) (string, error) {
	return q.SQL(c.tables(), []uuid.UUID{captureID}, comps)
}

// GenerateSQLForCaptures is like GenerateSQL but scoped to multiple captures.
// When captureIDs is nil or empty, the generated SQL covers all captures.
func (c *Client) GenerateSQLForCaptures(captureIDs []uuid.UUID, q query.Query, comps []string) (string, error) {
	return q.SQL(c.tables(), captureIDs, comps)
}
