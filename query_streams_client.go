package caphouse

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// StreamRow represents one row from stream_captures LEFT JOIN stream_http.
type StreamRow struct {
	SessionID   uint64 `json:"session_id"`
	StreamID    string `json:"stream_id"`
	L7Proto     string `json:"l7_proto"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	IsComplete  bool   `json:"is_complete"`
	PacketCount uint64 `json:"packet_count"`
	ByteCount   uint64 `json:"byte_count"`
	HTTPMethod  string `json:"http_method,omitempty"`
	HTTPHost    string `json:"http_host,omitempty"`
	HTTPPath    string `json:"http_path,omitempty"`
}

// streamsWhere builds the shared WHERE clause and bind args for stream queries.
// When fromNs/toNs are non-zero a JOIN with pcap_packets is assumed and the
// timestamp conditions reference the aliased "p" table.
// It never returns an empty clause; at minimum it returns "1".
func streamsWhere(sessionIDs []uint64, l7proto string, fromNs, toNs int64) (string, []any) {
	var parts []string
	var args []any

	if len(sessionIDs) > 0 {
		ids := make([]string, len(sessionIDs))
		for i, id := range sessionIDs {
			ids[i] = strconv.FormatUint(id, 10)
		}
		parts = append(parts, "sc.session_id IN ("+strings.Join(ids, ",")+")")
	}
	if l7proto != "" {
		parts = append(parts, "sc.l7_proto = ?")
		args = append(args, l7proto)
	}
	if fromNs > 0 {
		parts = append(parts, "p.ts >= ?")
		args = append(args, fromNs)
	}
	if toNs > 0 {
		parts = append(parts, "p.ts < ?")
		args = append(args, toNs)
	}
	if len(parts) == 0 {
		return "1", args
	}
	return strings.Join(parts, " AND "), args
}

// QueryStreams returns stream rows from stream_captures LEFT JOIN stream_http.
// sessionIDs is optional; l7proto filters by protocol (empty = all).
// fromNs/toNs are optional Unix-nanosecond bounds that filter by first-packet timestamp (0 = unset).
func (c *Client) QueryStreams(ctx context.Context, sessionIDs []uint64, l7proto string, fromNs, toNs int64, limit, offset int) ([]StreamRow, error) {
	sc := c.streamCapturesTable()
	sh := c.streamHTTPTable()

	where, args := streamsWhere(sessionIDs, l7proto, fromNs, toNs)

	// Add a JOIN with pcap_packets when a time range is requested so we can
	// filter by the first-packet timestamp (stream_captures has no ts column).
	var timeJoin string
	if fromNs > 0 || toNs > 0 {
		timeJoin = fmt.Sprintf(
			"JOIN %s AS p ON sc.session_id = p.session_id AND sc.first_packet_id = p.packet_id",
			c.packetsTable(),
		)
	}

	sql := fmt.Sprintf(`
SELECT
    sc.session_id,
    toString(sc.stream_id),
    sc.l7_proto,
    replaceOne(IPv6NumToString(sc.src_ip), '::ffff:', ''),
    replaceOne(IPv6NumToString(sc.dst_ip), '::ffff:', ''),
    sc.src_port,
    sc.dst_port,
    sc.is_complete,
    sc.packet_count,
    sc.byte_count,
    coalesce(sh.method, ''),
    coalesce(sh.host, ''),
    coalesce(sh.path, '')
FROM %s AS sc
%s
LEFT JOIN %s AS sh ON sc.session_id = sh.session_id AND sc.stream_id = sh.stream_id
WHERE %s
ORDER BY sc.session_id, sc.first_packet_id DESC
LIMIT %d OFFSET %d
`, sc, timeJoin, sh, where, limit, offset)

	rows, err := c.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query streams: %w", err)
	}
	defer rows.Close()

	var result []StreamRow
	for rows.Next() {
		var r StreamRow
		if err := rows.Scan(
			&r.SessionID, &r.StreamID, &r.L7Proto,
			&r.SrcIP, &r.DstIP,
			&r.SrcPort, &r.DstPort,
			&r.IsComplete, &r.PacketCount, &r.ByteCount,
			&r.HTTPMethod, &r.HTTPHost, &r.HTTPPath,
		); err != nil {
			return nil, fmt.Errorf("scan stream row: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// CountStreams returns the total number of rows in stream_captures matching
// the given filters. fromNs/toNs are optional nanosecond timestamp bounds (0 = unset).
func (c *Client) CountStreams(ctx context.Context, sessionIDs []uint64, l7proto string, fromNs, toNs int64) (uint64, error) {
	sc := c.streamCapturesTable()

	where, args := streamsWhere(sessionIDs, l7proto, fromNs, toNs)

	var timeJoin string
	if fromNs > 0 || toNs > 0 {
		timeJoin = fmt.Sprintf(
			"JOIN %s AS p ON sc.session_id = p.session_id AND sc.first_packet_id = p.packet_id",
			c.packetsTable(),
		)
	}

	sql := fmt.Sprintf("SELECT count() FROM %s AS sc %s WHERE %s", sc, timeJoin, where)

	row := c.conn.QueryRow(ctx, sql, args...)
	var total uint64
	if err := row.Scan(&total); err != nil {
		return 0, fmt.Errorf("count streams: %w", err)
	}
	return total, nil
}
