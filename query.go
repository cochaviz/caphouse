package caphouse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"
)

// PacketRef identifies a single packet within a capture.
type PacketRef struct {
	CaptureID uuid.UUID
	PacketID  uint64
}

// Query is a compiled packet query expression ready to execute against
// ClickHouse.
type Query struct {
	root queryNode
}

// ParseQuery parses a tcpdump-style query expression. Supported primitives:
//
//	host <ip>                      src or dst IP matches (IPv4 or IPv6)
//	src host <ip>                  source IP matches
//	dst host <ip>                  destination IP matches
//	port <n>                       src or dst TCP/UDP port matches
//	src port <n>                   source port matches
//	dst port <n>                   destination port matches
//	time <rfc3339> to <rfc3339>    packet timestamp within range
//
// Primitives can be combined with 'and', 'or', 'not', and parentheses.
func ParseQuery(s string) (Query, error) {
	p := newParser(s)
	root, err := p.parseExpr()
	if err != nil {
		return Query{}, err
	}
	if !p.done() {
		return Query{}, fmt.Errorf("unexpected token %q", p.peek())
	}
	return Query{root: root}, nil
}

// QueryPackets returns the packet references within the given captures that
// match f, ordered by (capture_id, packet_id).
func (c *Client) QueryPackets(ctx context.Context, captureIDs []uuid.UUID, f Query) ([]PacketRef, error) {
	if len(captureIDs) == 0 {
		return nil, errors.New("at least one capture ID is required")
	}
	sub, args, err := f.root.subquery(c, captureIDs)
	if err != nil {
		return nil, err
	}
	query := "SELECT capture_id, packet_id FROM (" + sub + ") ORDER BY capture_id ASC, packet_id ASC"
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("execute filter: %w", err)
	}
	defer rows.Close()
	var refs []PacketRef
	for rows.Next() {
		var r PacketRef
		if err := rows.Scan(&r.CaptureID, &r.PacketID); err != nil {
			return nil, fmt.Errorf("scan packet ref: %w", err)
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}

// ExportCaptureFiltered runs f against captureID to resolve matching packet IDs,
// then streams those packets as a classic PCAP file. packetsWritten is incremented
// after each packet (may be nil). Returns the total matched packet count alongside
// the reader so callers can use it for progress reporting.
func (c *Client) ExportCaptureFiltered(ctx context.Context, captureID uuid.UUID, f Query, packetsWritten *atomic.Int64) (rc io.ReadCloser, total int64, err error) {
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

// formatArg formats a single query argument as an inline SQL literal.
func formatArg(v any) string {
	switch val := v.(type) {
	case string:
		return "'" + strings.ReplaceAll(val, "'", "\\'") + "'"
	case uint16:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// inlineArgs replaces each ? placeholder in sql with the corresponding formatted arg.
func inlineArgs(sql string, args []any) string {
	var b strings.Builder
	argIdx := 0
	for i := 0; i < len(sql); i++ {
		if sql[i] == '?' && argIdx < len(args) {
			b.WriteString(formatArg(args[argIdx]))
			argIdx++
		} else {
			b.WriteByte(sql[i])
		}
	}
	return b.String()
}

// knownComponents maps component flag values to their table name suffixes and aliases.
var knownComponents = map[string]struct {
	table string
	alias string
}{
	"ethernet":     {"pcap_ethernet", "ethernet"},
	"dot1q":        {"pcap_dot1q", "dot1q"},
	"linuxsll":     {"pcap_linuxsll", "linuxsll"},
	"ipv4":         {"pcap_ipv4", "ipv4"},
	"ipv4_options": {"pcap_ipv4_options", "ipv4_options"},
	"ipv6":         {"pcap_ipv6", "ipv6"},
	"ipv6_ext":     {"pcap_ipv6_ext", "ipv6_ext"},
	"tcp":          {"pcap_tcp", "tcp"},
	"udp":          {"pcap_udp", "udp"},
	"raw_tail":     {"pcap_raw_tail", "raw_tail"},
}

// GenerateSQL returns a SELECT statement equivalent to the filter query with
// all bind parameters inlined. components is a list of protocol table names
// (e.g. "ipv4", "tcp") whose rows will be LEFT JOINed into the result.
func (c *Client) GenerateSQL(captureID uuid.UUID, q Query, components []string) (string, error) {
	sub, args, err := q.root.subquery(c, []uuid.UUID{captureID})
	if err != nil {
		return "", err
	}
	inlinedSub := inlineArgs(sub, args)

	// Validate component names.
	for _, comp := range components {
		if _, ok := knownComponents[comp]; !ok {
			return "", fmt.Errorf("unknown component %q", comp)
		}
	}

	packetsRef := c.tableRef("pcap_packets")

	// Build SELECT list.
	selectParts := []string{"p.*"}
	for _, comp := range components {
		info := knownComponents[comp]
		selectParts = append(selectParts,
			fmt.Sprintf("%s.* EXCEPT (capture_id, packet_id, codec_version)", info.alias),
		)
	}

	// Build FROM + JOINs.
	fromClause := fmt.Sprintf("FROM %s AS p FINAL", packetsRef)
	var joins []string
	for _, comp := range components {
		info := knownComponents[comp]
		tableRef := c.tableRef(info.table)
		joins = append(joins,
			fmt.Sprintf("LEFT JOIN %s AS %s FINAL USING (capture_id, packet_id)", tableRef, info.alias),
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

// queryNode produces a SQL subquery returning (capture_id, packet_id) rows.
type queryNode interface {
	subquery(c *Client, captureIDs []uuid.UUID) (sql string, args []any, err error)
}

// captureInSQL returns a SQL IN predicate with capture UUIDs inlined.
// UUIDs are safe to inline — they are hex strings validated by the uuid package.
func captureInSQL(ids []uuid.UUID) string {
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = "'" + id.String() + "'"
	}
	return "capture_id IN (" + strings.Join(quoted, ",") + ")"
}

// --- and / or / not ---

type andNode struct{ left, right queryNode }

func (n *andNode) subquery(c *Client, ids []uuid.UUID) (string, []any, error) {
	ls, la, err := n.left.subquery(c, ids)
	if err != nil {
		return "", nil, err
	}
	rs, ra, err := n.right.subquery(c, ids)
	if err != nil {
		return "", nil, err
	}
	return "(" + ls + ") INTERSECT (" + rs + ")", append(la, ra...), nil
}

type orNode struct{ left, right queryNode }

func (n *orNode) subquery(c *Client, ids []uuid.UUID) (string, []any, error) {
	ls, la, err := n.left.subquery(c, ids)
	if err != nil {
		return "", nil, err
	}
	rs, ra, err := n.right.subquery(c, ids)
	if err != nil {
		return "", nil, err
	}
	return "(" + ls + ") UNION DISTINCT (" + rs + ")", append(la, ra...), nil
}

type notNode struct{ expr queryNode }

func (n *notNode) subquery(c *Client, ids []uuid.UUID) (string, []any, error) {
	es, ea, err := n.expr.subquery(c, ids)
	if err != nil {
		return "", nil, err
	}
	universe := fmt.Sprintf(
		"SELECT capture_id, packet_id FROM %s FINAL WHERE %s",
		c.packetsTable(), captureInSQL(ids),
	)
	return "(" + universe + ") EXCEPT (" + es + ")", ea, nil
}

// --- host ---

type hostNode struct {
	dir string // "src", "dst", or "" (either)
	ip  string
}

func (n *hostNode) subquery(c *Client, ids []uuid.UUID) (string, []any, error) {
	scope := captureInSQL(ids)
	var args []any
	var parts []string

	add := func(table, srcCol, dstCol string) {
		var cond string
		switch n.dir {
		case "src":
			cond = srcCol + " = ?"
			args = append(args, n.ip)
		case "dst":
			cond = dstCol + " = ?"
			args = append(args, n.ip)
		default:
			cond = "(" + srcCol + " = ? OR " + dstCol + " = ?)"
			args = append(args, n.ip, n.ip)
		}
		parts = append(parts, fmt.Sprintf(
			"SELECT capture_id, packet_id FROM %s FINAL WHERE %s AND %s",
			table, scope, cond,
		))
	}

	add(c.ipv4Table(), "src_ip_v4", "dst_ip_v4")
	add(c.ipv6Table(), "src_ip_v6", "dst_ip_v6")
	return strings.Join(parts, " UNION DISTINCT "), args, nil
}

// --- port ---

type portNode struct {
	dir  string // "src", "dst", or "" (either)
	port uint16
}

func (n *portNode) subquery(c *Client, ids []uuid.UUID) (string, []any, error) {
	scope := captureInSQL(ids)
	var args []any
	var parts []string

	add := func(table string) {
		var cond string
		switch n.dir {
		case "src":
			cond = "src_port = ?"
			args = append(args, n.port)
		case "dst":
			cond = "dst_port = ?"
			args = append(args, n.port)
		default:
			cond = "(src_port = ? OR dst_port = ?)"
			args = append(args, n.port, n.port)
		}
		parts = append(parts, fmt.Sprintf(
			"SELECT capture_id, packet_id FROM %s FINAL WHERE %s AND %s",
			table, scope, cond,
		))
	}

	add(c.tcpTable())
	add(c.udpTable())
	return strings.Join(parts, " UNION DISTINCT "), args, nil
}

// --- time ---

type timeNode struct {
	from, to int64 // Unix nanoseconds
}

func (n *timeNode) subquery(c *Client, ids []uuid.UUID) (string, []any, error) {
	scope := captureInSQL(ids)
	// ts is stored as ns offset from capture start.
	// Absolute ns = toUnixTimestamp64Nano(created_at) + ts
	sql := fmt.Sprintf(`
		SELECT p.capture_id, p.packet_id
		FROM %s p FINAL
		INNER JOIN (
			SELECT capture_id, created_at FROM %s FINAL WHERE %s
		) cap ON p.capture_id = cap.capture_id
		WHERE %s
		  AND toInt64(toUnixTimestamp64Nano(cap.created_at)) + toInt64(p.ts)
		      BETWEEN ? AND ?`,
		c.packetsTable(), c.capturesTable(), scope, scope,
	)
	return sql, []any{n.from, n.to}, nil
}
