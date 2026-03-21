package query

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// queryNode produces a SQL subquery returning (capture_id, packet_id) rows.
type queryNode interface {
	subquery(t Tables, captureIDs []uuid.UUID) (sql string, args []any, err error)
}

// --- and / or / not ---

type andNode struct{ left, right queryNode }

func (n *andNode) subquery(t Tables, ids []uuid.UUID) (string, []any, error) {
	ls, la, err := n.left.subquery(t, ids)
	if err != nil {
		return "", nil, err
	}
	rs, ra, err := n.right.subquery(t, ids)
	if err != nil {
		return "", nil, err
	}
	return "(" + ls + ") INTERSECT (" + rs + ")", append(la, ra...), nil
}

type orNode struct{ left, right queryNode }

func (n *orNode) subquery(t Tables, ids []uuid.UUID) (string, []any, error) {
	ls, la, err := n.left.subquery(t, ids)
	if err != nil {
		return "", nil, err
	}
	rs, ra, err := n.right.subquery(t, ids)
	if err != nil {
		return "", nil, err
	}
	return "(" + ls + ") UNION DISTINCT (" + rs + ")", append(la, ra...), nil
}

type notNode struct{ expr queryNode }

func (n *notNode) subquery(t Tables, ids []uuid.UUID) (string, []any, error) {
	es, ea, err := n.expr.subquery(t, ids)
	if err != nil {
		return "", nil, err
	}
	scope := CaptureScope(ids)
	var universe string
	if scope == "" {
		universe = fmt.Sprintf("SELECT capture_id, packet_id FROM %s FINAL", t.Packets)
	} else {
		universe = fmt.Sprintf("SELECT capture_id, packet_id FROM %s FINAL %s", t.Packets, scope)
	}
	return "(" + universe + ") EXCEPT (" + es + ")", ea, nil
}

// --- host ---

type hostNode struct {
	dir string // "src", "dst", or "" (either)
	ip  string
}

func (n *hostNode) subquery(t Tables, ids []uuid.UUID) (string, []any, error) {
	var args []any
	var parts []string

	ipv4Ref, ipv6Ref := t.Components["ipv4"].TableRef, t.Components["ipv6"].TableRef

	add := func(tableRef, srcCol, dstCol string) {
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
			"SELECT capture_id, packet_id FROM %s FINAL %s",
			tableRef, whereWithScope(ids, cond),
		))
	}

	add(ipv4Ref, "src_ip_v4", "dst_ip_v4")
	add(ipv6Ref, "src_ip_v6", "dst_ip_v6")
	return strings.Join(parts, " UNION DISTINCT "), args, nil
}

// --- port ---

type portNode struct {
	dir  string // "src", "dst", or "" (either)
	port uint16
}

func (n *portNode) subquery(t Tables, ids []uuid.UUID) (string, []any, error) {
	var args []any
	var parts []string

	tcpRef, udpRef := t.Components["tcp"].TableRef, t.Components["udp"].TableRef

	add := func(tableRef string) {
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
			"SELECT capture_id, packet_id FROM %s FINAL %s",
			tableRef, whereWithScope(ids, cond),
		))
	}

	add(tcpRef)
	add(udpRef)
	return strings.Join(parts, " UNION DISTINCT "), args, nil
}

// --- time ---

type timeNode struct {
	from, to int64 // Unix nanoseconds
}

func (n *timeNode) subquery(t Tables, ids []uuid.UUID) (string, []any, error) {
	// ts is stored as ns offset from capture start.
	// Absolute ns = toUnixTimestamp64Nano(created_at) + ts
	//
	// PREWHERE created_at <= to prunes captures that started after the query
	// window — they cannot contain any in-range packets. We do not apply a
	// lower-bound PREWHERE because a capture that started before `from` may
	// still have packets inside [from, to].
	//
	// Use aliases tp/tc (time-packet/time-capture) to avoid collisions with
	// the outer query's p/cap aliases in SearchSQL and CountsSQL.
	capScope := CaptureScope(ids)
	timeCond := "toInt64(toUnixTimestamp64Nano(tc.created_at)) + toInt64(tp.ts) BETWEEN ? AND ?"
	sql := fmt.Sprintf(`
		SELECT tp.capture_id, tp.packet_id
		FROM %s tp FINAL
		INNER JOIN (
			SELECT capture_id, created_at FROM %s FINAL %s
			PREWHERE toInt64(toUnixTimestamp64Nano(created_at)) <= ?
		) tc ON tp.capture_id = tc.capture_id
		%s`,
		t.Packets, t.Captures, capScope,
		whereWithScope(ids, timeCond),
	)
	return sql, []any{n.to, n.from, n.to}, nil
}
