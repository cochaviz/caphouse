package query

import (
	"fmt"
	"strings"
)

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

// inlineArgs replaces each ? placeholder in sql with the corresponding
// formatted arg.
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

// SessionInSQL returns a SQL IN predicate with session IDs inlined as integers.
// Panics if ids is empty.
func SessionInSQL(ids []uint64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d", id)
	}
	return "session_id IN (" + strings.Join(parts, ",") + ")"
}

// SessionScope returns a WHERE clause (including the keyword) that restricts
// to the given sessions, or an empty string when ids is nil/empty (meaning
// "all sessions — no restriction").
func SessionScope(ids []uint64) string {
	if len(ids) == 0 {
		return ""
	}
	return "WHERE " + SessionInSQL(ids)
}

// whereWithScope returns a WHERE clause combining an optional session scope
// with a mandatory condition. When ids is empty only the condition is used.
func whereWithScope(ids []uint64, condition string) string {
	if len(ids) == 0 {
		return "WHERE " + condition
	}
	return "WHERE " + SessionInSQL(ids) + " AND " + condition
}
