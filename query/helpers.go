package query

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
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

// CaptureInSQL returns a SQL IN predicate with capture UUIDs inlined.
// UUIDs are safe to inline — they are hex strings validated by the uuid package.
// Panics if ids is empty.
func CaptureInSQL(ids []uuid.UUID) string {
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = "'" + id.String() + "'"
	}
	return "capture_id IN (" + strings.Join(quoted, ",") + ")"
}

// CaptureScope returns a WHERE clause (including the keyword) that restricts
// to the given captures, or an empty string when ids is nil/empty (meaning
// "all captures — no restriction").
func CaptureScope(ids []uuid.UUID) string {
	if len(ids) == 0 {
		return ""
	}
	return "WHERE " + CaptureInSQL(ids)
}

// whereWithScope returns a WHERE clause combining an optional capture scope
// with a mandatory condition. When ids is empty only the condition is used.
func whereWithScope(ids []uuid.UUID, condition string) string {
	if len(ids) == 0 {
		return "WHERE " + condition
	}
	return "WHERE " + CaptureInSQL(ids) + " AND " + condition
}
