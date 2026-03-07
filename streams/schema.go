package streams

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed captures_schema.sql
var capturesSchemaSQL string

//go:embed http_schema.sql
var httpSchemaSQL string

func applySchema(sql, table string) string {
	return strings.ReplaceAll(sql, "{{ table }}", table)
}

func CapturesSchema(table string) string {
	return applySchema(capturesSchemaSQL, table)
}

func CapturesIndexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_l7_proto (l7_proto) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_dst_port (dst_port) TYPE set(512) GRANULARITY 4", table),
	}
}

func HTTPSchema(table string) string {
	return applySchema(httpSchemaSQL, table)
}

func HTTPIndexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_host (host) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_method (method) TYPE set(16) GRANULARITY 4", table),
	}
}
