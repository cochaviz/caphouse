package streams

import (
	_ "embed"
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

func HTTPSchema(table string) string {
	return applySchema(httpSchemaSQL, table)
}
