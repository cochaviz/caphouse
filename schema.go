package caphouse

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"caphouse/components"
	"caphouse/streams"
)

//go:embed captures_schema.sql
var capturesSchemaSQL string

//go:embed packets_schema.sql
var packetsSchemaSQL string

func applySchema(sql, table string) string {
	return strings.ReplaceAll(sql, "{{ table }}", table)
}

// InitSchema creates the database and all caphouse tables if they do not
// exist. It is safe to call on every startup — all statements use
// CREATE TABLE IF NOT EXISTS / ADD INDEX IF NOT EXISTS.
//
// Tables created:
//
//   - pcap_captures — one row per ingested capture session.
//   - pcap_packets — one row per packet; ts is a nanosecond offset from the
//     capture's created_at so that absolute time = created_at + ts.
//   - pcap_<protocol> — one table per registered [components.Component]
//     (e.g. pcap_ethernet, pcap_ipv4, pcap_tcp). New components are picked
//     up automatically via [components.ComponentFactories].
//   - stream_captures — one row per observed TCP stream.
//   - stream_http — reconstructed HTTP sessions from TCP stream reassembly.
//
// All tables use ReplacingMergeTree, making re-ingest of the same capture
// idempotent: duplicate rows are deduplicated at merge time (or on read with
// FINAL). The primary key / ORDER BY on each table is chosen to maximise
// compression for that layer's column access patterns.
func (c *Client) InitSchema(ctx context.Context) error {
	if c.cfg.Database == "" {
		return errors.New("database is required")
	}

	db := quoteIdent(c.cfg.Database)
	if err := c.conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", db)); err != nil {
		return fmt.Errorf("create database: %w", err)
	}

	capturesTable := c.capturesTable()
	packetsTable := c.packetsTable()
	streamCapturesTable := c.streamCapturesTable()
	streamHTTPTable := c.streamHTTPTable()

	if err := c.conn.Exec(ctx, applySchema(capturesSchemaSQL, capturesTable)); err != nil {
		return fmt.Errorf("create captures table: %w", err)
	}
	if err := c.conn.Exec(ctx, applySchema(packetsSchemaSQL, packetsTable)); err != nil {
		return fmt.Errorf("create packets table: %w", err)
	}

	for _, ctor := range components.ComponentFactories {
		proto := ctor()
		table := c.tableRef(components.ComponentTable(proto))
		if err := c.conn.Exec(ctx, proto.Schema(table)); err != nil {
			return fmt.Errorf("create %s table: %w", proto.Name(), err)
		}
	}

	if err := c.conn.Exec(ctx, streams.CapturesSchema(streamCapturesTable)); err != nil {
		return fmt.Errorf("create stream_captures table: %w", err)
	}
	if err := c.conn.Exec(ctx, streams.HTTPSchema(streamHTTPTable)); err != nil {
		return fmt.Errorf("create stream_http table: %w", err)
	}

	indexes := []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_session (session_id) TYPE set(10000) GRANULARITY 1", packetsTable),
	}
	for _, ctor := range components.ComponentFactories {
		proto := ctor()
		indexes = append(indexes, proto.Indexes(c.tableRef(components.ComponentTable(proto)))...)
	}
	indexes = append(indexes, streams.CapturesIndexes(streamCapturesTable)...)
	indexes = append(indexes, streams.HTTPIndexes(streamHTTPTable)...)
	for _, stmt := range indexes {
		if err := c.conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("add index: %w", err)
		}
	}

	return nil
}

// tableRef returns a fully-qualified, backtick-quoted ClickHouse table reference.
// SQL does not support ? placeholders for identifiers, so we interpolate with
// fmt.Sprintf. This is safe because cfg.Database is the only variable component
// and is validated as strictly alphanumeric+underscore by validateIdent in New().
// All table names are hardcoded string literals.
func (c *Client) tableRef(table string) string {
	return fmt.Sprintf("%s.%s", quoteIdent(c.cfg.Database), quoteIdent(table))
}

func (c *Client) capturesTable() string       { return c.tableRef("pcap_captures") }
func (c *Client) packetsTable() string        { return c.tableRef("pcap_packets") }
func (c *Client) streamCapturesTable() string { return c.tableRef("stream_captures") }
func (c *Client) streamHTTPTable() string     { return c.tableRef("stream_http") }

// componentTable returns the fully-qualified table reference for the component
// of the given kind, as registered in ComponentFactories.
func (c *Client) componentTable(kind uint) string {
	proto := components.ComponentFactories[kind]()
	return c.tableRef(components.ComponentTable(proto))
}

func quoteIdent(name string) string {
	return "`" + name + "`"
}

func validateIdent(name string) error {
	if name == "" {
		return errors.New("identifier is empty")
	}
	for _, r := range name {
		switch {
		case r == '_':
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		default:
			return fmt.Errorf("invalid identifier: %q", name)
		}
	}
	return nil
}

// ColumnDef is a queryable column with its ClickHouse type.
type ColumnDef struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// TableSchema describes the queryable columns for a single table, using the
// names as they appear in query results (i.e. with component alias prefixes).
type TableSchema struct {
	Name    string      `json:"name"`    // SQL alias used in queries (e.g. "ipv4", "p", "captures")
	Label   string      `json:"label"`   // human-readable label
	Columns []ColumnDef `json:"columns"` // result-column names with ClickHouse types
}

// parseSchemaColumnTypes extracts column → ClickHouse type from a CREATE TABLE statement.
func parseSchemaColumnTypes(sql string) map[string]string {
	types := make(map[string]string)
	start := strings.Index(sql, "(")
	end := strings.LastIndex(sql, ")")
	if start < 0 || end <= start {
		return types
	}
	for _, line := range strings.Split(sql[start+1:end], "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		line = strings.TrimRight(line, ",")
		upper := strings.ToUpper(line)
		for _, kw := range []string{" CODEC(", " COMMENT ", " DEFAULT ", " TTL ", " ALIAS "} {
			if i := strings.Index(upper, kw); i >= 0 {
				line = strings.TrimSpace(line[:i])
				upper = strings.ToUpper(line)
			}
		}
		idx := strings.IndexByte(line, ' ')
		if idx < 0 {
			continue
		}
		name, typ := line[:idx], strings.TrimSpace(line[idx+1:])
		switch strings.ToUpper(name) {
		case "ENGINE", "ORDER", "PRIMARY", "PARTITION", "SETTINGS", "INDEX", "PROJECTION", "SAMPLE":
			continue
		}
		if name != "" && typ != "" {
			types[name] = typ
		}
	}
	return types
}

// DisplaySchema returns schema metadata for all queryable tables, suitable
// for display in a UI or documentation.
func (c *Client) DisplaySchema() []TableSchema {
	packetTypes := parseSchemaColumnTypes(packetsSchemaSQL)
	captureTypes := parseSchemaColumnTypes(capturesSchemaSQL)

	colDef := func(typMap map[string]string, name string, fallback string) ColumnDef {
		if t, ok := typMap[name]; ok {
			return ColumnDef{Name: name, Type: t}
		}
		return ColumnDef{Name: name, Type: fallback}
	}

	tables := []TableSchema{
		{
			Name:  "p",
			Label: "Packet",
			Columns: []ColumnDef{
				colDef(packetTypes, "session_id", "UInt64"),
				colDef(packetTypes, "packet_id", "UInt32"),
				colDef(packetTypes, "ts", "Int64"),
				colDef(packetTypes, "incl_len", "UInt32"),
				{Name: "orig_len", Type: "UInt32"},
				colDef(packetTypes, "payload", "String"),
			},
		},
		{
			Name:  "captures",
			Label: "Capture",
			Columns: []ColumnDef{
				colDef(captureTypes, "session_id", "UInt64"),
				colDef(captureTypes, "sensor", "String"),
				colDef(captureTypes, "endianness", "String"),
				colDef(captureTypes, "snaplen", "UInt32"),
				colDef(captureTypes, "linktype", "UInt32"),
				colDef(captureTypes, "time_res", "String"),
			},
		},
	}
	for _, kind := range components.KnownComponentKinds {
		proto := components.ComponentFactories[kind]()
		name := proto.Name()
		cols, err := proto.DataColumns(name)
		if err != nil {
			continue
		}
		schemaTypes := parseSchemaColumnTypes(proto.Schema("t"))
		defs := make([]ColumnDef, 0, len(cols))
		for _, expr := range cols {
			// expr is "alias.rawCol AS resultCol"; extract both parts.
			asIdx := strings.Index(expr, " AS ")
			if asIdx < 0 {
				continue
			}
			qualified := expr[:asIdx]                                 // e.g. "ipv4.src"
			rawCol := qualified[strings.IndexByte(qualified, '.')+1:] // e.g. "src"
			typ := schemaTypes[rawCol]
			if typ == "" {
				typ = "String"
			}
			defs = append(defs, ColumnDef{Name: qualified, Type: typ})
		}
		label := strings.ToUpper(name[:1]) + name[1:]
		tables = append(tables, TableSchema{Name: name, Label: label, Columns: defs})
	}
	return tables
}
