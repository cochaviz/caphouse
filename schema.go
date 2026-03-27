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
