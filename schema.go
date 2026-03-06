package caphouse

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"caphouse/components"
)

//go:embed captures_schema.sql
var capturesSchemaSQL string

//go:embed packets_schema.sql
var packetsSchemaSQL string

func applySchema(sql, table string) string {
	return strings.ReplaceAll(sql, "{{ table }}", table)
}

// InitSchema creates the database and tables if they do not exist.
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
	ethernetTable := c.ethernetTable()
	dot1qTable := c.dot1qTable()
	linuxSLLTable := c.linuxSLLTable()
	ipv4Table := c.ipv4Table()
	ipv4OptionsTable := c.ipv4OptionsTable()
	ipv6Table := c.ipv6Table()
	ipv6ExtTable := c.ipv6ExtTable()
	tcpTable := c.tcpTable()
	udpTable := c.udpTable()
	rawTailTable := c.rawTailTable()

	if err := c.conn.Exec(ctx, applySchema(capturesSchemaSQL, capturesTable)); err != nil {
		return fmt.Errorf("create captures table: %w", err)
	}

	if err := c.conn.Exec(ctx, applySchema(packetsSchemaSQL, packetsTable)); err != nil {
		return fmt.Errorf("create packets table: %w", err)
	}

	if err := c.conn.Exec(ctx, components.EthernetSchema(ethernetTable)); err != nil {
		return fmt.Errorf("create ethernet table: %w", err)
	}
	if err := c.conn.Exec(ctx, components.Dot1QSchema(dot1qTable)); err != nil {
		return fmt.Errorf("create dot1q table: %w", err)
	}
	if err := c.conn.Exec(ctx, components.LinuxSLLSchema(linuxSLLTable)); err != nil {
		return fmt.Errorf("create linux sll table: %w", err)
	}
	if err := c.conn.Exec(ctx, components.IPv4Schema(ipv4Table)); err != nil {
		return fmt.Errorf("create ipv4 table: %w", err)
	}
	if err := c.conn.Exec(ctx, components.IPv4OptionsSchema(ipv4OptionsTable)); err != nil {
		return fmt.Errorf("create ipv4 options table: %w", err)
	}
	if err := c.conn.Exec(ctx, components.IPv6Schema(ipv6Table)); err != nil {
		return fmt.Errorf("create ipv6 table: %w", err)
	}
	if err := c.conn.Exec(ctx, components.IPv6ExtSchema(ipv6ExtTable)); err != nil {
		return fmt.Errorf("create ipv6 ext table: %w", err)
	}
	if err := c.conn.Exec(ctx, components.TCPSchema(tcpTable)); err != nil {
		return fmt.Errorf("create tcp table: %w", err)
	}
	if err := c.conn.Exec(ctx, components.UDPSchema(udpTable)); err != nil {
		return fmt.Errorf("create udp table: %w", err)
	}
	if err := c.conn.Exec(ctx, components.RawTailSchema(rawTailTable)); err != nil {
		return fmt.Errorf("create raw tail table: %w", err)
	}

	indexes := []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_capture (capture_id) TYPE set(10000) GRANULARITY 1", packetsTable),
	}
	indexes = append(indexes, components.IPv4Indexes(ipv4Table)...)
	indexes = append(indexes, components.IPv6Indexes(ipv6Table)...)
	indexes = append(indexes, components.TCPIndexes(tcpTable)...)
	indexes = append(indexes, components.UDPIndexes(udpTable)...)
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

func (c *Client) capturesTable() string   { return c.tableRef("pcap_captures") }
func (c *Client) packetsTable() string    { return c.tableRef("pcap_packets") }
func (c *Client) ethernetTable() string   { return c.tableRef("pcap_ethernet") }
func (c *Client) dot1qTable() string      { return c.tableRef("pcap_dot1q") }
func (c *Client) linuxSLLTable() string   { return c.tableRef("pcap_linuxsll") }
func (c *Client) ipv4Table() string       { return c.tableRef("pcap_ipv4") }
func (c *Client) ipv4OptionsTable() string { return c.tableRef("pcap_ipv4_options") }
func (c *Client) ipv6Table() string       { return c.tableRef("pcap_ipv6") }
func (c *Client) ipv6ExtTable() string    { return c.tableRef("pcap_ipv6_ext") }
func (c *Client) tcpTable() string        { return c.tableRef("pcap_tcp") }
func (c *Client) udpTable() string        { return c.tableRef("pcap_udp") }
func (c *Client) rawTailTable() string    { return c.tableRef("pcap_raw_tail") }

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
