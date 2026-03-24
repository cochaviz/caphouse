// Package geoip populates and queries ClickHouse ip_trie dictionaries for
// IP geolocation and ASN lookups. It supports separate IPv4 and IPv6
// dictionaries (ip_trie / ip_trie_v6, asn_trie / asn_trie_v6), each loaded
// from a DB-IP-compatible CSV source URL.
//
// # IPv4 CIDR conversion
//
// For IPv4, the start/end IP range from the CSV is converted to CIDR notation
// using 32-bit integer arithmetic in ClickHouse (via the approach described in
// https://clickhouse.com/blog/geolocating-ips-in-clickhouse-and-grafana):
// XOR the start and end addresses to find the differing bits, compute the
// number of unmatched bits with log2, mask the start address to obtain the
// network address, and format as "a.b.c.d/prefix".
//
// # IPv6 CIDR conversion
//
// ClickHouse has no native 128-bit integer type, so log2-based arithmetic
// is unreliable for the full 128-bit XOR. Instead we use the hex
// representation of the XOR FixedString(16):
//
//  1. XOR start and end: bitXor(start_bytes, end_bytes) → FixedString(16).
//     Bits that are 1 mark the host (unmatched) part of the range.
//
//  2. Convert to a 32-character hex string. Count leading '0' hex characters
//     (each represents 4 zero bits). Then inspect the first non-zero nibble to
//     count any additional leading zero bits within it (e.g. nibble 0x4 = 0100
//     → 1 more zero bit). Together these give the network prefix length.
//
//  3. Because DB-IP ranges are always CIDR-aligned, the start address is
//     already the network address, so no masking is needed. The CIDR is
//     formatted as "addr/prefix" using IPv6NumToString.
//
// # Graceful degradation
//
// IPv4 and IPv6 dictionaries are queried independently. A missing dictionary
// (ClickHouse error 495 UNKNOWN_DICTIONARY) returns empty fields for those
// addresses rather than an error, so partial initialisation (e.g. only IPv4
// sources provided) works without penalty.
package geoip

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
)

//go:embed schema.sql
var schemaSQL string

//go:embed schema_v6.sql
var schemaV6SQL string

//go:embed asn_schema.sql
var asnSchemaSQL string

//go:embed asn_schema_v6.sql
var asnSchemaV6SQL string

// GeoInfo holds geolocation and network info for a single IP address.
type GeoInfo struct {
	Country string `json:"country"`
	City    string `json:"city"`
	ASN     string `json:"asn"`
	Org     string `json:"org"`
}

// InitConfig holds the optional source URLs for each dictionary.
// Any field left empty skips initialisation of that dictionary.
type InitConfig struct {
	CityV4 string
	CityV6 string
	ASNV4  string
	ASNV6  string
}

// Init creates/refreshes the ip_trie, ip_trie_v6, asn_trie, and asn_trie_v6
// dictionaries in ClickHouse. Any source URL left empty skips that dictionary.
func Init(ctx context.Context, conn clickhouse.Conn, cfg InitConfig) error {
	type job struct{ sql, placeholder, url, label string }
	jobs := []job{
		{schemaSQL, "{source_url}", cfg.CityV4, "city v4"},
		{schemaV6SQL, "{source_url_v6}", cfg.CityV6, "city v6"},
		{asnSchemaSQL, "{asn_source_url}", cfg.ASNV4, "asn v4"},
		{asnSchemaV6SQL, "{asn_source_url_v6}", cfg.ASNV6, "asn v6"},
	}
	for _, j := range jobs {
		if j.url == "" {
			continue
		}
		sql := strings.ReplaceAll(j.sql, j.placeholder, j.url)
		for _, stmt := range splitStatements(sql) {
			if err := conn.Exec(ctx, stmt); err != nil {
				preview := stmt
				if len(preview) > 60 {
					preview = preview[:60] + "…"
				}
				return fmt.Errorf("geoip %s init (%s): %w", j.label, preview, err)
			}
		}
	}
	return nil
}

const cityV4SQL = `
SELECT ip,
    dictGetOrDefault('ip_trie',    'country_code', tuple(toIPv4OrDefault(ip)), '') AS country,
    dictGetOrDefault('ip_trie',    'city',         tuple(toIPv4OrDefault(ip)), '') AS city
FROM (SELECT arrayJoin(?) AS ip)`

const cityV6SQL = `
SELECT ip,
    dictGetOrDefault('ip_trie_v6', 'country_code', tuple(toIPv6OrDefault(ip)), '') AS country,
    dictGetOrDefault('ip_trie_v6', 'city',         tuple(toIPv6OrDefault(ip)), '') AS city
FROM (SELECT arrayJoin(?) AS ip)`

const asnV4SQL = `
SELECT ip,
    dictGetOrDefault('asn_trie',    'asn', tuple(toIPv4OrDefault(ip)), '') AS asn,
    dictGetOrDefault('asn_trie',    'org', tuple(toIPv4OrDefault(ip)), '') AS org
FROM (SELECT arrayJoin(?) AS ip)`

const asnV6SQL = `
SELECT ip,
    dictGetOrDefault('asn_trie_v6', 'asn', tuple(toIPv6OrDefault(ip)), '') AS asn,
    dictGetOrDefault('asn_trie_v6', 'org', tuple(toIPv6OrDefault(ip)), '') AS org
FROM (SELECT arrayJoin(?) AS ip)`

// LookupBatch resolves geo and ASN info for a list of IPs. IPv4 and IPv6
// addresses are queried against their respective dictionaries independently,
// so a missing dictionary returns empty fields rather than an error.
func LookupBatch(ctx context.Context, conn clickhouse.Conn, ips []string) (map[string]GeoInfo, error) {
	if len(ips) == 0 {
		return map[string]GeoInfo{}, nil
	}

	var v4, v6 []string
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}

	result := make(map[string]GeoInfo, len(ips))

	if err := queryCity(ctx, conn, cityV4SQL, v4, result); err != nil {
		return nil, err
	}
	if err := queryCity(ctx, conn, cityV6SQL, v6, result); err != nil {
		return nil, err
	}
	if err := queryASN(ctx, conn, asnV4SQL, v4, result); err != nil {
		return nil, err
	}
	if err := queryASN(ctx, conn, asnV6SQL, v6, result); err != nil {
		return nil, err
	}

	return result, nil
}

func queryCity(ctx context.Context, conn clickhouse.Conn, sql string, ips []string, result map[string]GeoInfo) error {
	if len(ips) == 0 {
		return nil
	}
	rows, err := conn.Query(ctx, sql, ips)
	if err != nil {
		if isDictUnavailable(err) {
			return nil
		}
		return fmt.Errorf("geoip city lookup: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip, country, city string
		if err := rows.Scan(&ip, &country, &city); err != nil {
			return fmt.Errorf("geoip city scan: %w", err)
		}
		result[ip] = GeoInfo{Country: country, City: city}
	}
	return rows.Err()
}

func queryASN(ctx context.Context, conn clickhouse.Conn, sql string, ips []string, result map[string]GeoInfo) error {
	if len(ips) == 0 {
		return nil
	}
	rows, err := conn.Query(ctx, sql, ips)
	if err != nil {
		if isDictUnavailable(err) {
			return nil
		}
		return fmt.Errorf("geoip asn lookup: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip, asn, org string
		if err := rows.Scan(&ip, &asn, &org); err != nil {
			return fmt.Errorf("geoip asn scan: %w", err)
		}
		info := result[ip]
		info.ASN = asn
		info.Org = org
		result[ip] = info
	}
	return rows.Err()
}

// DictionariesReady returns true when all four dictionaries (ip_trie,
// ip_trie_v6, asn_trie, asn_trie_v6) respond to a lightweight probe lookup.
// It is used to skip the expensive CSV re-import on restart when the data is
// already loaded.
func DictionariesReady(ctx context.Context, conn clickhouse.Conn) bool {
	probes := []string{
		`SELECT dictGetOrDefault('ip_trie',    'country_code', tuple(toIPv4OrDefault('1.1.1.1')), '')`,
		`SELECT dictGetOrDefault('ip_trie_v6', 'country_code', tuple(toIPv6OrDefault('2606:4700::1')), '')`,
		`SELECT dictGetOrDefault('asn_trie',   'asn',          tuple(toIPv4OrDefault('1.1.1.1')), '')`,
		`SELECT dictGetOrDefault('asn_trie_v6','asn',          tuple(toIPv6OrDefault('2606:4700::1')), '')`,
	}
	for _, sql := range probes {
		if err := conn.QueryRow(ctx, sql).Scan(new(string)); err != nil {
			return false
		}
	}
	return true
}

// isDictUnavailable reports whether err is a ClickHouse dictionary error that
// should be treated as "no data" rather than a fatal failure:
//   - 495 UNKNOWN_DICTIONARY: dictionary was never created (no source configured)
//   - 36  CANNOT_LOAD_DICTIONARY: dictionary exists but its last reload failed
//     (e.g. source URL temporarily unreachable)
func isDictUnavailable(err error) bool {
	var ex *clickhouse.Exception
	return errors.As(err, &ex) && (ex.Code == 495 || ex.Code == 36)
}

// splitStatements splits a SQL string into individual statements by semicolon,
// trimming whitespace and skipping empty entries.
func splitStatements(sql string) []string {
	parts := strings.Split(sql, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
