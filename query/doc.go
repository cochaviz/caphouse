// Package query implements a tcpdump-style filter expression parser and
// ClickHouse SQL compiler for caphouse packet queries.
//
// # Parsing
//
// Use [ParseQuery] to compile a filter string into a [Query]:
//
//	q, err := query.ParseQuery("host 10.0.0.1 and port 443")
//
// Supported primitives:
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
//
// # SQL generation
//
// A [Query] compiles to ClickHouse SQL via INTERSECT / UNION DISTINCT / EXCEPT
// set operations. Call [Query.Subquery] to get an embeddable SQL fragment that
// returns (capture_id, packet_id) rows, or [Query.SQL] / [Query.SearchSQL] for
// full SELECT statements.
//
// Both methods require a [Tables] value that holds pre-qualified table
// references; obtain one from the caphouse client via its Tables() method.
//
// # Time range extraction
//
// [Query.TimeRange] returns the time bounds implied by any 'time' nodes in the
// filter. For AND queries the intersection of both sides is used; for OR
// queries the union. This is used by the export pipeline to prune captures
// before executing the full SQL filter.
package query
