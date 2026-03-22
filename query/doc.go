// Package query provides a raw-SQL WHERE clause query type for filtering
// network packet captures stored in ClickHouse.
//
// Users write standard ClickHouse SQL predicates referencing component tables
// by name (e.g. ipv4.dst = '1.1.1.1', tcp.src = 80). The package detects
// which component tables are needed and INNER JOINs them automatically.
//
// # Query syntax
//
// A query is a raw ClickHouse WHERE clause body. Component tables are
// referenced as "component.field", e.g.:
//
//	ipv4.dst = '1.1.1.1' and udp.dst = 53
//	tcp.flags & 2 != 0
//	dns
//
// A bare component name (no dot) is a presence check: packets are filtered
// to those that have that component (via INNER JOIN with no extra condition).
//
// # Aliases
//
// Short component name: eth → ethernet
//
// Field aliases that expand to src/dst pairs (= operator only):
//
//	ipv4.addr    → (ipv4.src = val or ipv4.dst = val)
//	ipv6.addr    → (ipv6.src = val or ipv6.dst = val)
//	tcp.port     → (tcp.src = val or tcp.dst = val)
//	udp.port     → (udp.src = val or udp.dst = val)
//	ethernet.mac → (ethernet.src = val or ethernet.dst = val)
//	arp.ip       → (arp.sender_ip = val or arp.target_ip = val)
//	arp.mac      → (arp.sender_mac = val or arp.target_mac = val)
//
// # Time range
//
// Time-bounded searches pass fromNs/toNs (Unix nanoseconds) directly to
// [Query.SearchSQL] and [Query.CountsSQL]. The condition is applied to the
// absolute packet timestamp (capture start + relative offset) in the outer
// query, using the captures table that is already joined there.
package query
