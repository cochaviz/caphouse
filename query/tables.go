package query

// Tables holds pre-computed, fully-qualified ClickHouse table references used
// when building filter queries. Construct one from a [caphouse.Client] via its
// Tables() method.
type Tables struct {
	Packets    string // e.g. "`mydb`.`pcap_packets`"
	Captures   string // e.g. "`mydb`.`pcap_captures`"
	Components map[string]ComponentInfo // keyed by alias, e.g. "ipv4", "tcp"
}

// ComponentInfo holds the fully-qualified table reference and short alias for
// a single protocol component table.
type ComponentInfo struct {
	TableRef string   // fully-qualified, e.g. "`mydb`.`pcap_ipv4`"
	Alias    string   // short alias, e.g. "ipv4"
	Columns  []string // prefixed SELECT expressions, e.g. ["ipv4.src AS ipv4_src", ...]
}
