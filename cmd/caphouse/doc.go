// caphouse stores and exports classic PCAP files in ClickHouse.
//
// Usage:
//
//	caphouse [flags] [file ...]
//
// Input files (read mode) and the output file (write mode) are positional
// arguments. Multiple files and glob patterns are accepted in read mode.
// Omit files to read from stdin (write mode writes to stdout).
//
// The DSN must use the native ClickHouse protocol (clickhouse://host:9000/db).
// HTTP connections are not supported. The DSN can also be supplied via the
// CAPHOUSE_DSN environment variable.
//
// Examples:
//
//	# Ingest a file
//	caphouse --dsn="clickhouse://user:pass@localhost:9000/db" --sensor=myhost capture.pcap
//
//	# Ingest multiple files or a glob
//	caphouse --dsn="clickhouse://user:pass@localhost:9000/db" ring*.pcap
//
//	# Pipe from tcpdump
//	tcpdump -i eth0 -w - | caphouse --dsn="clickhouse://user:pass@localhost:9000/db" --sensor=myhost
//
//	# Export a capture to a file
//	caphouse -w --dsn="clickhouse://user:pass@localhost:9000/db" --capture=<uuid> out.pcap
//
//	# Export all captures within a time window, merged and time-sorted
//	caphouse -w --dsn="clickhouse://user:pass@localhost:9000/db" --capture=all \
//	  --query="time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z" merged.pcap
//
// For full flag documentation run caphouse --help or see
// https://cochaviz.github.io/caphouse/.
package main
