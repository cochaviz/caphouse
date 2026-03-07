# caphouse

caphouse stores classic PCAP files in ClickHouse — parsed into protocol columns,
compressed, and reconstructible on demand.

Instead of writing raw frames to disk it splits each packet into its protocol
layers (Ethernet, VLAN, IPv4/6, TCP, UDP, …) and stores each layer in its own
table. The result is queryable at the column level — filter by IP, port, time
range, or any combination — while the original PCAP can be reconstructed
byte-for-byte at any time. Every packet is preserved; none are ever silently
dropped.

> **Status:** experimental
> **Docs:** https://cochaviz.github.io/caphouse/

## Install

```sh
go install github.com/cochaviz/caphouse@latest
```

Requires Go 1.25+ and a ClickHouse instance on port 9000 (native protocol).

## Quick example

```sh
# Ingest
caphouse -d "clickhouse://user:pass@localhost:9000/default" --sensor myhost -f capture.pcap

# Export
caphouse -w -d "..." -c <uuid> -f out.pcap

# Filter and export
caphouse -w -d "..." -c <uuid> -q "host 10.0.0.1 and port 443" -f filtered.pcap

# Print SQL for a filter
caphouse -d "..." -c <uuid> -q "host 10.0.0.1"
```

## Testing

```sh
go test ./...                                            # unit tests
go test -tags integration -timeout 300s ./...           # requires Docker
```
