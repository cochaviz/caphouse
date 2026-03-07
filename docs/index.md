# caphouse

caphouse stores classic PCAP files in ClickHouse — parsed into protocol columns,
compressed, and reconstructible on demand.

Instead of writing raw frames to disk it splits each packet into its protocol
layers (Ethernet, VLAN, IPv4/6, TCP, UDP, …) and stores each layer in its own
table. The result is queryable at the column level — filter by IP, port, time
range, or any combination — while the original PCAP can be reconstructed
byte-for-byte at any time. Every packet is preserved; none are ever silently
dropped.

!!! warning "Status: experimental"

## Install

```sh
go install github.com/cochaviz/caphouse@latest
```

Or build from source:

```sh
go build -o caphouse ./cmd/caphouse
```

Requires Go 1.25+ and a ClickHouse instance reachable over the native protocol
(port 9000). HTTP is not supported.

## Testing

```sh
# Unit tests
go test ./...

# Integration tests — require Docker (spins up a ClickHouse container)
go test -tags integration -timeout 300s ./...

# Compression ratio report — requires Docker
go test -tags compression -v -timeout 300s .
```

CI runs unit and integration tests automatically on every push and pull request via GitHub Actions.
