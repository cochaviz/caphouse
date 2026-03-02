# caphouse

caphouse stores and exports classic PCAP files in ClickHouse.

Instead of writing raw frames to disk, it parses each packet into its protocol
layers and stores each layer in its own ClickHouse table. This makes packet data
queryable at the column level — filter by destination IP, protocol, or VLAN tag
without ever touching raw frame bytes — while still being able to reconstruct
the original PCAP losslessly on demand.

> **Status:** experimental

## Install

```sh
go install github.com/cochaviz/caphouse@latest
```

Or build from source:

```sh
go build -o caphouse ./cmd/caphouse
```

Requires Go 1.25+ and a ClickHouse instance reachable over the native protocol
(port 9000). HTTP connections are not supported.

## Quick start

```sh
# Ingest a file — creates a new capture and prints its UUID on completion
caphouse --dsn="clickhouse://user:pass@localhost:9000/default" \
         --sensor="myhost" --file=capture.pcap

# Export a capture back to PCAP
caphouse -w --dsn="clickhouse://user:pass@localhost:9000/default" \
            --capture=<uuid> --file=out.pcap
```

The schema is created automatically on the first read-mode invocation.

## Usage

### Modes

| Flag | Short | Description |
|------|-------|-------------|
| `--read` | `-r` | Ingest PCAP from file or stdin into ClickHouse. **Default** — the flag may be omitted. |
| `--write` | `-w` | Export a capture from ClickHouse as a PCAP file or stream. |

### Flags

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--dsn` | `CAPHOUSE_DSN` | — | ClickHouse connection string, e.g. `clickhouse://user:pass@host:9000/db`. Required. |
| `--db` | `CAPHOUSE_DB`, `CAPHOUSE_DATABASE` | from DSN | ClickHouse database. Falls back to the database in the DSN, then `default`. |
| `--sensor` | `CAPHOUSE_SENSOR` | — | Sensor name attached to the capture. Required in read mode. |
| `--capture` | — | new | In read mode: UUID of an existing capture to append to, or `new` (default) to create one. In write mode: UUID of the capture to export. Required in write mode. |
| `--file` | — | `-` | File path for input (read) or output (write). `-` means stdin / stdout. |
| `--batch-size` | — | 1000 | Number of packets per ClickHouse batch insert. |
| `--flush-interval` | — | 1s | Maximum time between batch flushes. |
| `--debug` | — | false | Enable verbose ClickHouse driver logging to stderr. |
| `--silent` | `-s` | false | Suppress warnings and progress output. |

### Examples

```sh
# Ingest from a file (new capture)
caphouse --dsn="..." --sensor="myhost" --file=capture.pcap

# Append packets to an existing capture
caphouse --dsn="..." --sensor="myhost" --file=more.pcap --capture=<uuid>

# Pipe from tcpdump
tcpdump -i eth0 -w - | caphouse --dsn="..." --sensor="myhost"

# Export to a file
caphouse -w --dsn="..." --capture=<uuid> --file=out.pcap

# Stream into tcpreplay
caphouse -w --dsn="..." --capture=<uuid> | tcpreplay --intf1=eth0 -
```

## Continuous capture with bounded disk usage

caphouse reads discrete files — it does not do live capture. The companion
script `caphouse-monitor` wraps tcpdump's built-in rotation with caphouse
ingest: each completed file is ingested into ClickHouse and then removed.

```sh
caphouse-monitor -i eth0 -d "clickhouse://user:pass@localhost:9000/default" -s myhost
```

By default, tcpdump rotates every 100 MB and keeps at most 10 files on disk
(~1 GB ring buffer). Override with `-C SIZE` and `-W COUNT`:

```sh
caphouse-monitor -i eth0 -d "..." -s myhost -C 50 -W 20  # 50 MB files, up to 20 (~1 GB)
```

DSN and sensor can also be provided via `CAPHOUSE_DSN` and `CAPHOUSE_SENSOR`.

Files are only removed after a successful ingest. If ClickHouse is temporarily
unavailable, caphouse retries with exponential backoff and jitter before giving
up; if it ultimately fails, the file is left on disk for the next rotation cycle
to attempt again.

`caphouse-monitor` is installed alongside `caphouse` by `make install`. It uses
`inotifywait` on Linux and `fswatch` on macOS to detect completed rotation files.

## Storage model

Each frame is decoded into its constituent protocol layers. Each layer type has
its own ClickHouse table, keyed by `(capture_id, packet_id)`. A bitmask column
in `pcap_packets` records which layer tables hold rows for a given packet.

```
pcap_captures      capture-level metadata (sensor, link type, snaplen, …)
pcap_packets       per-packet nucleus (timestamp, lengths, component bitmask)

pcap_ethernet      │
pcap_dot1q         │ L2 — one row per packet
pcap_linuxsll      │    (dot1q: one row per VLAN tag)

pcap_ipv4          │
pcap_ipv4_options  │ L3 — one row per packet
pcap_ipv6          │
pcap_ipv6_ext      │    (ipv6_ext: one row per extension header)

pcap_raw_tail      payload bytes from tail_offset to end of frame
```

If a frame cannot be fully parsed — unknown link type, malformed headers — the
raw bytes are stored in `pcap_packets.frame_raw` and recovered verbatim on
export. No packet is ever silently dropped.

### Why this layout?

- **Narrow queries.** Scanning destination IPs touches only `pcap_ipv4`; it
  never reads raw frame bytes.
- **Columnar compression.** Protocol fields (IPs, ports, TTLs, VLAN IDs) repeat
  and compress well when stored together.
- **Partial reconstruction.** Payload bytes live in `pcap_raw_tail`, separate
  from header metadata, so header columns stay small.

### Deduplication

All tables use `ReplacingMergeTree`. Duplicates are removed during background
merges, making it safe to re-ingest a file (e.g. after a failed run). On
export, `FINAL` is applied to all tables to guarantee a clean result even
before background merges have caught up.

## Testing

```sh
# Unit tests
go test ./...

# Integration tests — require Docker (spins up a ClickHouse container)
go test -tags integration -timeout 300s ./...

# Compression ratio report — require Docker
go test -tags compression -v -timeout 120s .
```

CI runs unit and integration tests automatically on every push and pull request via GitHub Actions.
