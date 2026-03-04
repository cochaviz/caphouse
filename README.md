# caphouse

caphouse stores and exports classic PCAP files in ClickHouse.

Instead of writing raw frames to disk, it parses each packet into its protocol
layers and stores each layer in its own ClickHouse table. This makes packet data
queryable at the column level — filter by destination IP, port, protocol, or
VLAN tag without ever touching raw frame bytes — while still being able to
reconstruct the original PCAP losslessly on demand.

Supported protocol layers: Ethernet, dot1q (VLAN), Linux SLL, IPv4, IPv6, TCP,
and UDP.

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
caphouse -d "clickhouse://user:pass@localhost:9000/default" \
         --sensor="myhost" -f capture.pcap

# Export a capture back to PCAP
caphouse -w -d "clickhouse://user:pass@localhost:9000/default" \
            --capture=<uuid> -f out.pcap
```

The schema is created automatically on the first read-mode invocation.

## Usage

### Modes

| Flag | Short | Description |
|------|-------|-------------|
| `--read` | `-r` | Ingest PCAP from file or stdin into ClickHouse. **Default** — the flag may be omitted. |
| `--write` | `-w` | Export a capture from ClickHouse as a PCAP file or stream. |

### Flags

| Flag | Short | Env var | Default | Description |
|------|-------|---------|---------|-------------|
| `--dsn` | `-d` | `CAPHOUSE_DSN` | — | ClickHouse connection string, e.g. `clickhouse://user:pass@host:9000/db`. Required. |
| `--sensor` | | `CAPHOUSE_SENSOR` | hostname | Sensor name attached to the capture. Falls back to the system hostname in read mode. |
| `--capture` | | — | new | In read mode: UUID of an existing capture to append to, or `new` (default) to create one. In write mode: UUID of the capture to export. Required in write mode. |
| `--file` | `-f` | — | `-` | File path for input (read) or output (write). `-` means stdin / stdout. |
| `--batch-size` | | — | 1000 | Number of packets per ClickHouse batch insert. |
| `--flush-interval` | | — | 1s | Maximum time between batch flushes. |
| `--debug` | | — | false | Enable verbose ClickHouse driver logging to stderr. |
| `--silent` | `-s` | — | false | Suppress warnings and progress output. |
| `--version` | `-v` | — | — | Print version and exit. |

### Examples

```sh
# Ingest from a file (new capture; sensor defaults to hostname)
caphouse -d "..." -f capture.pcap

# Ingest with an explicit sensor name
caphouse -d "..." --sensor="myhost" -f capture.pcap

# Append packets to an existing capture
caphouse -d "..." -f more.pcap --capture=<uuid>

# Pipe from tcpdump
tcpdump -i eth0 -w - | caphouse -d "..."

# Export to a file
caphouse -w -d "..." --capture=<uuid> -f out.pcap

# Stream into tcpreplay
caphouse -w -d "..." --capture=<uuid> | tcpreplay --intf1=eth0 -
```

## Continuous capture with bounded disk usage

caphouse reads discrete files — it does not do live capture. The companion
script `caphouse-monitor` wraps tcpdump's built-in rotation with caphouse
ingest: each completed file is ingested into ClickHouse and then removed.

```sh
caphouse-monitor -i eth0 -d "clickhouse://user:pass@localhost:9000/default" -s myhost
```

By default, tcpdump rotates every 60 seconds. Override with `-t SECS`:

```sh
caphouse-monitor -i eth0 -d "..." -s myhost -t 300  # rotate every 5 minutes
```

The capture directory defaults to `/var/capture`. Override with `-D DIR`.

DSN and sensor can also be provided via `CAPHOUSE_DSN` and `CAPHOUSE_SENSOR`.

Files are only removed after a successful ingest. If ClickHouse is temporarily
unavailable, caphouse retries with exponential backoff and jitter before giving
up; if it ultimately fails, the file is left on disk for the next rotation cycle
to attempt again.

`caphouse-monitor` is installed alongside `caphouse` by `make install`. It uses
`inotifywait` on Linux and `lsof` polling on macOS to detect completed rotation
files.

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

pcap_tcp           │
pcap_udp           │ L4 — one row per packet

pcap_raw_tail      payload bytes from tail_offset to end of frame
```

If a frame cannot be fully parsed — unknown link type, malformed headers — the
raw bytes are stored in `pcap_packets.frame_raw` and recovered verbatim on
export. No packet is ever silently dropped.

### Why this layout?

- **Narrow queries.** Scanning destination IPs touches only `pcap_ipv4`;
  filtering by port touches only `pcap_tcp` or `pcap_udp`. Neither ever reads
  raw frame bytes.
- **Columnar compression.** Protocol fields (IPs, ports, TTLs, VLAN IDs) repeat
  and compress well when stored together.
- **Partial reconstruction.** Payload bytes live in `pcap_raw_tail`, separate
  from header metadata, so header columns stay small.

### Compression

Sequential and monotonic columns carry explicit codecs; low-cardinality fields use dictionary encoding:

| Column | Tables | Encoding |
|--------|--------|----------|
| `packet_id` | all | `CODEC(Delta, LZ4)` — differences are always 1 |
| `ts` | packets, ipv4, ipv6 | `CODEC(DoubleDelta, LZ4)` — monotonically increasing nanosecond timestamps |
| `incl_len`, `orig_len` | packets | `CODEC(Delta, LZ4)` — lengths cluster tightly |
| `tail_offset` | packets, raw\_tail | `CODEC(Delta, LZ4)` |
| `ipv4_total_len`, `ipv6_payload_len` | ipv4, ipv6 | `CODEC(Delta, LZ4)` |
| `seq`, `ack` | tcp | `CODEC(Delta, LZ4)` — sequence numbers increment monotonically in most flows |
| MAC addresses | ethernet | `FixedString(6)` — raw 6 bytes instead of a 17-char formatted string |
| `frame_raw` | packets | `CODEC(ZSTD(3))` — higher ZSTD level for the raw fallback frame blob |
| `bytes` | raw\_tail | `CODEC(ZSTD(3))` — same for the payload blob |
| `options_raw` | tcp | `CODEC(ZSTD(3))` — TCP options blob |

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
