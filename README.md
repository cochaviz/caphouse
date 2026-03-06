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
            -c <uuid> -f out.pcap
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
| `--capture` | `-c` | — | new | In read mode: UUID of an existing capture to append to, or `new` (default) to create one. In write/query mode: UUID of the capture to operate on. Required in write and explain mode. |
| `--file` | `-f` | — | `-` | File path for input (read) or output (write). `-` means stdin / stdout. |
| `--query` | `-q` | — | — | Filter expression (see [Filter syntax](#filter-syntax)). Without `--write`: prints the equivalent ClickHouse SQL (see [SQL explain mode](#sql-explain-mode)). With `--write`: exports only matching packets as PCAP. |
| `--components` | `-C` | — | — | Comma-separated protocol tables to LEFT JOIN into the SQL output (e.g. `ipv4,tcp`). Only valid with `--query` without `--write`. |
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
caphouse -d "..." -f more.pcap -c <uuid>

# Pipe from tcpdump
tcpdump -i eth0 -w - | caphouse -d "..."

# Export to a file
caphouse -w -d "..." -c <uuid> -f out.pcap

# Stream into tcpreplay
caphouse -w -d "..." -c <uuid> | tcpreplay --intf1=eth0 -

# Export only packets matching a filter
caphouse -w -d "..." -c <uuid> -q "host 10.0.0.1 and port 443" -f filtered.pcap

# Pipe filtered packets into tcpdump for live inspection
caphouse -w -d "..." -c <uuid> -q "src host 10.0.0.1" | tcpdump -r -

# Print the ClickHouse SQL for a filter (no --write)
caphouse -d "..." -c <uuid> -q "host 10.0.0.1"

# Pipe the SQL directly into clickhouse-client
caphouse -d "..." -c <uuid> -q "host 10.0.0.1" | clickhouse-client --multiquery

# Include protocol columns via LEFT JOINs
caphouse -d "..." -c <uuid> -q "port 443" -C ipv4,tcp | clickhouse-client --multiquery
```

## Filter syntax

The `--query` flag accepts a tcpdump-style filter expression. Filters are evaluated
against the stored protocol columns — no raw frame bytes are read during matching.

### Primitives

| Expression | Matches |
|------------|---------|
| `host <ip>` | src or dst IP (IPv4 or IPv6) |
| `src host <ip>` | source IP only |
| `dst host <ip>` | destination IP only |
| `port <n>` | src or dst TCP or UDP port |
| `src port <n>` | source port only |
| `dst port <n>` | destination port only |
| `time <rfc3339> to <rfc3339>` | packet timestamp within range |

### Combinators

Primitives can be combined with `and`, `or`, `not`, and parentheses:

```
src host 10.0.0.1 and port 443
host 192.168.1.0 or host 192.168.1.1
not port 22
(src host 10.0.0.1 or src host 10.0.0.2) and dst port 80
time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z
```

## SQL explain mode

Running `--query` without `--write` prints the equivalent ClickHouse `SELECT`
statement with all parameters inlined, ready to pipe into `clickhouse-client`.
No packets are read or exported — the output is pure SQL.

```sh
caphouse -d "clickhouse://user:pass@localhost:9000/db" \
         -c <uuid> -q "src host 10.0.0.1 and port 443" \
         | clickhouse-client --multiquery
```

By default the query selects from `pcap_packets` only. Use `--components` /
`-C` to LEFT JOIN one or more protocol tables and include their columns in the
result:

```sh
caphouse -d "..." -c <uuid> -q "port 443" -C ipv4,tcp \
         | clickhouse-client --multiquery
```

Supported component names:

| Name | Table |
|------|-------|
| `ethernet` | `pcap_ethernet` |
| `dot1q` | `pcap_dot1q` |
| `linuxsll` | `pcap_linuxsll` |
| `ipv4` | `pcap_ipv4` |
| `ipv4_options` | `pcap_ipv4_options` |
| `ipv6` | `pcap_ipv6` |
| `ipv6_ext` | `pcap_ipv6_ext` |
| `tcp` | `pcap_tcp` |
| `udp` | `pcap_udp` |
| `raw_tail` | `pcap_raw_tail` |

### Generated SQL shape

Without `--components`:

```sql
SELECT
    p.*
FROM `db`.`pcap_packets` AS p FINAL
WHERE (p.capture_id, p.packet_id) IN (
    -- filter subquery with all args inlined
)
```

With `--components ipv4,tcp`:

```sql
SELECT
    p.*,
    ipv4.* EXCEPT (capture_id, packet_id, codec_version),
    tcp.* EXCEPT (capture_id, packet_id, codec_version)
FROM `db`.`pcap_packets` AS p FINAL
LEFT JOIN `db`.`pcap_ipv4` AS ipv4 FINAL USING (capture_id, packet_id)
LEFT JOIN `db`.`pcap_tcp`  AS tcp  FINAL USING (capture_id, packet_id)
WHERE (p.capture_id, p.packet_id) IN (
    -- filter subquery with all args inlined
)
```

### Tips and tricks

**Pretty-print the SQL** using `clickhouse-format` (ships with ClickHouse):

```sh
caphouse -d "..." -c <uuid> -q "port 443" -C ipv4,tcp | clickhouse-format
```

**Run the query directly** by piping into `clickhouse-client`:

```sh
caphouse -d "..." -c <uuid> -q "port 443" -C ipv4,tcp \
  | clickhouse-client --multiquery
```

**Combine both** — format first, then execute:

```sh
caphouse -d "..." -c <uuid> -q "port 443" -C ipv4,tcp \
  | clickhouse-format \
  | clickhouse-client --multiquery
```

**Export as CSV** using `clickhouse-client`'s `--format` flag:

```sh
caphouse -d "..." -c <uuid> -q "port 443" -C ipv4,tcp \
  | clickhouse-client --multiquery --format CSVWithNames > packets.csv
```

Other useful formats: `CSV` (no header), `TSV`, `JSONEachRow`, `Parquet`.

**Inspect or edit before running** by saving to a file:

```sh
caphouse -d "..." -c <uuid> -q "host 10.0.0.1" > query.sql
# review / tweak query.sql, then:
clickhouse-client --multiquery < query.sql
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
its own ClickHouse table. A bitmask column in `pcap_packets` records which layer
tables hold rows for a given packet.

Sort keys are tuned per table: L2/L3 tables lead with address columns so that
rows for the same endpoint pair are physically adjacent, which both improves
compression and allows address-based queries to skip large portions of the table
without reading raw frames.

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

Codecs and sort keys are chosen per column based on the data's statistical
properties:

| Column | Table(s) | Codec | Notes |
|--------|----------|-------|-------|
| `packet_id` | ethernet, ipv4, ipv6 | `DoubleDelta, LZ4` | Monotonically increasing within each address-group; delta-of-deltas approaches zero |
| `packet_id` | all others | `Delta, LZ4` | Sorted by `(capture_id, packet_id)` so differences are always 1 |
| `ts` | packets | `ZSTD(9)` | Stored as nanosecond offset from capture start; not in sort key so delta codecs don't help |
| `incl_len` | packets | `Delta, LZ4` | Lengths cluster tightly within a capture |
| `trunc_extra` | packets | `ZSTD(9)` | `orig_len − incl_len`; zero for non-truncated packets (~100% of rows) |
| `ipv4_total_len`, `ipv6_payload_len` | ipv4, ipv6 | `Delta, LZ4` | Packet sizes repeat heavily within a flow |
| `ipv4_flags` | ipv4 | `ZSTD(9)` | Low cardinality but not sorted by flags, so ZSTD beats plain LZ4 |
| `seq`, `ack` | tcp | `Delta, LZ4` | Sequence numbers increment monotonically in most flows |
| MAC addresses | ethernet | `FixedString(6)` | Raw 6 bytes; sort key groups same-pair rows together |
| `frame_raw` | packets | `ZSTD(3)` | Raw fallback frame blob |
| `bytes` | raw\_tail | `ZSTD(3)` | Payload blob |
| `options_raw` | tcp | `ZSTD(3)` | TCP options blob |

**Sort keys by table:**

| Table | `ORDER BY` |
|-------|-----------|
| `pcap_packets` | `(capture_id, packet_id)` |
| `pcap_ethernet` | `(dst_mac, src_mac, capture_id, packet_id)` |
| `pcap_ipv4` | `(dst_ip_v4, src_ip_v4, capture_id, packet_id)` |
| `pcap_ipv6` | `(dst_ip_v6, src_ip_v6, capture_id, packet_id)` |
| all others | `(capture_id, packet_id)` |

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
