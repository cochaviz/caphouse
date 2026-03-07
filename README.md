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

## Three things you can do

### 1. Ingest a PCAP

```sh
# From a file — prints the capture UUID on completion
caphouse -d "clickhouse://user:pass@localhost:9000/default" \
         --sensor myhost -f capture.pcap

# From tcpdump over a pipe
tcpdump -i eth0 -w - | caphouse -d "..."

# Append to an existing capture
caphouse -d "..." -f more.pcap -c <uuid>
```

The schema is created automatically on the first ingest.

### 2. Export a PCAP

```sh
# Export an entire capture to a file
caphouse -w -d "..." -c <uuid> -f out.pcap

# Stream into tcpreplay
caphouse -w -d "..." -c <uuid> | tcpreplay --intf1=eth0 -

# Export only matching packets (tcpdump-style filter)
caphouse -w -d "..." -c <uuid> -q "host 10.0.0.1 and port 443" -f filtered.pcap

# Pipe filtered packets into tcpdump for live inspection
caphouse -w -d "..." -c <uuid> -q "src host 10.0.0.1" | tcpdump -r -
```

### 3. Query packets directly with SQL

`-q` without `-w` prints the equivalent ClickHouse `SELECT` statement with all
parameters inlined — ready to pipe into `clickhouse-client` or tweak by hand.
No packets are read or exported; the output is pure SQL.

```sh
# Print the SQL for a filter
caphouse -d "..." -c <uuid> -q "host 10.0.0.1"

# Run it directly
caphouse -d "..." -c <uuid> -q "host 10.0.0.1" | clickhouse-client --multiquery

# Add protocol columns with --components / -C
caphouse -d "..." -c <uuid> -q "port 443" -C ipv4,tcp \
  | clickhouse-client --multiquery

# Export as CSV
caphouse -d "..." -c <uuid> -q "port 443" -C ipv4,tcp \
  | clickhouse-client --multiquery --format CSVWithNames > packets.csv

# Export as JSON
caphouse -d "..." -c <uuid> -q "port 443" -C ipv4,tcp \
  | clickhouse-client --multiquery --format JSONEachRow > packets.jsonl

# Pretty-print the SQL before running it
caphouse -d "..." -c <uuid> -q "port 443" -C ipv4,tcp | clickhouse-format

# Save, edit, then run
caphouse -d "..." -c <uuid> -q "host 10.0.0.1" > query.sql
$EDITOR query.sql
clickhouse-client --multiquery < query.sql
```

Other `--format` values accepted by `clickhouse-client`: `CSV` (no header),
`TSV`, `JSONEachRow`, `Parquet`, and [many more](https://clickhouse.com/docs/interfaces/formats).

#### Generated SQL shape

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
    tcp.*  EXCEPT (capture_id, packet_id, codec_version)
FROM `db`.`pcap_packets` AS p FINAL
LEFT JOIN `db`.`pcap_ipv4` AS ipv4 FINAL USING (capture_id, packet_id)
LEFT JOIN `db`.`pcap_tcp`  AS tcp  FINAL USING (capture_id, packet_id)
WHERE (p.capture_id, p.packet_id) IN (
    -- filter subquery with all args inlined
)
```

#### Available components

| `-C` value | Table joined |
|------------|-------------|
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

## Filter syntax

The `-q` flag accepts a tcpdump-style expression. Filters are evaluated against
stored protocol columns — no raw frame bytes are read during matching.

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

## All flags

| Flag | Short | Env var | Default | Description |
|------|-------|---------|---------|-------------|
| `--dsn` | `-d` | `CAPHOUSE_DSN` | — | ClickHouse DSN, e.g. `clickhouse://user:pass@host:9000/db`. Required. |
| `--sensor` | | — | hostname | Sensor name attached to the capture. Falls back to the system hostname in read mode. |
| `--capture` | `-c` | — | new | Capture UUID. In read mode: existing capture to append to, or `new` to create one. In write/query mode: required. |
| `--file` | `-f` | — | `-` | Input (read) or output (write) file path. `-` means stdin/stdout. |
| `--read` | `-r` | — | — | Ingest mode (default; flag may be omitted). |
| `--write` | `-w` | — | — | Export mode — write a PCAP. |
| `--query` | `-q` | — | — | Filter expression. Without `--write`: prints SQL. With `--write`: exports matching packets as PCAP. |
| `--components` | `-C` | — | — | Comma-separated protocol tables to LEFT JOIN in SQL output (e.g. `ipv4,tcp`). Requires `-q` without `-w`. |
| `--batch-size` | | — | 1000 | Packets per ClickHouse batch insert. |
| `--flush-interval` | | — | 1s | Maximum time between batch flushes. |
| `--silent` | `-s` | — | false | Suppress warnings and progress output. |
| `--debug` | | — | false | Enable verbose ClickHouse driver logging to stderr. |
| `--version` | `-v` | — | — | Print version and exit. |

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
DSN can also be provided via `CAPHOUSE_DSN`.

Files are only removed after a successful ingest. If ClickHouse is temporarily
unavailable, caphouse retries with exponential backoff and jitter; if it
ultimately fails the file is left on disk for the next rotation cycle. `caphouse-monitor`
is installed alongside `caphouse` by `make install`.

## Storage and compression

### How packets are stored

Each packet is split into its protocol layers. Every layer type has its own
ClickHouse table:

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

pcap_raw_tail      payload bytes beyond the parsed headers
```

If a frame cannot be fully parsed the raw bytes are stored in
`pcap_packets.frame_raw` and recovered verbatim on export. No packet is ever
silently dropped.

### Why this layout?

- **Narrow queries.** Filtering by destination IP touches only `pcap_ipv4`;
  filtering by port touches only `pcap_tcp` or `pcap_udp`. Raw frame bytes are
  never read during matching.
- **Columnar compression.** Protocol fields (IPs, ports, TTLs, sequence
  numbers, VLAN IDs) repeat heavily and compress extremely well when stored in
  dedicated columns.
- **Lossless reconstruction.** Every bit of every frame is preserved and the
  original PCAP can be reconstructed byte-for-byte on demand.

### Compression results

Tested on a 174.8 MB SYN-flood capture (2.58 million packets, 100% parsed):

| | Size | vs raw PCAP |
|--|------|------------|
| Raw PCAP | 174.8 MB | 1x |
| ClickHouse (on disk) | 35.5 MB | **4.9x smaller** |
| xz -9 (reference) | 21.4 MB | 8.2x smaller |

ClickHouse stores the data at roughly **5x compression** compared to the
original PCAP — approaching `xz -9` at maximum compression, but remaining fully
queryable, filterable, and randomly accessible.

Per-table compression ratios on the same capture:

| Table | Logical size | On-disk size | Ratio |
|-------|-------------|--------------|-------|
| `pcap_ethernet` | 98.5 MB | 1.4 MB | **70x** |
| `pcap_packets` | 108.4 MB | 1.8 MB | **59x** |
| `pcap_raw_tail` | 64.0 MB | 1.4 MB | **45x** |
| `pcap_ipv4` | 113.3 MB | 8.6 MB | **13x** |

Ethernet and packet-nucleus columns compress so aggressively because the
sort keys group rows from the same source-destination pair together, making
delta and delta-of-delta codecs near-lossless.

### Codec choices

| Column | Table(s) | Codec | Rationale |
|--------|----------|-------|-----------|
| `packet_id` | ethernet, ipv4, ipv6 | `DoubleDelta, LZ4` | Sorted by address pair; delta-of-deltas approaches zero |
| `packet_id` | all others | `Delta, LZ4` | Sequential within `(capture_id, packet_id)` order |
| `ts` | packets | `ZSTD(9)` | Nanosecond offset; not in sort key so delta codecs don't help |
| `incl_len` | packets | `Delta, LZ4` | Packet lengths cluster tightly within a capture |
| `trunc_extra` | packets | `ZSTD(9)` | `orig_len − incl_len`; zero for ~100% of packets |
| `ipv4_total_len`, `ipv6_payload_len` | ipv4, ipv6 | `Delta, LZ4` | Sizes repeat heavily within a flow |
| `ipv4_flags` | ipv4 | `ZSTD(9)` | Low cardinality; ZSTD beats LZ4 here |
| `seq`, `ack` | tcp | `Delta, LZ4` | Sequence numbers increment monotonically per flow |
| MAC addresses | ethernet | `FixedString(6)` | Raw 6 bytes; sort key collocates same-pair rows |
| `frame_raw` | packets | `ZSTD(3)` | Raw fallback blob |
| `bytes` | raw\_tail | `ZSTD(3)` | Payload blob |
| `options_raw` | tcp | `ZSTD(3)` | TCP options blob |

### Sort keys

| Table | `ORDER BY` |
|-------|-----------|
| `pcap_packets` | `(capture_id, packet_id)` |
| `pcap_ethernet` | `(dst_mac, src_mac, capture_id, packet_id)` |
| `pcap_ipv4` | `(dst_ip_v4, src_ip_v4, capture_id, packet_id)` |
| `pcap_ipv6` | `(dst_ip_v6, src_ip_v6, capture_id, packet_id)` |
| all others | `(capture_id, packet_id)` |

### Deduplication

All tables use `ReplacingMergeTree`. Re-ingesting a file is safe — duplicates
are removed during background merges. On export, `FINAL` is applied to all
tables to guarantee a clean result even before background merges have caught up.

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
