# Filter Syntax

The `-f` / `--filter` flag accepts a ClickHouse SQL `WHERE` clause. Filters
are evaluated against stored protocol columns — no raw frame bytes are read
during matching.

## Writing filters

A filter is any valid ClickHouse boolean expression. You reference packet
fields using `component.field` notation:

```sh
# Packets with a specific destination IP
caphouse -w -d "..." -c <uuid> -f "ipv4.dst = '1.1.1.1'" out.pcap

# Packets on a specific port
caphouse -w -d "..." -c <uuid> -f "tcp.dst = 443" out.pcap

# Combining conditions
caphouse -w -d "..." -c <uuid> -f "ipv4.src = '10.0.0.1' AND tcp.dst = 443" out.pcap
```

Any `component.field` reference automatically INNER JOINs that component
table, so only packets that have that protocol layer are matched.

## Field aliases

Shorthand aliases expand to `(src OR dst)` checks automatically:

| Alias | Expands to |
|-------|-----------|
| `ipv4.addr = 'x'` | `(ipv4.src = 'x' OR ipv4.dst = 'x')` |
| `ipv6.addr = 'x'` | `(ipv6.src = 'x' OR ipv6.dst = 'x')` |
| `tcp.port = n` | `(tcp.src = n OR tcp.dst = n)` |
| `udp.port = n` | `(udp.src = n OR udp.dst = n)` |
| `ethernet.mac = 'x'` | `(ethernet.src = 'x' OR ethernet.dst = 'x')` |
| `arp.ip = 'x'` | `(arp.sender_ip = 'x' OR arp.target_ip = 'x')` |
| `arp.mac = 'x'` | `(arp.sender_mac = 'x' OR arp.target_mac = 'x')` |

Aliases also work with `!=`, `IN (...)`, `BETWEEN … AND …`, and as the first
argument to a function call (e.g. `match(ipv4.addr, '^10\.')`).

## Bare component names

A bare component name (without a `.field` suffix) matches any packet that
contains that protocol layer:

```sh
# Only TCP packets
-f "tcp"

# TCP or UDP packets
-f "tcp OR udp"

# TCP packets that are not DNS
-f "tcp AND NOT dns"
```

Bare component checks use the per-packet component bitmask and do not require
an INNER JOIN, so they are efficient even on large captures.

## Special column aliases

| Alias | Refers to |
|-------|-----------|
| `packet.ts` | packet timestamp (nanoseconds, `pcap_packets.ts`) |
| `packet.payload` | raw frame fallback bytes |
| `capture.sensor` | sensor name from `pcap_captures` |

## Time ranges with `--from` / `--to`

Time bounds are specified as separate flags rather than inline in the filter:

```sh
# Export packets from a one-hour window
caphouse -w -d "..." -c <uuid> \
  --from 2024-01-01T00:00:00Z --to 2024-01-01T01:00:00Z out.pcap

# Combine with a filter
caphouse -w -d "..." -c <uuid> \
  --from 2024-01-01T00:00:00Z --to 2024-01-01T01:00:00Z \
  -f "ipv4.addr = '10.0.0.1'" out.pcap
```

Both `--from` and `--to` are required when using `--capture all`.

## Querying across all captures

Pass `--capture all` (or `-c all`) to run the filter against every stored
capture. `--from` and `--to` are **required** with `--capture all`:

```sh
# Export matching packets from all captures in a one-hour window
caphouse -w -d "..." -c all \
  --from 2024-01-01T00:00:00Z --to 2024-01-01T01:00:00Z \
  -f "ipv4.addr = '10.0.0.1'" merged.pcap

# Generate SQL spanning all captures
caphouse -d "..." -c all \
  --from 2024-01-01T00:00:00Z --to 2024-01-01T01:00:00Z \
  | clickhouse-client --multiquery
```

The exported PCAP contains packets in strict time order (ties broken by
capture start time, then session ID). A warning is emitted when the merged
output contains captures with different link types.

## Generated SQL

Without `--components`:

```sql
SELECT
    p.*
FROM `db`.`pcap_packets` AS p
WHERE (p.session_id, p.packet_id) IN (
    -- filter subquery with all args inlined
)
LIMIT 1 BY p.session_id, p.packet_id
```

With `--components ipv4,tcp`:

```sql
SELECT
    p.*,
    ipv4.* EXCEPT (session_id, packet_id, codec_version),
    tcp.*  EXCEPT (session_id, packet_id, codec_version)
FROM `db`.`pcap_packets` AS p
LEFT JOIN `db`.`pcap_ipv4` AS ipv4 USING (session_id, packet_id)
LEFT JOIN `db`.`pcap_tcp`  AS tcp  USING (session_id, packet_id)
WHERE (p.session_id, p.packet_id) IN (
    -- filter subquery with all args inlined
)
LIMIT 1 BY p.session_id, p.packet_id
```

Other `--format` values accepted by `clickhouse-client`: `CSV` (no header),
`TSV`, `JSONEachRow`, `Parquet`, and [many more](https://clickhouse.com/docs/interfaces/formats).

## Available components

| `-C` value | Table joined |
|------------|-------------|
| `ethernet` | `pcap_ethernet` |
| `dot1q` | `pcap_dot1q` |
| `linuxsll` | `pcap_linuxsll` |
| `ipv4` | `pcap_ipv4` |
| `ipv6` | `pcap_ipv6` |
| `ipv6_ext` | `pcap_ipv6_ext` |
| `tcp` | `pcap_tcp` |
| `udp` | `pcap_udp` |
| `dns` | `pcap_dns` |
| `ntp` | `pcap_ntp` |
| `arp` | `pcap_arp` |
| `gre` | `pcap_gre` |
