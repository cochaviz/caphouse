# Filter Syntax

The `-q` flag accepts a tcpdump-style expression. Filters are evaluated against
stored protocol columns — no raw frame bytes are read during matching.

## Primitives

| Expression | Matches |
|------------|---------|
| `host <ip>` | src or dst IP (IPv4 or IPv6) |
| `src host <ip>` | source IP only |
| `dst host <ip>` | destination IP only |
| `port <n>` | src or dst TCP or UDP port |
| `src port <n>` | source port only |
| `dst port <n>` | destination port only |
| `time <rfc3339> to <rfc3339>` | packet timestamp within range |

## Combinators

Primitives can be combined with `and`, `or`, `not`, and parentheses:

```
src host 10.0.0.1 and port 443
host 192.168.1.0 or host 192.168.1.1
not port 22
(src host 10.0.0.1 or src host 10.0.0.2) and dst port 80
time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z
```

## Querying across all captures

Pass `-c all` (or `--capture all`) instead of a specific UUID to run the filter
against every stored capture. A `time` primitive is **required** when using
`-c all`:

```sh
# Export matching packets from all captures in a one-hour window
caphouse -w -d "..." -c all \
  -q "time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z and host 10.0.0.1" \
  merged.pcap

# Generate SQL spanning all captures
caphouse -d "..." -c all \
  -q "time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z" \
  | clickhouse-client --multiquery
```

The exported PCAP contains packets in strict time order (ties broken by capture
start time, then capture UUID). A warning is emitted when the merged output
contains captures with different link types.

## Generated SQL

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

Other `--format` values accepted by `clickhouse-client`: `CSV` (no header),
`TSV`, `JSONEachRow`, `Parquet`, and [many more](https://clickhouse.com/docs/interfaces/formats).

## Available components

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
