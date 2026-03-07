# Storage & Compression

## How packets are stored

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

## Why this layout?

- **Narrow queries.** Filtering by destination IP touches only `pcap_ipv4`;
  filtering by port touches only `pcap_tcp` or `pcap_udp`. Raw frame bytes are
  never read during matching.
- **Columnar compression.** Protocol fields (IPs, ports, TTLs, sequence
  numbers, VLAN IDs) repeat heavily and compress extremely well when stored in
  dedicated columns.
- **Lossless reconstruction.** Every bit of every frame is preserved and the
  original PCAP can be reconstructed byte-for-byte on demand.

## Compression results

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

## Codec choices

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

## Sort keys

| Table | `ORDER BY` |
|-------|-----------|
| `pcap_packets` | `(capture_id, packet_id)` |
| `pcap_ethernet` | `(dst_mac, src_mac, capture_id, packet_id)` |
| `pcap_ipv4` | `(dst_ip_v4, src_ip_v4, capture_id, packet_id)` |
| `pcap_ipv6` | `(dst_ip_v6, src_ip_v6, capture_id, packet_id)` |
| all others | `(capture_id, packet_id)` |

## Deduplication

All tables use `ReplacingMergeTree`. Re-ingesting a file is safe — duplicates
are removed during background merges. On export, `FINAL` is applied to all
tables to guarantee a clean result even before background merges have caught up.
