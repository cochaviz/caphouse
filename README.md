# caphouse

Store and export classic PCAPs in ClickHouse using the native protocol.

Status: experimental.

## Usage

Modes:
- `read`: read PCAP from file/stdin and write into ClickHouse
- `write`: read from ClickHouse and write PCAP to file/stdout

Required flags:
- `--dsn` (or `CAPHOUSE_DSN`)
- `--sensor` for `read`
- `--capture` for `write`

Examples:
```
caphouse --mode=read --dsn="clickhouse://user:pass@localhost:9000/default" --file capture.pcap --sensor test --capture new
caphouse --mode=write --dsn="clickhouse://user:pass@localhost:9000/default" --capture <uuid> --file out.pcap
```

Notes:
- HTTP DSNs are not supported; use `clickhouse://` with the native port.
- Test fixtures live under `testdata/`.

## Component Storage Model

Packets are stored in a normalized, component-based schema:
- `pcap_packets` holds the nucleus (timestamps, lengths, component bitmask, optional raw frame/hash).
- Protocol layers (Ethernet, Dot1Q, IPv4/IPv6, IPv6 ext, raw tail) live in separate tables keyed by `(capture_id, packet_id)`.
- A bitmask in `pcap_packets.components` indicates which component rows exist.

This layout is efficient because it:
- Avoids rewriting large raw frames for every query; only the required layers are touched.
- Enables columnar compression on per-layer fields (e.g., IPs, ports, VLAN IDs).
- Keeps hot queries narrow (scan only the relevant component table).
- Allows partial reconstruction; if parsing fails, raw bytes are still preserved via the raw tail/raw frame.

`raw_tail` stores the payload bytes that follow the parsed headers, starting at `tail_offset`. This preserves unparsed data and enables full frame reconstruction without storing the entire frame in every layer table.

## Enhancements (Planned)

- Efficient PCAP retrieval through JOIN operations and bulk decodes (currently decode per-packet).
- Code quality improvements in `export.go` (currently very bare-bones) and `ingest.go` (abstractions available but not yet used).
- Increase test coverage.
