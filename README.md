# caphouse

Store and export classic PCAPs in ClickHouse using the native protocol.

Status: experimental.

## Usage

Modes:

- `--read` / `-r`: read PCAP from file/stdin and write into ClickHouse (default, flag may be omitted)
- `--write` / `-w`: read from ClickHouse and write PCAP to file/stdout

Required flags:

- `--dsn` (or `CAPHOUSE_DSN`)
- `--sensor` for `read`
- `--capture` for `write`

In `read` mode, `--capture` is optional:

- Omit it (or pass `--capture new`) to create a new capture; its UUID is printed on completion.
- Pass an existing UUID to append packets to that capture.

Examples:

```
# Ingest a file (new capture, UUID printed on completion)
caphouse --dsn="clickhouse://user:pass@localhost:9000/default" --file capture.pcap --sensor test

# Ingest a file into an existing capture
caphouse --dsn="clickhouse://user:pass@localhost:9000/default" --file extra.pcap --sensor test --capture <uuid>

# Export a capture
caphouse -w --dsn="clickhouse://user:pass@localhost:9000/default" --capture <uuid> --file out.pcap
```

Using tcpdump (pipe stdin):

```
tcpdump -i en0 -w - | caphouse --dsn="clickhouse://user:pass@localhost:9000/default" --sensor test
```

Continuous capture with bounded on-disk storage (rotation script):

```sh
#!/bin/sh
# Rotate every 100 MB, keep 10 files (~1 GB ring), ingest each on close.
DSN="clickhouse://user:pass@localhost:9000/default"
SENSOR="myhost"
DIR="/var/capture"

tcpdump -i eth0 -G 0 -C 100 -W 10 -w "$DIR/ring" &
TCPDUMP_PID=$!

inotifywait -m -e close_write --format '%w%f' "$DIR" | while read -r FILE; do
    caphouse --dsn="$DSN" --sensor="$SENSOR" --file="$FILE" && rm -f "$FILE"
done
```

Packets are ingested from each closed file before tcpdump can overwrite it.
On macOS, replace `inotifywait` with `fswatch -e Updated --event IsFile "$DIR"`.

Using tcpreplay:

```
caphouse -w --dsn="clickhouse://user:pass@localhost:9000/default" --capture <uuid> | tcpreplay --intf1=en0 -
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
- Use the `CreateBatch` abstraction in `components` from `ingest.go` (currently unused).
- Increase test coverage.
