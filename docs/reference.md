# All Flags

| Flag | Short | Env var | Default | Description |
|------|-------|---------|---------|-------------|
| `--dsn` | `-d` | `CAPHOUSE_DSN` | — | ClickHouse DSN, e.g. `clickhouse://user:pass@host:9000/db`. Required. |
| `--sensor` | | — | hostname | Sensor name attached to the capture. Falls back to the system hostname in read mode. |
| `--capture` | `-c` | — | new | Capture UUID. In read mode: existing capture to append to, or `new` to create one. In write/query mode: capture UUID, or `all` to operate across every stored capture (requires `--from` and `--to`). |
| `--from` | | — | — | Start of time window for `--capture all` (RFC 3339, e.g. `2024-01-01T00:00:00Z`). Required with `--capture all`. |
| `--to` | | — | — | End of time window for `--capture all` (RFC 3339). Required with `--capture all`. |
| `--read` | `-r` | — | — | Ingest mode (default; flag may be omitted). Input files are passed as positional arguments; omit for stdin. |
| `--write` | `-w` | — | — | Export mode — write a PCAP. Output file is the first positional argument; omit for stdout. |
| `--filter` | `-f` | — | — | ClickHouse WHERE clause filter (e.g. `ipv4.dst = '1.1.1.1' AND tcp.dst = 443`). Without `--write`: prints equivalent SQL. With `--write`: exports matching packets as PCAP. |
| `--components` | `-C` | — | — | Comma-separated protocol tables to LEFT JOIN in SQL output (e.g. `ipv4,tcp`). Requires `-f` without `-w`. |
| `--no-streams` | | — | false | Disable TCP stream tracking and L7 protocol detection during ingest. Speeds up ingest when stream reassembly is not needed. |
| `--max-storage` | | `CAPHOUSE_MAX_STORAGE` | disabled | Maximum compressed size for caphouse-managed ClickHouse tables after ingest. Accepts plain bytes or human-readable sizes such as `100GiB`, `500MB`, `800Gib`, or `1TiB`. Use `B` for bytes and `b` for bits. When exceeded, whole oldest captures are pruned. |
| `--batch-size` | | — | 1000 | Packets per ClickHouse batch insert. |
| `--flush-interval` | | — | 1s | Maximum time between batch flushes. |
| `--silent` | `-s` | — | false | Suppress warnings and progress output. |
| `--debug` | | — | false | Enable verbose ClickHouse driver logging to stderr. |
| `--version` | `-v` | — | — | Print version and exit. |

Input files (read mode) and the output file (write mode) are positional
arguments, not flags. Multiple files and glob patterns are accepted in read
mode:

```sh
# Ingest three files
caphouse -d "..." a.pcap b.pcap c.pcap

# Ingest a glob
caphouse -d "..." ring*.pcap

# Export to a file
caphouse -w -d "..." -c <uuid> out.pcap
```

## caphouse-api flags

`caphouse-api` runs an HTTP REST API server for querying and exporting
captures stored in ClickHouse. OpenAPI documentation is served at `/docs`
and the raw schema at `/openapi.json`.

| Flag | Short | Env var | Default | Description |
|------|-------|---------|---------|-------------|
| `--dsn` | `-d` | `CAPHOUSE_DSN` | — | ClickHouse DSN. Required. |
| `--addr` | `-a` | — | `:8080` | TCP address to listen on. |
| `--geoip-source` | | `CAPHOUSE_GEOIP_SOURCE` | — | URL of a DB-IP city IPv4 CSV for GeoIP enrichment. |
| `--geoip-source-v6` | | `CAPHOUSE_GEOIP_SOURCE_V6` | — | URL of a DB-IP city IPv6 CSV. |
| `--asn-source` | | `CAPHOUSE_ASN_SOURCE` | — | URL of a DB-IP ASN IPv4 CSV. |
| `--asn-source-v6` | | `CAPHOUSE_ASN_SOURCE_V6` | — | URL of a DB-IP ASN IPv6 CSV. |
| `--anthropic-key` | | `ANTHROPIC_API_KEY` | — | Anthropic API key for AI-assisted SQL generation. |
| `--debug` | | — | false | Enable verbose ClickHouse driver logging to stderr. |

## caphouse-sanitize flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--seed` | | random | Hex-encoded 32-byte HMAC seed (64 hex chars). A random seed is generated when omitted and printed to stderr. |
| `--in` | `-i` | stdin | Input PCAP file or folder. When a folder is given, all `*.pcap` files inside are processed. |
| `--out` | `-o` | stdout | Output PCAP file or folder. Must be a folder when `--in` is a folder, and must differ from `--in`. |

Only public IPv4 and IPv6 addresses are pseudonymized. Private (RFC 1918 /
RFC 4193), loopback, link-local, multicast, and unspecified addresses are
passed through unchanged. Unicast MAC addresses are replaced with
locally-administered addresses (`02:xx:xx:xx:xx:xx`); broadcast and multicast
MACs are unchanged.

IPv4 header checksums and TCP/UDP checksums are recomputed after rewriting so
the output is a valid PCAP that can be ingested, replayed, or inspected
normally.

## caphouse-monitor flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | — | Network interface to capture on. Required. |
| `-d` | `$CAPHOUSE_DSN` | ClickHouse DSN. |
| `-s` | — | Sensor name. Required. |
| `-t` | `60` | tcpdump rotation interval in seconds. |
| `-D` | `/var/capture` | Directory for temporary capture files. |
