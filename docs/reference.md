# All Flags

| Flag | Short | Env var | Default | Description |
|------|-------|---------|---------|-------------|
| `--dsn` | `-d` | `CAPHOUSE_DSN` | — | ClickHouse DSN, e.g. `clickhouse://user:pass@host:9000/db`. Required. |
| `--sensor` | | — | hostname | Sensor name attached to the capture. Falls back to the system hostname in read mode. |
| `--capture` | `-c` | — | new | Capture UUID. In read mode: existing capture to append to, or `new` to create one. In write/query mode: capture UUID, or `all` to operate across every stored capture (requires a `time` filter in `-q`). |
| `--read` | `-r` | — | — | Ingest mode (default; flag may be omitted). Input files are passed as positional arguments; omit for stdin. |
| `--write` | `-w` | — | — | Export mode — write a PCAP. Output file is the first positional argument; omit for stdout. |
| `--query` | `-q` | — | — | Filter expression. Without `--write`: prints SQL. With `--write`: exports matching packets as PCAP. |
| `--components` | `-C` | — | — | Comma-separated protocol tables to LEFT JOIN in SQL output (e.g. `ipv4,tcp`). Requires `-q` without `-w`. |
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

## caphouse-monitor flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | — | Network interface to capture on. Required. |
| `-d` | `$CAPHOUSE_DSN` | ClickHouse DSN. |
| `-s` | — | Sensor name. Required. |
| `-t` | `60` | tcpdump rotation interval in seconds. |
| `-D` | `/var/capture` | Directory for temporary capture files. |
