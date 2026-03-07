# All Flags

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

## caphouse-monitor flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | — | Network interface to capture on. Required. |
| `-d` | `$CAPHOUSE_DSN` | ClickHouse DSN. |
| `-s` | — | Sensor name. Required. |
| `-t` | `60` | tcpdump rotation interval in seconds. |
| `-D` | `/var/capture` | Directory for temporary capture files. |
