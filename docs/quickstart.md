# Quickstart

## 1. Ingest a PCAP

```sh
# From a file — prints the capture UUID on completion
caphouse -d "clickhouse://user:pass@localhost:9000/default" \
         --sensor myhost capture.pcap

# From tcpdump over a pipe
tcpdump -i eth0 -w - | caphouse -d "..."

# Ingest multiple files or a glob in one command
caphouse -d "..." --sensor myhost ring*.pcap

# Keep caphouse-managed ClickHouse storage under 100 GiB
caphouse -d "..." --sensor myhost --max-storage 100GiB capture.pcap

# Append to an existing capture
caphouse -d "..." more.pcap -c <uuid>

# Disable L7 protocol detection (faster ingest, no stream tracking)
caphouse -d "..." --no-streams capture.pcap
```

The schema is created automatically on the first ingest.

When `--max-storage` is set, caphouse measures compressed bytes across its own
`pcap_*` and `stream_*` tables after each successful ingest and prunes whole
oldest captures until usage drops under the configured cap or only the newest
just-ingested capture remains.

PCAPng files (`.pcapng`) are also accepted. They are converted to classic PCAP
on ingest — non-packet blocks are discarded and the exported result is always a
valid classic PCAP stream. No byte-exact round-trip is guaranteed for PCAPng
sources.

## 2. Export a PCAP

```sh
# Export an entire capture to a file
caphouse -w -d "..." -c <uuid> out.pcap

# Stream into tcpreplay
caphouse -w -d "..." -c <uuid> | tcpreplay --intf1=eth0 -

# Export only matching packets (tcpdump-style filter)
caphouse -w -d "..." -c <uuid> -q "host 10.0.0.1 and port 443" filtered.pcap

# Pipe filtered packets into tcpdump for live inspection
caphouse -w -d "..." -c <uuid> -q "src host 10.0.0.1" | tcpdump -r -
```

## 3. Export across all captures

Use `--capture all` (or `-c all`) together with a mandatory time-range filter
to merge packets from every stored capture into a single time-sorted PCAP.

```sh
# Merge all captures from a one-hour window into a single file
caphouse -w -d "..." -c all \
  -q "time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z" merged.pcap

# Same, but piped into tcpdump for quick inspection
caphouse -w -d "..." -c all \
  -q "time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z and port 443" \
  | tcpdump -r -
```

A warning is printed when the merged output contains captures with different
link types, as the resulting PCAP will use the link type of the first capture.

## 4. Query packets directly with SQL

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

# Save, edit, then run
caphouse -d "..." -c <uuid> -q "host 10.0.0.1" > query.sql
$EDITOR query.sql
clickhouse-client --multiquery < query.sql

# Query across all captures (requires a time filter)
caphouse -d "..." -c all -q "host 10.0.0.1 and time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z" \
  | clickhouse-client --multiquery
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
The DSN can also be provided via `CAPHOUSE_DSN`.

Files are only removed after a successful ingest. If ClickHouse is temporarily
unavailable, caphouse retries with exponential backoff and jitter; if it
ultimately fails the file is left on disk for the next rotation cycle.
