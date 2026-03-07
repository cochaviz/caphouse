# Quickstart

## 1. Ingest a PCAP

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

## 2. Export a PCAP

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

## 3. Query packets directly with SQL

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
