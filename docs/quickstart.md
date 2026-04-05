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

# Export only matching packets
caphouse -w -d "..." -c <uuid> -f "ipv4.addr = '10.0.0.1' AND tcp.dst = 443" filtered.pcap

# Pipe filtered packets into tcpdump for live inspection
caphouse -w -d "..." -c <uuid> -f "ipv4.src = '10.0.0.1'" | tcpdump -r -
```

See [Filter Syntax](filters.md) for the full filter reference.

## 3. Export across all captures

Use `--capture all` (or `-c all`) together with mandatory `--from` and `--to`
bounds to merge packets from every stored capture into a single time-sorted PCAP.

```sh
# Merge all captures from a one-hour window into a single file
caphouse -w -d "..." -c all \
  --from 2024-01-01T00:00:00Z --to 2024-01-01T01:00:00Z merged.pcap

# Same, with an additional filter
caphouse -w -d "..." -c all \
  --from 2024-01-01T00:00:00Z --to 2024-01-01T01:00:00Z \
  -f "tcp.dst = 443" | tcpdump -r -
```

A warning is printed when the merged output contains captures with different
link types, as the resulting PCAP will use the link type of the first capture.

## 4. Query packets directly with SQL

`-f` without `-w` prints the equivalent ClickHouse `SELECT` statement with all
parameters inlined — ready to pipe into `clickhouse-client` or tweak by hand.
No packets are read or exported; the output is pure SQL.

```sh
# Print the SQL for a filter
caphouse -d "..." -c <uuid> -f "ipv4.addr = '10.0.0.1'"

# Run it directly
caphouse -d "..." -c <uuid> -f "ipv4.addr = '10.0.0.1'" | clickhouse-client --multiquery

# Add protocol columns with --components / -C
caphouse -d "..." -c <uuid> -f "tcp.dst = 443" -C ipv4,tcp \
  | clickhouse-client --multiquery

# Export as CSV
caphouse -d "..." -c <uuid> -f "tcp.dst = 443" -C ipv4,tcp \
  | clickhouse-client --multiquery --format CSVWithNames > packets.csv

# Export as JSON
caphouse -d "..." -c <uuid> -f "tcp.dst = 443" -C ipv4,tcp \
  | clickhouse-client --multiquery --format JSONEachRow > packets.jsonl

# Save, edit, then run
caphouse -d "..." -c <uuid> -f "ipv4.addr = '10.0.0.1'" > query.sql
$EDITOR query.sql
clickhouse-client --multiquery < query.sql

# Query across all captures (requires --from and --to)
caphouse -d "..." -c all \
  --from 2024-01-01T00:00:00Z --to 2024-01-01T01:00:00Z \
  -f "ipv4.addr = '10.0.0.1'" | clickhouse-client --multiquery
```

## 5. Sanitize a PCAP

`caphouse-sanitize` replaces every public IP and MAC address with a
deterministic pseudonym so captures can be shared without exposing real
addresses. Private, loopback, link-local, and multicast addresses are left
unchanged, preserving internal network topology.

```sh
# Anonymize a single file; seed is random and printed to stderr
caphouse-sanitize -i capture.pcap -o sanitized.pcap

# Reproducible mapping — use the same seed to get the same pseudonyms
caphouse-sanitize --seed <64-hex-chars> -i capture.pcap -o sanitized.pcap

# Anonymize all *.pcap files in a folder (filenames preserved)
caphouse-sanitize -i captures/ -o sanitized/

# Stream from stdin to stdout
tcpdump -i eth0 -w - | caphouse-sanitize > sanitized.pcap
```

The seed is a 32-byte value encoded as 64 hex characters. When omitted a
random seed is generated and printed to stderr — keep it if you need to
reproduce the mapping later.

## 6. Explore captures in the browser with caphouse-ui

For a hosted workflow, run `caphouse-api` against the same ClickHouse database
and place `caphouse-ui` in front of it. The UI expects the API on the same
origin under `/v1`, with `/docs` and `/openapi.json` exposed as well.

The quickest way to try this repository is the devcontainer stack in
[`../.devcontainer/docker-compose.yml`](../.devcontainer/docker-compose.yml).
Unlike the production compose file, it includes a `clickhouse` service for you.
Run it like this:

```sh
docker compose -f .devcontainer/docker-compose.yml up --build -d
docker compose -f .devcontainer/docker-compose.yml exec app go run ./cmd/caphouse-api
```

Or open the repo in the devcontainer and start the API from the `app`
container:

```sh
go run ./cmd/caphouse-api
```

The UI service from the same compose file already runs in development mode and
proxies to the API over the Docker network. If you run that compose file
directly, the UI is exposed on `http://localhost:8088`.

The browser UI is best for:

- Searching packets with the same filter syntax used by `caphouse -f`
- Zooming and breaking down packet timelines in the histogram
- Inspecting packet layers, hex dumps, and GeoIP-enriched addresses
- Reviewing stream/session summaries for HTTP, TLS, and SSH traffic
- Building and running SQL from the Query page, with optional AI-assisted SQL
  generation when `ANTHROPIC_API_KEY` is configured on `caphouse-api`

The repository contains both pieces:

- `cmd/caphouse-api/` for the HTTP API server
- `caphouse-ui/` for the React frontend

For production, use [`../Dockerfile`](../Dockerfile) for the API and
[`../caphouse-ui/Dockerfile`](../caphouse-ui/Dockerfile) for the UI. The
repository-level [`../docker-compose.yml`](../docker-compose.yml) builds those
two services, but it does **not** include ClickHouse; set `CAPHOUSE_DSN` to an
external ClickHouse instance and add your own port/reverse-proxy configuration.

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
