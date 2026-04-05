# Developing

To start developing with `caphouse`, you really only need two things: Go and
ClickHouse. Both are really easy to install and get started with, but we have
also included a `.devcontainer` that, as long as you have Docker installed,
sets you up with everything you need to get started quickly.

The development container stack is defined in
[`../.devcontainer/docker-compose.yml`](../.devcontainer/docker-compose.yml).
Unlike the repository-level [`../docker-compose.yml`](../docker-compose.yml),
it includes a bundled `clickhouse` service for local development. The root
compose file is closer to a production starting point: it builds `caphouse-api`
and `caphouse-ui`, but expects you to provide ClickHouse separately via
`CAPHOUSE_DSN`.

Inside the devcontainer, the `app` service already has
`CAPHOUSE_DSN=clickhouse://default:@clickhouse:9000/default` configured. A
typical workflow is:

```sh
# From the repo root, if you want to run the dev stack directly
docker compose -f .devcontainer/docker-compose.yml up --build -d
docker compose -f .devcontainer/docker-compose.yml exec app go run ./cmd/caphouse-api

# In the devcontainer app shell
go run ./cmd/caphouse-api
```

The companion `caphouse-ui` service from the same dev compose file runs Vite in
watch mode and proxies `/v1` requests to the API over the internal Docker
network.

## Creating new Components

One of the easiest ways to contribute to `caphouse` is by creating new
components. Components are packet-level layers (i.e. L4 and below) that parse
the raw bytes of a packet and extract meaningful information from them. Mostly,
they're direct mappings of `gopacket` layers, making them easy to use and
understand.

Full documentation for the component system — including a step-by-step guide for
adding a new protocol layer — is in the package godoc:
<https://pkg.go.dev/github.com/cochaviz/caphouse/components>

## Library API

Full API reference is available on pkg.go.dev:
<https://pkg.go.dev/github.com/cochaviz/caphouse>

All exported symbols carry godoc comments. Key entry points:

- **`New`** — create a `*Client` from a `Config`
- **`Client.IngestPCAPStream`** — ingest a classic PCAP or PCAPng stream
- **`Client.ExportCapture`** / **`ExportCaptureFiltered`** / **`ExportAllCapturesFiltered`** — export one or more captures as PCAP
- **`ParseQuery`** — compile a tcpdump-style filter expression
- **`Client.GenerateSQL`** / **`GenerateSQLForCaptures`** — render a filter as a ClickHouse `SELECT`

## Running Tests

The test suite is split into tiers, each with its own build tag. Test fixture
PCAPs live in `testdata/` and are stored in Git LFS — run `git lfs pull` after
cloning if they are not present.

### Unit tests

Pure in-memory tests with no external dependencies or file I/O.

```sh
go test ./...
```

### Integration tests

Use fixture files from `testdata/` with the in-memory mock client. No
ClickHouse instance is required.

```sh
go test -tags integration ./...
```

### E2E tests

Spin up a real ClickHouse container via
[testcontainers](https://testcontainers.com/). Docker must be running.

```sh
go test -tags e2e -timeout 600s ./...
```

### Throughput benchmarks

Measure ingest and export throughput against a live ClickHouse container.

```sh
# Run the Go benchmarks directly
go test -tags throughput -bench=. -benchtime=3x ./...

# Run as a regression test (fails if >5% slower than the baseline in main)
go test -tags "throughput regression" -v -timeout 600s ./...
```

After a `throughput,regression` run, `benchmark_results/throughput_baseline.json`
is updated in the working tree. Commit it alongside your changes to record the
new expected performance.

### Compression tests

Measure ClickHouse storage efficiency and parse ratios for each PCAP in
`testdata/`. Results are written to `benchmark_results/` as JSON (regression
baseline) and CSV (ratio tables).

```sh
# Run the regression test (fails if compression worsens vs baseline in main)
go test -tags "compression regression" -v -timeout 300s .
```

To run all tiers at once:

```sh
go test -tags "integration e2e" ./...
```

## Schema Migrations

`InitSchema` (called automatically on the first ingest) applies SQL migration
files embedded in the binary from `migrations/`. Applied migrations are
recorded in a `caphouse_schema_migrations` table so each file runs exactly
once. Migrations are sorted and applied in lexicographic order — prefix file
names with a timestamp (`YYYYMMDDHHMMSS`) to control ordering.

If the database version is _ahead_ of the binary's compiled-in migrations
(e.g. after a downgrade), `InitSchema` returns an error before touching any
data.

To add a migration, create a new `.sql` file in `migrations/`:

```
migrations/20260401120000_add_my_column.sql
```

The migration system is tested by `go test -tags e2e` (`TestMigrationsIdempotent`,
`TestMigrationsVersionTracking`, `TestMigrationsStaleClientError`) and by
`migrations/test_migration_compat.sh`, which builds both the pre-migration
binary and the current binary against a live ClickHouse and diffs their exports.

## Working with Compression

An important feature of `caphouse` is its ability to efficiently compress PCAPs
to provide a somewhat reasonable alternative to raw and even compressed PCAPS.
This is possible due to ClickHouse's columnar storage and compression
algorithms. When trying to improve the compression ratio of a table and its
rows, make sure to read the [ClickHouse documentation on
compression](https://clickhouse.com/docs/data-compression/compression-in-clickhouse).

In order to make investigating the compression capabilities as easy as possible,
we have included the `compression` tests which show compression ratios for each
table, comparing them with uncompressed and XZ compressed data:

```
go test -v -tags compression ./...
```

However, if you want to investigate compression ratios for a specific table or
column, you can use the following query:

```sql
SELECT
      column,
      formatReadableSize(sum(column_data_uncompressed_bytes))  AS logical,
      formatReadableSize(sum(column_data_compressed_bytes))    AS compressed,
      round(sum(column_data_uncompressed_bytes)
            / nullIf(sum(column_data_compressed_bytes), 0), 2) AS ratio,
      round(100 * sum(column_data_compressed_bytes)
            / sum(sum(column_data_compressed_bytes)) OVER (), 2) AS pct_of_table_disk
  FROM system.parts_columns
  WHERE database = '<database>'
    AND table    = '<table>'
    AND active   = 1
  GROUP BY column
  ORDER BY ratio ASC
```

Ingesting the `synflood_high.pcap`, we get the following output for the
`pcap_ethernet` table:

```
   ┌─column────────┬─logical───┬─compressed─┬──ratio─┬─pct_of_table_disk─┐
1. │ packet_id     │ 18.07 MiB │ 995.24 KiB │   18.6 │             75.58 │
2. │ eth_len       │ 2.57 KiB  │ 71.00 B    │  37.01 │              0.01 │
3. │ eth_type      │ 4.52 MiB  │ 20.84 KiB  │ 222.06 │              1.58 │
4. │ codec_version │ 4.52 MiB  │ 20.71 KiB  │  223.4 │              1.57 │
5. │ src_mac       │ 13.56 MiB │ 60.17 KiB  │ 230.68 │              4.57 │
6. │ dst_mac       │ 13.56 MiB │ 60.17 KiB  │ 230.68 │              4.57 │
7. │ capture_id    │ 36.15 MiB │ 159.60 KiB │ 231.93 │             12.12 │
   └───────────────┴───────────┴────────────┴────────┴───────────────────┘
```
