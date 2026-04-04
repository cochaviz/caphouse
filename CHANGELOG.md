# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### New Features

- **Storage cap retention (`--max-storage`)** — optionally bound
  caphouse-managed ClickHouse storage to a target size. After each successful
  ingest, caphouse measures compressed bytes across its own `pcap_*` and
  `stream_*` tables and prunes whole oldest captures until usage drops under
  the configured cap, keeping the newest just-ingested capture.

### Fixes

- **`--max-storage` size parsing** — distinguish `B` (bytes) from `b`
  (bits), so values like `500MB` and `500Mb` no longer resolve to the same
  threshold.
- **DNS byte-exact export** — preserve the DNS `Z` header bits during ingest
  and reconstruction so captures with non-zero reserved/AD/CD-style DNS flags
  round-trip byte-for-byte.

## [v0.3.1] - 2026-03-18

### New Features

- **`caphouse-watch-dir` script** — watches a directory for PCAP files
  (`*.pcap`, `*.pcapng`), ingests each into ClickHouse when the writing
  process closes the file, and removes it from disk on success. Useful as a
  drop folder: any tool that writes PCAPs into the directory will have them
  automatically drained and stored. Uses `inotifywait` on Linux and
  polling + `lsof` on macOS. Installed alongside `caphouse-monitor` via
  `caphouse install-scripts`.

## [v0.3.0] - 2026-03-11

### New Features

- **PCAPng ingest support** — PCAPng files are accepted as input and converted
  to classic PCAP on ingest. All non-packet blocks (metadata, interface
  descriptions, etc.) are discarded. No byte-exact round-trip is guaranteed for
  PCAPng sources; the exported result is always a valid classic PCAP stream.
- **Multi-file ingest** — input files are now positional arguments; multiple
  files and glob patterns are accepted in a single invocation (e.g.
  `caphouse -d "..." ring*.pcap`). The `--file` / `-f` flag has been removed.
- **Cross-capture export (`--capture all`)** — pass `-c all` with a mandatory
  `time <from> to <to>` filter to merge packets from every stored capture into
  a single time-sorted PCAP stream. Ties are broken by capture start time, then
  capture ID. A warning is emitted when captures have mixed link types.
- **L7 protocol parsing** — DNS, NTP, and HTTP are parsed and stored per packet;
  TCP stream reassembly enables HTTP reconstruction across multiple packets.
- **`--no-streams` flag** — disables TCP stream tracking and L7 protocol
  detection during ingest. Useful for high-throughput scenarios where stream
  reassembly is not required.
- **Documentation site** — full MkDocs-based documentation published at
  <https://cochaviz.github.io/caphouse/>, covering quickstart, filter syntax,
  storage internals, and a complete flag reference.

### Library API

- **`IngestPCAPStream`** promoted to public API — previously an internal CLI
  helper, it is now a public method on `*Client`. Transparently handles both
  classic PCAP and PCAPng input and is the single entry point for stream-based
  ingest.
- **`ExportAllCapturesFiltered`** — new `*Client` method for cross-capture
  filtered export; returns an `io.ReadCloser` and total packet count. Requires
  a query containing a `time` primitive.
- **`GenerateSQLForCaptures`** — like `GenerateSQL` but accepts `[]uuid.UUID`;
  pass `nil` to generate SQL spanning all captures without an explicit capture
  filter.

### Changes

- `-c all` is valid in write (`-w`) and query (`-q`) modes; forbidden in read
  (`-r`) mode.
- SQL subqueries for cross-capture queries omit the `capture_id IN (...)` clause
  entirely when operating over all captures, avoiding a pre-fetch round-trip.
- `timeNode` subqueries add a `PREWHERE` clause on the captures join for
  ClickHouse granule-level pruning, improving time-range query performance.
- `captures_schema.sql`: `created_at` precision raised from `DateTime64(3)` to
  `DateTime64(9)` (nanosecond); `time_res` column changed from
  `Enum8('us' = 1)` to `LowCardinality(String)` to accommodate `"ns"` captures.
- `CreatedAt` on a capture is now derived from the first packet's timestamp
  rather than the wall-clock time at ingest start.
- A `Warn`-level log is emitted when exporting a capture whose original PCAP
  global header was not preserved (i.e. any pcapng-sourced capture), indicating
  that the exported header is synthetic.
- Component interface simplified; `RawTailComponent` removed.

### Testing

- Test suite reorganised into three explicit tiers:
  - **Unit** (`*_test.go`, no build tag) — pure in-memory, no files, no external dependencies.
  - **Integration** (`*_integration_test.go`, `//go:build integration`) — uses `testdata/` fixtures with the mock client; no container required.
  - **E2E** (`*_e2e_test.go`, `//go:build e2e`) — requires a running ClickHouse container via testcontainers.

## [v0.2.0] - 2026-03-07

### New Features

- **Query filtering (`-q` / `--query`)** — filter captured data using a simple DSL similar to BPF (e.g. `host 1.1.1.1 and port 53 and time <begin> to <end>`) when retrieving with `-w`
- **Standalone `-q` usage** — running `caphouse -q <query> --capture` prints the SQL query to stdout, enabling direct piping to `clickhouse-client` for inspection
- Scripts now bundled in the binary; `go install` works directly (Makefile no longer required for installation)
- ClickHouse client added to devcontainer
- Banner added to the manual

### Compression Improvements

- Significant compression improvements across Ethernet, IPv4/6, and `pcap_packets` tables

### Documentation

- README and manual updated to reflect all new features and CLI changes

## [v0.1.1] - 2026-03-04

### New Features

- **TCP/UDP (L4) support** — packet capture now parses and stores TCP and UDP protocol layers in dedicated tables
- **`--version` flag** — report the installed version
- Simplified CLI interface
- Devcontainer configuration added; user installs now go to `/home/vscode/.local/bin`

### Testing

- Test data moved to an external location and downloaded on demand
- Integration tests also download PCAPs automatically
- Compression tests now export results in CSV
- Integration test timeout increased from 5 to 7 minutes to reduce flakiness
- Fixed tests failing due to hardcoded test file names

### Performance

- Reduced query size by bundling successive packet IDs
- Slight improvements to compression

## [v0.1.0] - 2026-03-02

- Initial release
