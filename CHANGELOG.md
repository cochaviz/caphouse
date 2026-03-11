# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### New Features

- **PCAPng ingest support** — PCAPng files are accepted as input and converted
  to classic PCAP on ingest. All non-packet blocks (metadata, interface
  descriptions, etc.) are discarded. No byte-exact round-trip is guaranteed for
  PCAPng sources; the exported result is always a valid classic PCAP stream.
- **`IngestPCAPStream` promoted to library API** — previously an internal CLI
  helper, it is now a public method on `*Client`. It transparently handles both
  classic PCAP and PCAPng input and is the single entry point for stream-based
  ingest.

### Changes

- `captures_schema.sql`: `created_at` precision raised from `DateTime64(3)` to
  `DateTime64(9)` (nanosecond); `time_res` column changed from
  `Enum8('us' = 1)` to `LowCardinality(String)` to accommodate `"ns"` captures.
- `CreatedAt` on a capture is now derived from the first packet's timestamp
  rather than the wall-clock time at ingest start.
- A `Warn`-level log is emitted when exporting a capture whose original PCAP
  global header was not preserved (i.e. any pcapng-sourced capture), indicating
  that the exported header is synthetic.

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
