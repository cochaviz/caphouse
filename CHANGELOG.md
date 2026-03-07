# Changelog

All notable changes to this project will be documented in this file.

## [v0.2.0] - 2026-03-07

### New Features

- **Query filtering (`-q` / `--query`)** — filter captured data using a simple DSL similar to BPF (e.g. `host 1.1.1.1 and port 53 and time <begin> to <end>`) when retrieving with `-w`
- **Standalone `-q` usage** — running `caphouse -q <query> --capture` prints the SQL query to stdout, enabling direct piping to `clickhouse-client` for inspection
- Scripts now bundled in the binary; `go install` works directly (Makefile no longer required for installation)

### Compression Improvements

- Significant compression improvements across Ethernet, IPv4/6, and `pcap_packets` tables

### Documentation

- README and manual updated to reflect all new features and CLI changes

## [v0.1.1] - 2026-03-04

### New Features

- **TCP/UDP (L4) support** — packet capture now parses and stores TCP and UDP protocol layers in dedicated tables
- **`--version` flag** — report the installed version
- Simplified CLI interface
- Banner added to the manual
- Devcontainer configuration added, including ClickHouse client
- User installs now go to `/home/vscode/.local/bin`

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
