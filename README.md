# caphouse

caphouse stores classic PCAP files in ClickHouse achieving high compression and
fast query performance.

Traditionally, PCAPs are stored on disk and compressed using a variety of
methods, such as gzip. This is difficult to query remotely; the workaround is to
download a filtered subset of the file, and open it in Wireshark or another
tool. While this works for localized queries, it can be slow and cumbersome if
the filtered subset is sufficiently large.

With `caphouse`, you can query certain PCAP data directly from ClickHouse
without needing to download a filtered subset first (although this is still
possible!). It can serve as a drop-in replacement for traditional PCAP storage:
if you require byte-level inspection of the raw frames, you can still export
them to your local host with filtering.

Read more about how it works, and get started by following the documentation:
<https://cochaviz.github.io/caphouse/>.

> This project is still in an experimental state and should be used with caution!

## Features

- **~5x compression** — columnar storage and per-field codecs compress a
  typical SYN-flood capture from 174 MB to 35 MB, approaching `xz -9` while
  keeping the data fully queryable.
- **BPF-style filtering** — filter on host, port, protocol, and time range
  using a familiar tcpdump-like syntax; results stream directly as PCAP.
- **SQL query generation** — the same filter expression can be rendered as a
  ClickHouse `SELECT` statement for direct inspection or further customisation.
- **Lossless reconstruction** — every bit of every frame is preserved; packets
  that cannot be parsed fall back to raw frame storage.
- **Byte-exact export** — classic PCAP captures can be exported bit-for-bit to
  the original file.
- **Cross-capture export** — use `--capture all` with a time-range filter to
  merge packets from every capture into a single time-sorted PCAP stream.
- **At-least-once delivery** — batch retries with exponential backoff and
  `ReplacingMergeTree`-based deduplication mean re-ingesting a file is always
  safe.
- **Continuous capture** — `caphouse-monitor` wraps tcpdump ring-buffer
  rotation with automatic ingest, keeping disk usage bounded.
- **Ingest classic PCAP and PCAPng** — both formats are accepted; PCAPng is
  converted to classic PCAP on ingest with packet data fully preserved.
- **Multi-file ingest** — pass multiple files or glob patterns as positional
  arguments to ingest them in one command (e.g. `caphouse -d "..." ring*.pcap`).

## Install

To install `caphouse`, you need Go (version 1.25 or above:
<https://go.dev/doc/install>) installed and have an active ClickHouse instance
(we recommend using the Docker image: <https://clickhouse.com/docs/install>).
Then, you run the following command:

```sh
go install github.com/cochaviz/caphouse@latest
```

You can verify the installation by running:

```sh
caphouse --version
```

## Quick example

Assuming you have a ClickHouse (native protocol, not HTTP:
<https://clickhouse.com/docs/interfaces/overview>) instance running on
`localhost:9000` with user `default`, password `default` and access to the
`default` database, you can use `caphouse` for PCAP storage as follows:

```sh
# Ingest (spits out the capture_id once finished)
# DSN has the format clickhouse://<user>:<password>@<host>:<port>/<database>
caphouse -d "clickhouse://default:default@localhost:9000/default" capture.pcap

# Ingest multiple files or a glob
caphouse -d "..." ring*.pcap

# Export
caphouse -w -d "..." -c "<capture_id>" out.pcap

# Filter and export
caphouse -w -d "..." -c "<capture_id>" -q "host 10.0.0.1 and port 443" filtered.pcap
```

More usage examples can be found in the
[documentation](https://cochaviz.com/caphouse/quickstart/).

### Filters and Querying

For querying stored captures, you can use the standalone `-q/--query` flag to
generate a SQL query and pipe it to `clickhouse-client`:

```sh
caphouse -q "host 10.0.0.1 and port 443" -c "<capture_id>" | clickhouse-client
```

Use `--capture all` with a time-range filter to query or export across every
capture at once:

```sh
# Export all captures within a time window, merged and sorted by time
caphouse -w -d "..." -c all -q "time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z" merged.pcap

# Generate SQL spanning all captures
caphouse -q "host 10.0.0.1 and time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z" -c all | clickhouse-client
```

For more details on filters and querying, see the
[documentation](https://cochaviz.com/caphouse/filters/).

### Streaming

By default, `caphouse` uses `stdin` for input and `stdout` for output, meaning
you can pipe PCAP data directly to `caphouse` with `tcpdump`:

```sh
tcpdump -i eth0 -w - | caphouse -d "..."
```

Because of `caphouse`'s retry mechanism, you can use `tcpdump`'s ring buffers
for at-least-once delivery. A companion script, `caphouse-monitor`, can be used
for this exact purpose. First, install it using the following command:

```sh
caphouse install-scripts
```

This will install `caphouse-monitor` to `$HOME/.local/bin`, allowing you to
continuously capture network traffic without losing packets if ClickHouse is
temporarily unavailable:

```sh
caphouse-monitor -i eth0 -d "..." -D captures/
```
