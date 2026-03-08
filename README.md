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
caphouse -d "clickhouse://default:default@localhost:9000/default" -f capture.pcap

# Export
caphouse -w -d "..." -c "<capture_id>" -f out.pcap

# Filter and export
caphouse -w -d "..." -c "<capture_id>" -q "host 10.0.0.1 and port 443" -f filtered.pcap
```

More usage examples can be found in the
[documentation](https://cochaviz.com/caphouse/quickstart/).

### Filters and Querying

For querying stored captures, you can use the standalone `-q/--query` flag to
generate a SQL query and pipe it to `clickhouse-client`:

```sh
caphouse -q "host 10.0.0.1 and port 443" -c "<capture_id>" | clickhouse-client
```

For more details on filters and querying, see the
[documentation](https://cochaviz.com/caphouse/filters/).

### Streaming

By default, `caphouse` uses `stdin` for input and `stdout` for output, meaning
you can pipe PCAP data directly to `caphouse` with `tcpdump`:

```sh
tcpdump -i eth0 -w - | caphouse -d "..." -f - 
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
