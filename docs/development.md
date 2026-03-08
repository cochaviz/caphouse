# Developing

To start developing with `caphouse`, you really only need two things: Go and
ClickHouse. Both are really easy to install and get started with, but we have
also included a `.devcontainer` that, as long as you have Docker installed,
sets you up with everything you need to get started quickly.

## Creating new Components

One of the easiest ways to contribute to `caphouse` is by creating new
components. Components are packet-level layers (i.e. L4 and below) that parse
the raw bytes of a packet and extract meaningful information from them. Mostly,
they're direct mappings of `gopacket` layers, making them easy to use and
understand.

todo...

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
