
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  ts          Int64  CODEC(Delta, LZ4),
  packet_id  UInt32 CODEC(Delta, LZ4),

  codec_version UInt16,

  ext_index UInt16,
  ext_type  UInt16,
  ext_raw   String CODEC(ZSTD)
)
ENGINE = ReplacingMergeTree
ORDER BY (ts, session_id, packet_id, ext_index)
