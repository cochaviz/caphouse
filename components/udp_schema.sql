
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  packet_id     UInt32 CODEC(Delta, LZ4),
  codec_version UInt16,
  layer_index   UInt16 CODEC(Delta, LZ4),

  src      UInt16,
  dst      UInt16,
  length   UInt16,
  checksum UInt16,
  INDEX idx_dst (dst) TYPE bloom_filter GRANULARITY 4
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, packet_id)
