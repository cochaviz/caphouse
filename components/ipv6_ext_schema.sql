
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id  UInt64 CODEC(Delta, LZ4),

  codec_version UInt16,

  ext_index UInt16,
  ext_type  UInt16,
  ext_raw   String CODEC(ZSTD)
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id, ext_index)
