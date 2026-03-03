
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id  UInt64 CODEC(Delta, LZ4),

  codec_version UInt16,

  l2_len     UInt16,
  l2_hdr_raw String CODEC(ZSTD)
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id)
