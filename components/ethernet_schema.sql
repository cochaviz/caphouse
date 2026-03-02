
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id UInt64,

  codec_version UInt16,

  src_mac String CODEC(ZSTD),
  dst_mac String CODEC(ZSTD),
  eth_type UInt16,
  eth_len UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id)