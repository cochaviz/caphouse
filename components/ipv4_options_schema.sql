
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id UInt64,

  codec_version UInt16,

  options_raw String CODEC(ZSTD)
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id)