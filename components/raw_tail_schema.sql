
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id UInt64,

  tail_offset UInt16,
  bytes String CODEC(ZSTD)
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id)