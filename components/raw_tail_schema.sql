
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id  UUID,
  packet_id   UInt64 CODEC(Delta, LZ4),
  tail_offset UInt16 CODEC(Delta, LZ4),
  bytes       String CODEC(ZSTD)
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id)
