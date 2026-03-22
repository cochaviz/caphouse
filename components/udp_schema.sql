
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id    UUID,
  packet_id     UInt64 CODEC(Delta, LZ4),
  codec_version UInt16,

  src      UInt16,
  dst      UInt16,
  length   UInt16,
  checksum UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, dst, src, packet_id)
