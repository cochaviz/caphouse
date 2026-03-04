
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id    UUID,
  packet_id     UInt64 CODEC(Delta, LZ4),
  codec_version UInt16,

  src_port  UInt16,
  dst_port  UInt16,
  length    UInt16,
  checksum  UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, dst_port, src_port, packet_id)
