
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id  UInt64 CODEC(DoubleDelta, LZ4),

  codec_version UInt16,

  src  FixedString(6),
  dst  FixedString(6),
  type UInt16,
  len  UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (dst, src, capture_id, packet_id)
