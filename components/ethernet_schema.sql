
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id  UInt64 CODEC(DoubleDelta, LZ4),

  codec_version UInt16,

  src_mac  FixedString(6),
  dst_mac  FixedString(6),
  eth_type UInt16,
  eth_len  UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (dst_mac, src_mac, capture_id, packet_id)
