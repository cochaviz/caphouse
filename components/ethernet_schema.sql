
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  packet_id  UInt32 CODEC(Delta, LZ4),

  codec_version UInt16,
  layer_index   UInt16 CODEC(Delta, LZ4),

  src  FixedString(6),
  dst  FixedString(6),
  type UInt16,
  len  UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, packet_id)
