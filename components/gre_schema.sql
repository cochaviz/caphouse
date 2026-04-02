
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id    UInt64 CODEC(LZ4),
  packet_id     UInt32 CODEC(Delta, LZ4),
  codec_version UInt16,
  layer_index   UInt16 CODEC(Delta, LZ4),

  protocol UInt16,
  flags    UInt8,
  version  UInt8,
  checksum UInt16,
  key      UInt32 CODEC(LZ4),
  seq      UInt32 CODEC(Delta, LZ4)
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, packet_id)
