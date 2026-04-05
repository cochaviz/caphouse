
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id    UInt64 CODEC(LZ4),
  packet_id     UInt32 CODEC(Delta, LZ4),
  codec_version UInt16,
  layer_index   UInt16 CODEC(Delta, LZ4),

  type      UInt8,
  code      UInt8,
  checksum  UInt16,
  INDEX idx_type (type) TYPE set(256) GRANULARITY 4
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, packet_id)
