
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  packet_id     UInt32 CODEC(Delta, LZ4),
  codec_version UInt16,

  src      UInt16,
  dst      UInt16,
  length   UInt16,
  checksum UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, packet_id)
