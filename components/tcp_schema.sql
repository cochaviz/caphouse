
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  ts          Int64  CODEC(Delta, LZ4),
  packet_id     UInt32 CODEC(Delta, LZ4),
  codec_version UInt16,

  src         UInt16,
  dst         UInt16,
  seq         UInt32 CODEC(Delta, LZ4),
  ack         UInt32 CODEC(Delta, LZ4),
  data_offset UInt8,
  flags       UInt16,
  window      UInt16,
  checksum    UInt16,
  urgent      UInt16,
  options_raw String CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree
ORDER BY (ts, session_id, packet_id)
