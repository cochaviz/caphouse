
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id    UUID,
  packet_id     UInt64 CODEC(Delta, LZ4),
  codec_version UInt16,

  src_port    UInt16,
  dst_port    UInt16,
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
ORDER BY (capture_id, dst_port, src_port, packet_id)
