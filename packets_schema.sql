
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id  UUID,
  packet_id   UInt64          CODEC(Delta,   LZ4),
  ts          UInt64          CODEC(ZSTD(9)),
  incl_len    UInt32          CODEC(Delta,   LZ4),
  trunc_extra UInt32          CODEC(ZSTD(9)),
  components  UInt128,
  frame_raw   String          CODEC(ZSTD(3)),
  frame_hash  FixedString(32) CODEC(ZSTD),
  block_raw   String          CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id)
