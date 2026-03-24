
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64          CODEC(LZ4),
  packet_id   UInt32          CODEC(Delta,   LZ4),
  ts          Int64  CODEC(Delta, LZ4),
  incl_len    UInt32          CODEC(Delta,   LZ4),
  trunc_extra UInt32          CODEC(ZSTD(9)),
  components  UInt128,
  frame_raw   String          CODEC(ZSTD(3)),
  frame_hash  FixedString(32) CODEC(ZSTD)
)
ENGINE = ReplacingMergeTree
ORDER BY (ts, session_id, packet_id)
