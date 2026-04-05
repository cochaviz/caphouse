
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64          CODEC(LZ4),
  packet_id   UInt32          CODEC(Delta,   LZ4),
  ts          Int64           CODEC(Delta, LZ4),
  incl_len    UInt32          CODEC(Delta,   LZ4),
  trunc_extra UInt32          CODEC(ZSTD(9)),
  components  UInt128,
  payload     String          CODEC(ZSTD(3)),
  INDEX idx_session (session_id) TYPE set(10000) GRANULARITY 1
)
ENGINE = ReplacingMergeTree
PARTITION BY toDate(intDiv(ts, 1000000000))
ORDER BY (ts, session_id, packet_id)
