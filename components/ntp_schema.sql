
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  packet_id        UInt32 CODEC(Delta, LZ4),
  codec_version    UInt16,
  layer_index      UInt16 CODEC(Delta, LZ4),

  leap_indicator   UInt8,
  version          UInt8,
  mode             UInt8,
  stratum          UInt8,
  poll             Int8,
  precision        Int8,
  root_delay       UInt32,
  root_dispersion  UInt32,
  reference_id     UInt32,

  reference_ts     UInt64,
  origin_ts        UInt64,
  receive_ts       UInt64,
  transmit_ts      UInt64,

  ntp_raw          String CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, packet_id)
