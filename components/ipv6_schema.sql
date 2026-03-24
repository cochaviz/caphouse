
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  ts          Int64  CODEC(Delta, LZ4),
  packet_id  UInt32 CODEC(Delta, LZ4),

  codec_version UInt16,

  parsed_ok UInt8,
  parse_err LowCardinality(String),

  protocol UInt8,

  src IPv6,
  dst IPv6,

  payload_len   UInt16 CODEC(Delta, LZ4),
  hop_limit     UInt8,
  flow_label    UInt32,
  traffic_class UInt8
)
ENGINE = ReplacingMergeTree
ORDER BY (ts, session_id, packet_id)
