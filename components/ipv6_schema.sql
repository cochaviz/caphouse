
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id  UInt64 CODEC(DoubleDelta, LZ4),

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
ORDER BY (dst, src, capture_id, packet_id)
