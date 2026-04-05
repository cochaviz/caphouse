
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  packet_id  UInt32 CODEC(Delta, LZ4),

  codec_version UInt16,
  layer_index   UInt16 CODEC(Delta, LZ4),

  protocol UInt8,

  src IPv6,
  dst IPv6,

  payload_len   UInt16 CODEC(Delta, LZ4),
  hop_limit     UInt8,
  flow_label    UInt32,
  traffic_class UInt8,
  INDEX idx_dst (dst) TYPE bloom_filter GRANULARITY 4,
  INDEX idx_proto (protocol) TYPE set(256) GRANULARITY 4
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, packet_id)
