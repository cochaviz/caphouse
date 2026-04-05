
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id      UInt64,
  stream_id       UUID,
  l7_proto        LowCardinality(String),
  proto           UInt8,
  src_ip          IPv6,
  dst_ip          IPv6,
  src_port        UInt16,
  dst_port        UInt16,
  is_complete     Bool,
  first_packet_id UInt32,
  last_packet_id  UInt32,
  packet_count    UInt64,
  byte_count      UInt64,
  INDEX idx_l7_proto (l7_proto) TYPE bloom_filter GRANULARITY 4,
  INDEX idx_dst_port (dst_port) TYPE set(512) GRANULARITY 4
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, stream_id)
