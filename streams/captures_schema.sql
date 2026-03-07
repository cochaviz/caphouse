
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id      UUID,
  stream_id       UUID,
  l7_proto        LowCardinality(String),
  proto           UInt8,
  src_ip          IPv6,
  dst_ip          IPv6,
  src_port        UInt16,
  dst_port        UInt16,
  is_complete     Bool,
  first_packet_id UInt64,
  last_packet_id  UInt64,
  packet_count    UInt64,
  byte_count      UInt64
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, stream_id)
