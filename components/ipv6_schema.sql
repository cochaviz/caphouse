
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id  UInt64 CODEC(DoubleDelta, LZ4),

  codec_version UInt16,

  parsed_ok UInt8,
  parse_err LowCardinality(String),

  protocol UInt8,

  src_ip_v6 IPv6,
  dst_ip_v6 IPv6,

  ipv6_payload_len   UInt16 CODEC(Delta, LZ4),
  ipv6_hop_limit     UInt8,
  ipv6_flow_label    UInt32,
  ipv6_traffic_class UInt8
)
ENGINE = ReplacingMergeTree
ORDER BY (dst_ip_v6, src_ip_v6, capture_id, packet_id)
