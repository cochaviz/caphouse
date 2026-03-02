
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id UInt64,
  ts DateTime64(9),

  codec_version UInt16,

  parsed_ok UInt8,
  parse_err LowCardinality(String),

  protocol UInt8,

  src_ip_v4 IPv4,
  dst_ip_v4 IPv4,

  ipv4_ihl UInt8,
  ipv4_tos UInt8,
  ipv4_total_len UInt16,
  ipv4_id UInt16,
  ipv4_flags UInt8,
  ipv4_frag_offset UInt16,
  ipv4_ttl UInt8,
  ipv4_hdr_checksum UInt16
)
ENGINE = ReplacingMergeTree
PARTITION BY toDate(ts)
ORDER BY (toDate(ts), protocol, dst_ip_v4, capture_id, packet_id)