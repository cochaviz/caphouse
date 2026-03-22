
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id  UInt64 CODEC(DoubleDelta, LZ4),

  codec_version UInt16,

  parsed_ok UInt8,
  parse_err LowCardinality(String),

  protocol UInt8,

  src IPv4,
  dst IPv4,

  ihl          UInt8,
  tos          UInt8,
  total_len    UInt16 CODEC(Delta, LZ4),
  id           UInt16,
  flags        UInt8  CODEC(ZSTD(9)),
  frag_offset  UInt16,
  ttl          UInt8,
  hdr_checksum UInt16,
  options_raw  String CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree
ORDER BY (dst, src, capture_id, packet_id)
