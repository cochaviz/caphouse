
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id    UInt64 CODEC(LZ4),
  packet_id     UInt32 CODEC(Delta, LZ4),
  codec_version UInt16,
  layer_index   UInt16 CODEC(Delta, LZ4),

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
  options_raw  String CODEC(ZSTD(3)),
  INDEX idx_dst (dst) TYPE bloom_filter GRANULARITY 4,
  INDEX idx_proto (protocol) TYPE set(256) GRANULARITY 4
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, packet_id)
