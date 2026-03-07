
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id      UUID,
  packet_id       UInt64 CODEC(Delta, LZ4),
  codec_version   UInt16,

  transaction_id  UInt16,
  qr              UInt8,
  opcode          UInt8 CODEC(ZSTD(9)),
  rcode           UInt8,
  flags           UInt8,
  an_count        UInt16,
  ns_count        UInt16,
  ar_count        UInt16,

  questions_name  Array(String) CODEC(ZSTD(3)),
  questions_type  Array(UInt16),
  questions_class Array(UInt16),

  dns_raw         String CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id)
