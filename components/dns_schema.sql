
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  ts          Int64  CODEC(Delta, LZ4),
  packet_id       UInt32 CODEC(Delta, LZ4),
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

  answers_name   Array(String) CODEC(ZSTD(3)),
  answers_type   Array(UInt16),
  answers_class  Array(UInt16),
  answers_ttl    Array(UInt32),
  answers_rdata  Array(String) CODEC(ZSTD(3)),
  answers_ip     Array(String) CODEC(ZSTD(3)),

  authority_name   Array(String) CODEC(ZSTD(3)),
  authority_type   Array(UInt16),
  authority_class  Array(UInt16),
  authority_ttl    Array(UInt32),
  authority_rdata  Array(String) CODEC(ZSTD(3)),

  additional_name   Array(String) CODEC(ZSTD(3)),
  additional_type   Array(UInt16),
  additional_class  Array(UInt16),
  additional_ttl    Array(UInt32),
  additional_rdata  Array(String) CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree
ORDER BY (ts, session_id, packet_id)
