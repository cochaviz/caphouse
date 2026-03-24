
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  ts          Int64  CODEC(Delta, LZ4),
  packet_id     UInt32 CODEC(Delta, LZ4),
  codec_version UInt16,

  arp_op     UInt16,
  sender_mac FixedString(6),
  sender_ip  IPv4,
  target_mac FixedString(6),
  target_ip  IPv4
)
ENGINE = ReplacingMergeTree
ORDER BY (ts, session_id, packet_id)
