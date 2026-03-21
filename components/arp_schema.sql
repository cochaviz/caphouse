
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id    UUID,
  packet_id     UInt64 CODEC(Delta, LZ4),
  codec_version UInt16,

  arp_op     UInt16,
  sender_mac FixedString(6),
  sender_ip  IPv4,
  target_mac FixedString(6),
  target_ip  IPv4
)
ENGINE = ReplacingMergeTree
ORDER BY (sender_ip, target_ip, capture_id, packet_id)
