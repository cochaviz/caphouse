
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id  UInt64 CODEC(LZ4),
  packet_id  UInt32 CODEC(Delta, LZ4),

  codec_version UInt16,

  tag_index     UInt16,
  priority      UInt8,
  drop_eligible UInt8,
  vlan_id       UInt16,
  type          UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, packet_id, tag_index)
