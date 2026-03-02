
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  packet_id  UInt64 CODEC(Delta, LZ4),

  codec_version UInt16,

  tag_index     UInt16,
  priority      UInt8,
  drop_eligible UInt8,
  vlan_id       UInt16,
  eth_type      UInt16
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, packet_id, tag_index)
