
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id       UUID,
  sensor_id        LowCardinality(String),
  created_at       DateTime64(3),
  endianness       Enum8('le' = 1, 'be' = 2),
  snaplen          UInt32,
  linktype         UInt32,
  time_res         Enum8('us' = 1),
  global_header_raw String,
  codec_version    UInt16,
  codec_profile    LowCardinality(String)
)
ENGINE = ReplacingMergeTree
ORDER BY (sensor_id, created_at, capture_id)
