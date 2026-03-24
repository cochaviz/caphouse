
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id       UInt64,
  sensor_id        LowCardinality(String),
  endianness       Enum8('le' = 1, 'be' = 2),
  snaplen          UInt32,
  linktype         UInt32,
  time_res         LowCardinality(String),
  global_header_raw String,
  codec_version    UInt16,
  codec_profile    LowCardinality(String)
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id)
