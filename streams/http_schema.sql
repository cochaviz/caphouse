
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id UInt64,
  stream_id  UUID,
  method     LowCardinality(String),
  host       String,
  path       String
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, stream_id)
