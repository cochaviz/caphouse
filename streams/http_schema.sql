
CREATE TABLE IF NOT EXISTS {{ table }}
(
  capture_id UUID,
  stream_id  UUID,
  method     LowCardinality(String),
  host       String,
  path       String
)
ENGINE = ReplacingMergeTree
ORDER BY (capture_id, stream_id)
