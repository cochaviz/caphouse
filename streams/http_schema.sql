
CREATE TABLE IF NOT EXISTS {{ table }}
(
  session_id UInt64,
  stream_id  UUID,
  method     LowCardinality(String),
  host       String,
  path       String,
  INDEX idx_host (host) TYPE bloom_filter GRANULARITY 4,
  INDEX idx_method (method) TYPE set(16) GRANULARITY 4
)
ENGINE = ReplacingMergeTree
ORDER BY (session_id, stream_id)
