DROP TABLE IF EXISTS geoip_url;

CREATE TABLE geoip_url(
    ip_range_start IPv4,
    ip_range_end   IPv4,
    country_code   Nullable(String),
    state1         Nullable(String),
    state2         Nullable(String),
    city           Nullable(String),
    postcode       Nullable(String),
    latitude       Float64,
    longitude      Float64,
    timezone       Nullable(String)
) ENGINE=URL('{source_url}', 'CSV');

CREATE OR REPLACE TABLE geoip (
    cidr         String,
    country_code String,
    city         String
) ENGINE = MergeTree() ORDER BY cidr;

INSERT INTO geoip
WITH
    bitXor(ip_range_start, ip_range_end) AS xor,
    if(xor != 0, ceil(log2(xor)), 0) AS unmatched,
    32 - unmatched AS cidr_suffix,
    toIPv4(bitAnd(bitNot(pow(2, unmatched) - 1), ip_range_start)::UInt64) AS cidr_address
SELECT
    concat(toString(cidr_address), '/', toString(cidr_suffix)) AS cidr,
    coalesce(country_code, '') AS country_code,
    coalesce(city, '') AS city
FROM geoip_url;

DROP DICTIONARY IF EXISTS ip_trie;

CREATE DICTIONARY ip_trie (
    cidr         String,
    country_code String,
    city         String
) PRIMARY KEY cidr
SOURCE(CLICKHOUSE(TABLE 'geoip'))
LAYOUT(IP_TRIE())
LIFETIME(3600);

DROP TABLE IF EXISTS geoip_url;
