DROP TABLE IF EXISTS geoip_v6_url;

CREATE TABLE geoip_v6_url(
    ip_range_start IPv6,
    ip_range_end   IPv6,
    country_code   Nullable(String),
    state1         Nullable(String),
    state2         Nullable(String),
    city           Nullable(String),
    postcode       Nullable(String),
    latitude       Float64,
    longitude      Float64,
    timezone       Nullable(String)
) ENGINE=URL('{source_url_v6}', 'CSV');

CREATE OR REPLACE TABLE geoip_v6 (
    cidr         String,
    country_code String,
    city         String
) ENGINE = MergeTree() ORDER BY cidr;

INSERT INTO geoip_v6
WITH
    IPv6StringToNum(toString(ip_range_start)) AS start_bytes,
    IPv6StringToNum(toString(ip_range_end))   AS end_bytes,
    bitXor(start_bytes, end_bytes)            AS xor_bytes,
    hex(xor_bytes)                            AS xor_hex,
    replaceAll(xor_hex, '0', '')              AS nonzero_part,
    if(nonzero_part = '',
        32,
        position(xor_hex, substring(nonzero_part, 1, 1)) - 1
    )                                         AS leading_zero_nibbles,
    multiIf(
        nonzero_part = '',                                                                    0,
        substring(xor_hex, leading_zero_nibbles + 1, 1) IN ('8','9','A','B','C','D','E','F'), 0,
        substring(xor_hex, leading_zero_nibbles + 1, 1) IN ('4','5','6','7'),                1,
        substring(xor_hex, leading_zero_nibbles + 1, 1) IN ('2','3'),                        2,
        3
    )                                         AS extra_zeros,
    if(nonzero_part = '',
        toUInt8(128),
        toUInt8(leading_zero_nibbles * 4 + extra_zeros)
    )                                         AS cidr_suffix
SELECT
    concat(IPv6NumToString(start_bytes), '/', toString(cidr_suffix)) AS cidr,
    coalesce(country_code, '') AS country_code,
    coalesce(city, '')         AS city
FROM geoip_v6_url;

DROP DICTIONARY IF EXISTS ip_trie_v6;

CREATE DICTIONARY ip_trie_v6 (
    cidr         String,
    country_code String,
    city         String
) PRIMARY KEY cidr
SOURCE(CLICKHOUSE(TABLE 'geoip_v6'))
LAYOUT(IP_TRIE())
LIFETIME(3600);

DROP TABLE IF EXISTS geoip_v6_url;
