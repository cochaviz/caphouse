DROP TABLE IF EXISTS asn_url;

CREATE TABLE asn_url(
    ip_range_start                 IPv4,
    ip_range_end                   IPv4,
    autonomous_system_number       String,
    autonomous_system_organization Nullable(String)
) ENGINE=URL('{asn_source_url}', 'CSV');

CREATE OR REPLACE TABLE asn (
    cidr String,
    asn  String,
    org  String
) ENGINE = MergeTree() ORDER BY cidr;

INSERT INTO asn
WITH
    bitXor(ip_range_start, ip_range_end) AS xor,
    if(xor != 0, ceil(log2(xor)), 0) AS unmatched,
    32 - unmatched AS cidr_suffix,
    toIPv4(bitAnd(bitNot(pow(2, unmatched) - 1), ip_range_start)::UInt64) AS cidr_address
SELECT
    concat(toString(cidr_address), '/', toString(cidr_suffix)) AS cidr,
    autonomous_system_number AS asn,
    coalesce(autonomous_system_organization, '') AS org
FROM asn_url;

DROP DICTIONARY IF EXISTS asn_trie;

CREATE DICTIONARY asn_trie (
    cidr String,
    asn  String,
    org  String
) PRIMARY KEY cidr
SOURCE(CLICKHOUSE(TABLE 'asn'))
LAYOUT(IP_TRIE())
LIFETIME(3600);

DROP TABLE IF EXISTS asn_url;
