DROP TABLE IF EXISTS asn_v6_url;

CREATE TABLE asn_v6_url(
    ip_range_start                 IPv6,
    ip_range_end                   IPv6,
    autonomous_system_number       String,
    autonomous_system_organization Nullable(String)
) ENGINE=URL('{asn_source_url_v6}', 'CSV');

CREATE OR REPLACE TABLE asn_v6 (
    cidr String,
    asn  String,
    org  String
) ENGINE = MergeTree() ORDER BY cidr;

INSERT INTO asn_v6
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
    autonomous_system_number                         AS asn,
    coalesce(autonomous_system_organization, '')     AS org
FROM asn_v6_url;

DROP DICTIONARY IF EXISTS asn_trie_v6;

CREATE DICTIONARY asn_trie_v6 (
    cidr String,
    asn  String,
    org  String
) PRIMARY KEY cidr
SOURCE(CLICKHOUSE(TABLE 'asn_v6'))
LAYOUT(IP_TRIE())
LIFETIME(3600);

DROP TABLE IF EXISTS asn_v6_url;
