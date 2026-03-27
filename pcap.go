package caphouse

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// byteOrder returns the binary byte order for an endianness string ("le"/"be").
func byteOrder(endian string) binary.ByteOrder {
	if endian == "be" {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

var errUnsupportedMagic = errors.New("unsupported pcap magic")

// CaptureMeta describes one stored session's global metadata.
type CaptureMeta struct {
	SessionID      uint64
	Sensor         string
	Snaplen        uint32
	LinkType       uint32 // DLT, for Ethernet use 1
	Endianness     string // "le" or "be"
	TimeResolution string // "us" or "ns"

	GlobalHeaderRaw []byte // 24-byte classic PCAP header; empty for pcapng-sourced captures

	CodecVersion uint16
	CodecProfile string
}

// Table implements clickhouseMapper.
func (CaptureMeta) Table() string { return "pcap_captures" }

// ClickhouseColumns implements clickhouseMapper.
func (CaptureMeta) ClickhouseColumns() ([]string, error) {
	return []string{
		"session_id", "sensor",
		"endianness", "snaplen", "linktype", "time_res",
		"global_header_raw", "codec_version", "codec_profile",
	}, nil
}

// ClickhouseValues implements clickhouseMapper. A nil GlobalHeaderRaw is
// replaced with an empty byte slice so ClickHouse does not reject the row.
func (m CaptureMeta) ClickhouseValues() ([]any, error) {
	raw := m.GlobalHeaderRaw
	if raw == nil {
		raw = []byte{}
	}
	return []any{
		m.SessionID, m.Sensor,
		m.Endianness, m.Snaplen, m.LinkType, m.TimeResolution,
		raw, m.CodecVersion, m.CodecProfile,
	}, nil
}

// ScanColumns implements clickhouseMapper.
func (CaptureMeta) ScanColumns() []string {
	return []string{
		"session_id", "sensor",
		"endianness", "snaplen", "linktype", "time_res",
		"global_header_raw", "codec_version", "codec_profile",
	}
}

// ScanRow populates m from a single ClickHouse row (e.g. from QueryRow).
func (m *CaptureMeta) ScanRow(row chdriver.Row) error {
	result, err := scanCaptureMeta(row.Scan)
	if err != nil {
		return err
	}
	*m = result
	return nil
}

// ParseGlobalHeader reads classic PCAP global header bytes into metadata.
// Returns ErrPcapNG if the stream is a pcapng file; callers should pass the
// reader to ParseNgCaptureMeta (pcapng.go) for pcapng processing.
func ParseGlobalHeader(raw []byte) (CaptureMeta, error) {
	if len(raw) < 24 {
		return CaptureMeta{}, errors.New("pcap header too short")
	}
	magic := binary.LittleEndian.Uint32(raw[0:4])
	meta := CaptureMeta{TimeResolution: "us"}

	switch magic {
	case 0xA1B2C3D4:
		meta.Endianness = "le"
	case 0xD4C3B2A1:
		meta.Endianness = "be"
	case 0xA1B23C4D:
		meta.Endianness = "le"
		meta.TimeResolution = "ns"
	case 0x4D3CB2A1:
		meta.Endianness = "be"
		meta.TimeResolution = "ns"
	case 0x0A0D0D0A:
		return CaptureMeta{}, ErrPcapNG
	default:
		return CaptureMeta{}, errUnsupportedMagic
	}

	order := byteOrder(meta.Endianness)
	meta.Snaplen = order.Uint32(raw[16:20])
	meta.LinkType = order.Uint32(raw[20:24])
	meta.GlobalHeaderRaw = raw[:24]
	return meta, nil
}

// scanCaptureMeta scans one CaptureMeta row using the provided scan function.
// Works with both chdriver.Row (QueryRow) and chdriver.Rows (Query).
func scanCaptureMeta(scan func(dest ...any) error) (CaptureMeta, error) {
	var m CaptureMeta
	var headerRaw string
	if err := scan(
		&m.SessionID, &m.Sensor,
		&m.Endianness, &m.Snaplen, &m.LinkType, &m.TimeResolution,
		&headerRaw,
		&m.CodecVersion, &m.CodecProfile,
	); err != nil {
		return CaptureMeta{}, err
	}
	m.GlobalHeaderRaw = []byte(headerRaw)
	return m, nil
}

// FetchAllSessions returns all stored session metadata.
func (c *Client) FetchAllSessions(ctx context.Context) ([]CaptureMeta, error) {
	cols := strings.Join(CaptureMeta{}.ScanColumns(), ", ")
	query := fmt.Sprintf(
		"SELECT %s FROM %s FINAL ORDER BY session_id ASC",
		cols, c.capturesTable(),
	)
	rows, err := c.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("fetch sessions: %w", err)
	}
	defer rows.Close()
	var captures []CaptureMeta
	for rows.Next() {
		m, err := scanCaptureMeta(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan capture meta: %w", err)
		}
		captures = append(captures, m)
	}
	return captures, rows.Err()
}

// fetchCaptureMeta retrieves the stored metadata for a session.
func (c *Client) fetchCaptureMeta(ctx context.Context, sessionID uint64) (CaptureMeta, error) {
	var meta CaptureMeta
	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE session_id = ? LIMIT 1",
		strings.Join(meta.ScanColumns(), ", "), c.capturesTable(),
	)
	if err := meta.ScanRow(c.conn.QueryRow(ctx, query, sessionID)); err != nil {
		return CaptureMeta{}, fmt.Errorf("fetch capture meta: %w", err)
	}
	return meta, nil
}
