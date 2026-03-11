package caphouse

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

// byteOrder returns the binary byte order for an endianness string ("le"/"be").
func byteOrder(endian string) binary.ByteOrder {
	if endian == "be" {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

var errUnsupportedMagic = errors.New("unsupported pcap magic")

// CaptureMeta describes one stored capture's global metadata.
type CaptureMeta struct {
	CaptureID      uuid.UUID
	SensorID       string
	CreatedAt      time.Time
	Snaplen        uint32
	LinkType       uint32 // DLT, for Ethernet use 1
	Endianness     string // "le" or "be"
	TimeResolution string // "us" or "ns"

	GlobalHeaderRaw []byte // 24-byte classic PCAP header; empty for pcapng-sourced captures

	CodecVersion uint16
	CodecProfile string
}

func (CaptureMeta) Table() string { return "pcap_captures" }

func (CaptureMeta) ClickhouseColumns() ([]string, error) {
	return []string{
		"capture_id", "sensor_id", "created_at",
		"endianness", "snaplen", "linktype", "time_res",
		"global_header_raw", "codec_version", "codec_profile",
	}, nil
}

func (m CaptureMeta) ClickhouseValues() ([]any, error) {
	raw := m.GlobalHeaderRaw
	if raw == nil {
		raw = []byte{}
	}
	return []any{
		m.CaptureID, m.SensorID, m.CreatedAt,
		m.Endianness, m.Snaplen, m.LinkType, m.TimeResolution,
		raw, m.CodecVersion, m.CodecProfile,
	}, nil
}

func (CaptureMeta) ScanColumns() []string {
	return []string{
		"capture_id", "sensor_id", "created_at",
		"endianness", "snaplen", "linktype", "time_res",
		"global_header_raw", "codec_version", "codec_profile",
	}
}

// ScanRow populates m from a single ClickHouse row (e.g. from QueryRow).
func (m *CaptureMeta) ScanRow(row chdriver.Row) error {
	var headerRaw string
	if err := row.Scan(
		&m.CaptureID, &m.SensorID, &m.CreatedAt,
		&m.Endianness, &m.Snaplen, &m.LinkType, &m.TimeResolution,
		&headerRaw,
		&m.CodecVersion, &m.CodecProfile,
	); err != nil {
		return err
	}
	m.GlobalHeaderRaw = []byte(headerRaw)
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

// fetchCaptureMeta retrieves the stored metadata for a capture.
func (c *Client) fetchCaptureMeta(ctx context.Context, captureID uuid.UUID) (CaptureMeta, error) {
	var meta CaptureMeta
	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE capture_id = ? LIMIT 1",
		strings.Join(meta.ScanColumns(), ", "), c.capturesTable(),
	)
	if err := meta.ScanRow(c.conn.QueryRow(ctx, query, captureID)); err != nil {
		return CaptureMeta{}, fmt.Errorf("fetch capture meta: %w", err)
	}
	return meta, nil
}
