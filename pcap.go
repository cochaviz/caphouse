package caphouse

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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

// ErrPcapNG is returned by ParseGlobalHeader when the file is in pcapng format.
// Use ParseNgCaptureMeta to handle pcapng files.
var ErrPcapNG = errors.New("pcapng format")

// CaptureMeta describes one stored capture's global metadata.
type CaptureMeta struct {
	CaptureID      uuid.UUID
	SensorID       string
	CreatedAt      time.Time
	Snaplen        uint32
	LinkType       uint32 // DLT, for Ethernet use 1
	Endianness     string // "le" or "be"
	TimeResolution string // "us" or "ns" for classic pcap; "pcapng" for pcapng format
	IsPcapNG       bool   // true when the source file is pcapng format

	GlobalHeaderRaw []byte // optional 24-byte classic pcap header

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
	m.IsPcapNG = m.TimeResolution == "pcapng"
	return nil
}

// ParseGlobalHeader reads classic PCAP global header bytes into metadata.
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

// ParseNgCaptureMeta reads a pcapng file header and returns a CaptureMeta
// populated from the Section Header Block and first Interface Description Block.
// It also returns the NgReader positioned at the first packet.
func ParseNgCaptureMeta(r io.Reader) (CaptureMeta, *pcapgo.NgReader, error) {
	ngr, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return CaptureMeta{}, nil, fmt.Errorf("pcapng reader: %w", err)
	}
	meta := CaptureMeta{
		IsPcapNG:       true,
		Endianness:     "le",
		TimeResolution: "pcapng",
		LinkType:       uint32(ngr.LinkType()),
		Snaplen:        65535,
	}
	return meta, ngr, nil
}

// NgPacket is a single packet for pcapng export.
type NgPacket struct {
	Timestamp time.Time
	InclLen   uint32
	OrigLen   uint32
	Frame     []byte
}

// WriteNgPackets writes packets as a pcapng file to w.
func WriteNgPackets(w io.Writer, linkType uint32, packets []NgPacket) error {
	ngw, err := pcapgo.NewNgWriter(w, layers.LinkType(linkType))
	if err != nil {
		return fmt.Errorf("pcapng writer: %w", err)
	}
	for _, p := range packets {
		ci := gopacket.CaptureInfo{
			Timestamp:     p.Timestamp,
			CaptureLength: int(p.InclLen),
			Length:        int(p.OrigLen),
		}
		if err := ngw.WritePacket(ci, p.Frame); err != nil {
			return fmt.Errorf("write pcapng packet: %w", err)
		}
	}
	return ngw.Flush()
}

// pcapng block type constants.
const (
	ngBlockSHB uint32 = 0x0A0D0D0A
	ngBlockIDB uint32 = 0x00000001
	ngBlockEPB uint32 = 0x00000006
	ngBlockSPB uint32 = 0x00000003
)

// NgRawPacket is a packet extracted from a pcapng stream with its raw block
// bytes preserved for byte-exact re-export.
type NgRawPacket struct {
	BlockRaw  []byte    // complete EPB or SPB block bytes
	Frame     []byte    // extracted packet payload
	Timestamp time.Time // decoded from EPB timestamp fields (zero for SPB)
	InclLen   uint32    // captured length
	OrigLen   uint32    // original (wire) length
}

// ReadNgRaw reads a pcapng stream block by block and returns:
//   - meta: CaptureMeta with IsPcapNG=true, LinkType and Snaplen from the first IDB
//   - headerRaw: raw bytes of all non-packet blocks (SHB + IDBs + any others)
//   - packets: one NgRawPacket per EPB/SPB with raw block bytes preserved
//
// The original file can be reconstructed exactly as: headerRaw + concat(p.BlockRaw).
func ReadNgRaw(r io.Reader) (meta CaptureMeta, headerRaw []byte, packets []NgRawPacket, err error) {
	// Read SHB preamble: block_type(4) + block_total_length(4) + byte_order_magic(4).
	var preamble [12]byte
	if _, err := io.ReadFull(r, preamble[:]); err != nil {
		return CaptureMeta{}, nil, nil, fmt.Errorf("read pcapng SHB: %w", err)
	}
	if binary.LittleEndian.Uint32(preamble[0:4]) != ngBlockSHB {
		return CaptureMeta{}, nil, nil, fmt.Errorf("not a pcapng file")
	}
	// Byte-order magic at offset 8 determines endianness.
	boMagic := binary.LittleEndian.Uint32(preamble[8:12])
	var order binary.ByteOrder
	switch boMagic {
	case 0x1A2B3C4D:
		order = binary.LittleEndian
	case 0x4D3C2B1A:
		order = binary.BigEndian
	default:
		return CaptureMeta{}, nil, nil, fmt.Errorf("pcapng: unrecognized byte-order magic 0x%08X", boMagic)
	}

	shbLen := order.Uint32(preamble[4:8])
	if shbLen < 28 {
		return CaptureMeta{}, nil, nil, fmt.Errorf("pcapng SHB too short: %d bytes", shbLen)
	}
	shbRaw := make([]byte, shbLen)
	copy(shbRaw[:12], preamble[:])
	if _, err := io.ReadFull(r, shbRaw[12:]); err != nil {
		return CaptureMeta{}, nil, nil, fmt.Errorf("read pcapng SHB body: %w", err)
	}
	headerRaw = append(headerRaw, shbRaw...)

	endian := "le"
	if order == binary.BigEndian {
		endian = "be"
	}
	meta = CaptureMeta{
		IsPcapNG:       true,
		Endianness:     endian,
		TimeResolution: "pcapng",
		Snaplen:        65535,
	}

	// Per-interface timestamp resolution in units/second (default: 1 µs = 10^6).
	var ifTsRes []uint64
	// Non-packet blocks that appear after the first packet are collected here
	// and prepended to the next packet's BlockRaw to preserve original order.
	var pendingNonPacket []byte

	for {
		// Read block type.
		var typeBuf [4]byte
		if _, readErr := io.ReadFull(r, typeBuf[:]); errors.Is(readErr, io.EOF) {
			break
		} else if readErr != nil {
			return CaptureMeta{}, nil, nil, fmt.Errorf("read pcapng block type: %w", readErr)
		}
		// Read block total length.
		var lenBuf [4]byte
		if _, readErr := io.ReadFull(r, lenBuf[:]); readErr != nil {
			return CaptureMeta{}, nil, nil, fmt.Errorf("read pcapng block length: %w", readErr)
		}
		bType := order.Uint32(typeBuf[:])
		bLen := order.Uint32(lenBuf[:])
		if bLen < 12 {
			return CaptureMeta{}, nil, nil, fmt.Errorf("pcapng block length %d < 12", bLen)
		}
		// Read the rest of the block.
		raw := make([]byte, bLen)
		copy(raw[0:4], typeBuf[:])
		copy(raw[4:8], lenBuf[:])
		if _, readErr := io.ReadFull(r, raw[8:]); readErr != nil {
			return CaptureMeta{}, nil, nil, fmt.Errorf("read pcapng block (type=0x%08X): %w", bType, readErr)
		}

		switch bType {
		case ngBlockIDB:
			// IDB body: link_type(2) + reserved(2) + snap_len(4) + options(...)
			// Always parse for timestamp resolution; IDBs may appear after packets.
			if len(raw) >= 16 {
				lt := uint32(order.Uint16(raw[8:10]))
				sl := order.Uint32(raw[12:16])
				if len(ifTsRes) == 0 { // LinkType/Snaplen from first IDB only
					meta.LinkType = lt
					meta.Snaplen = sl
				}
				ifTsRes = append(ifTsRes, ngParseTsResol(raw[16:len(raw)-4], order))
			}
			if len(packets) == 0 {
				headerRaw = append(headerRaw, raw...)
			} else {
				pendingNonPacket = append(pendingNonPacket, raw...)
			}

		case ngBlockEPB:
			// EPB body: interface_id(4) + ts_high(4) + ts_low(4) + cap_len(4) + orig_len(4) + data(...)
			if len(raw) < 32 {
				return CaptureMeta{}, nil, nil, fmt.Errorf("pcapng EPB too short: %d bytes", len(raw))
			}
			ifaceID := order.Uint32(raw[8:12])
			tsHigh := order.Uint32(raw[12:16])
			tsLow := order.Uint32(raw[16:20])
			capLen := order.Uint32(raw[20:24])
			origLen := order.Uint32(raw[24:28])
			if int(capLen) > len(raw)-32 { // 28 header + 4 trailing length
				return CaptureMeta{}, nil, nil, fmt.Errorf("pcapng EPB capLen %d exceeds block", capLen)
			}
			frame := make([]byte, capLen)
			copy(frame, raw[28:28+capLen])
			ts := ngDecodeTs((uint64(tsHigh)<<32)|uint64(tsLow), ngTsRes(ifTsRes, ifaceID))
			// Attach any queued non-packet blocks before this EPB.
			blockRaw := append(pendingNonPacket, raw...)
			pendingNonPacket = nil
			packets = append(packets, NgRawPacket{
				BlockRaw: blockRaw, Frame: frame, Timestamp: ts, InclLen: capLen, OrigLen: origLen,
			})

		case ngBlockSPB:
			// SPB body: orig_len(4) + data(padded)
			if len(raw) < 16 {
				return CaptureMeta{}, nil, nil, fmt.Errorf("pcapng SPB too short: %d bytes", len(raw))
			}
			origLen := order.Uint32(raw[8:12])
			capLen := origLen
			if capLen > meta.Snaplen {
				capLen = meta.Snaplen
			}
			if int(capLen) > len(raw)-16 {
				return CaptureMeta{}, nil, nil, fmt.Errorf("pcapng SPB capLen %d exceeds block", capLen)
			}
			frame := make([]byte, capLen)
			copy(frame, raw[12:12+capLen])
			blockRaw := append(pendingNonPacket, raw...)
			pendingNonPacket = nil
			packets = append(packets, NgRawPacket{
				BlockRaw: blockRaw, Frame: frame, Timestamp: time.Time{}, InclLen: capLen, OrigLen: origLen,
			})

		default:
			// NRB, ISB, and unknown blocks — queue for next packet or header.
			if len(packets) == 0 {
				headerRaw = append(headerRaw, raw...)
			} else {
				pendingNonPacket = append(pendingNonPacket, raw...)
			}
		}
	}
	// Trailing non-packet blocks (e.g. ISBs after the last packet) are appended
	// to the last packet's BlockRaw to preserve the original byte sequence.
	if len(pendingNonPacket) > 0 {
		if len(packets) > 0 {
			last := &packets[len(packets)-1]
			last.BlockRaw = append(last.BlockRaw, pendingNonPacket...)
		} else {
			headerRaw = append(headerRaw, pendingNonPacket...)
		}
	}
	return meta, headerRaw, packets, nil
}

// ngParseTsResol extracts the if_tsresol value from IDB option bytes and
// returns the timestamp resolution in units/second. Defaults to 1,000,000 (µs).
func ngParseTsResol(opts []byte, order binary.ByteOrder) uint64 {
	for len(opts) >= 4 {
		code := order.Uint16(opts[0:2])
		length := int(order.Uint16(opts[2:4]))
		if code == 0 {
			break
		}
		padded := (length + 3) &^ 3
		if 4+padded > len(opts) {
			break
		}
		if code == 9 && length >= 1 { // if_tsresol
			v := opts[4]
			if v&0x80 == 0 { // power of 10
				res := uint64(1)
				for range int(v & 0x7F) {
					res *= 10
				}
				return res
			}
			if exp := int(v & 0x7F); exp < 64 { // power of 2
				return uint64(1) << exp
			}
		}
		opts = opts[4+padded:]
	}
	return 1_000_000 // default: microseconds
}

// ngTsRes returns the timestamp resolution (units/second) for an interface ID.
func ngTsRes(res []uint64, ifaceID uint32) uint64 {
	if int(ifaceID) < len(res) {
		return res[ifaceID]
	}
	return 1_000_000
}

// ngDecodeTs converts a raw 64-bit pcapng timestamp to time.Time.
func ngDecodeTs(ts64, resolution uint64) time.Time {
	if resolution == 0 {
		resolution = 1_000_000
	}
	sec := int64(ts64 / resolution)
	ns := int64(ts64%resolution) * 1_000_000_000 / int64(resolution)
	return time.Unix(sec, ns).UTC()
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
