package caphouse

import (
	"bufio"
	"caphouse/components"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/netip"
	"os"
	"time"

	"github.com/google/uuid"
)

type captureMetaRow struct {
	Endianness      string
	Snaplen         uint32
	LinkType        uint32
	TimeResolution  string
	GlobalHeaderRaw []byte
}

// ExportCapture returns a reader that streams a classic PCAP file.
func (c *Client) ExportCapture(ctx context.Context, captureID uuid.UUID) (io.ReadCloser, error) {
	meta, err := c.fetchCaptureMeta(ctx, captureID)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		if err := c.streamCapture(ctx, meta, captureID, pw); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	return pr, nil
}

// ExportCaptureBytes reads the entire capture into memory.
func (c *Client) ExportCaptureBytes(ctx context.Context, captureID uuid.UUID) ([]byte, error) {
	rc, err := c.ExportCapture(ctx, captureID)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	return io.ReadAll(rc)
}

func (c *Client) fetchCaptureMeta(ctx context.Context, captureID uuid.UUID) (captureMetaRow, error) {
	query := fmt.Sprintf("SELECT endianness, snaplen, linktype, time_res, global_header_raw FROM %s WHERE capture_id = ? LIMIT 1", c.capturesTable())

	var meta captureMetaRow
	var headerRaw string
	if err := c.conn.QueryRow(ctx, query, captureID).Scan(
		&meta.Endianness,
		&meta.Snaplen,
		&meta.LinkType,
		&meta.TimeResolution,
		&headerRaw,
	); err != nil {
		return captureMetaRow{}, fmt.Errorf("fetch capture meta: %w", err)
	}
	meta.GlobalHeaderRaw = []byte(headerRaw)
	return meta, nil
}

func (c *Client) streamCapture(ctx context.Context, meta captureMetaRow, captureID uuid.UUID, w io.Writer) error {
	buf := bufio.NewWriterSize(w, 128*1024)
	if err := writePCAPHeader(buf, meta); err != nil {
		return err
	}

	query := fmt.Sprintf("SELECT packet_id, ts, incl_len, orig_len, components, tail_offset, frame_raw, frame_hash FROM %s WHERE capture_id = ? ORDER BY packet_id ASC", c.packetsTable())
	rows, err := c.conn.Query(ctx, query, captureID)
	if err != nil {
		return fmt.Errorf("query packets: %w", err)
	}
	defer rows.Close()

	order := byteOrder(meta.Endianness)
	for rows.Next() {
		var packetID uint64
		var ts time.Time
		var incl uint32
		var orig uint32
		var componentMask big.Int
		var tailOffset uint16
		var frameRaw string
		var frameHash string
		if err := rows.Scan(&packetID, &ts, &incl, &orig, &componentMask, &tailOffset, &frameRaw, &frameHash); err != nil {
			return fmt.Errorf("scan packet: %w", err)
		}

		nucleus := components.PacketNucleus{
			CaptureID:  captureID,
			PacketID:   packetID,
			Timestamp:  ts,
			InclLen:    incl,
			OrigLen:    orig,
			Components: new(big.Int).Set(&componentMask),
			TailOffset: tailOffset,
			FrameRaw:   []byte(frameRaw),
			FrameHash:  []byte(frameHash),
		}

		componentList := []components.ClickhouseMappedDecoder{}

		if components.ComponentHas(nucleus.Components, components.ComponentEthernet) {
			ethernet, err := c.fetchEthernet(ctx, captureID, packetID)
			if err != nil {
				return err
			}
			componentList = append(componentList, ethernet)
		}
		if components.ComponentHas(nucleus.Components, components.ComponentDot1Q) {
			tags, err := c.fetchDot1Q(ctx, captureID, packetID)
			if err != nil {
				return err
			}
			componentList = append(componentList, tags...)
		}
		if components.ComponentHas(nucleus.Components, components.ComponentLinuxSLL) {
			sll, err := c.fetchLinuxSLL(ctx, captureID, packetID)
			if err != nil {
				return err
			}
			componentList = append(componentList, sll)
		}
		if components.ComponentHas(nucleus.Components, components.ComponentIPv4) {
			ipv4, err := c.fetchIPv4(ctx, captureID, packetID)
			if err != nil {
				return err
			}
			componentList = append(componentList, ipv4)
		}
		if components.ComponentHas(nucleus.Components, components.ComponentIPv4Options) {
			options, err := c.fetchIPv4Options(ctx, captureID, packetID)
			if err != nil {
				return err
			}
			componentList = append(componentList, options)
		}
		if components.ComponentHas(nucleus.Components, components.ComponentIPv6) {
			ipv6, err := c.fetchIPv6(ctx, captureID, packetID)
			if err != nil {
				return err
			}
			componentList = append(componentList, ipv6)
		}
		if components.ComponentHas(nucleus.Components, components.ComponentIPv6Ext) {
			exts, err := c.fetchIPv6Ext(ctx, captureID, packetID)
			if err != nil {
				return err
			}
			componentList = append(componentList, exts...)
		}
		if components.ComponentHas(nucleus.Components, components.ComponentRawTail) {
			tail, err := c.fetchRawTail(ctx, captureID, packetID)
			if err != nil {
				return err
			}
			componentList = append(componentList, tail)
		}

		frame, err := ReconstructFrame(nucleus, componentList)
		if err != nil {
			if c.cfg.Debug {
				debugPacketDump(captureID, packetID, nucleus, componentList)
			}
			return fmt.Errorf("reconstruct packet %d: %w", packetID, err)
		}
		if err := writePacketRecord(buf, order, ts, incl, orig, frame); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate packets: %w", err)
	}
	if err := buf.Flush(); err != nil {
		return fmt.Errorf("flush pcap stream: %w", err)
	}
	return nil
}

func (c *Client) fetchEthernet(ctx context.Context, captureID uuid.UUID, packetID uint64) (*components.EthernetComponent, error) {
	query := fmt.Sprintf("SELECT src_mac, dst_mac, eth_type, eth_len FROM %s WHERE capture_id = ? AND packet_id = ? LIMIT 1", c.ethernetTable())
	var src string
	var dst string
	var ethType uint16
	var ethLen uint16
	if err := c.conn.QueryRow(ctx, query, captureID, packetID).Scan(&src, &dst, &ethType, &ethLen); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("missing ethernet component for %s/%d", captureID, packetID)
		}
		return nil, fmt.Errorf("fetch ethernet: %w", err)
	}
	return &components.EthernetComponent{
		CaptureID: captureID,
		PacketID:  packetID,
		SrcMAC:    []byte(src),
		DstMAC:    []byte(dst),
		EtherType: ethType,
		Length:    ethLen,
	}, nil
}

func (c *Client) fetchDot1Q(ctx context.Context, captureID uuid.UUID, packetID uint64) ([]components.ClickhouseMappedDecoder, error) {
	query := fmt.Sprintf("SELECT tag_index, priority, drop_eligible, vlan_id, eth_type FROM %s WHERE capture_id = ? AND packet_id = ? ORDER BY tag_index ASC", c.dot1qTable())
	rows, err := c.conn.Query(ctx, query, captureID, packetID)
	if err != nil {
		return nil, fmt.Errorf("fetch dot1q: %w", err)
	}
	defer rows.Close()

	var componentsList []components.ClickhouseMappedDecoder
	for rows.Next() {
		var index uint16
		var priority uint8
		var dropEligible uint8
		var vlanID uint16
		var ethType uint16
		if err := rows.Scan(&index, &priority, &dropEligible, &vlanID, &ethType); err != nil {
			return nil, fmt.Errorf("scan dot1q: %w", err)
		}
		componentsList = append(componentsList, &components.Dot1QComponent{
			CaptureID:    captureID,
			PacketID:     packetID,
			TagIndex:     index,
			Priority:     priority,
			VLANID:       vlanID,
			EtherType:    ethType,
			DropEligible: dropEligible,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate dot1q: %w", err)
	}
	if len(componentsList) == 0 {
		return nil, fmt.Errorf("missing dot1q component for %s/%d", captureID, packetID)
	}
	return componentsList, nil
}

func (c *Client) fetchLinuxSLL(ctx context.Context, captureID uuid.UUID, packetID uint64) (*components.LinuxSLLComponent, error) {
	query := fmt.Sprintf("SELECT l2_len, l2_hdr_raw FROM %s WHERE capture_id = ? AND packet_id = ? LIMIT 1", c.linuxSLLTable())
	var l2Len uint16
	var raw string
	if err := c.conn.QueryRow(ctx, query, captureID, packetID).Scan(&l2Len, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("missing linux sll component for %s/%d", captureID, packetID)
		}
		return nil, fmt.Errorf("fetch linux sll: %w", err)
	}
	return &components.LinuxSLLComponent{
		CaptureID: captureID,
		PacketID:  packetID,
		L2Len:     l2Len,
		L2HdrRaw:  []byte(raw),
	}, nil
}

func (c *Client) fetchIPv4(ctx context.Context, captureID uuid.UUID, packetID uint64) (*components.IPv4Component, error) {
	query := fmt.Sprintf(`SELECT ts, parsed_ok, parse_err, protocol, src_ip_v4, dst_ip_v4,
  ipv4_ihl, ipv4_tos, ipv4_total_len, ipv4_id, ipv4_flags, ipv4_frag_offset, ipv4_ttl, ipv4_hdr_checksum
FROM %s WHERE capture_id = ? AND packet_id = ? LIMIT 1`, c.ipv4Table())
	var ts time.Time
	var parsedOK uint8
	var parseErr string
	var protocol uint8
	var src4 string
	var dst4 string
	var ipv4IHL uint8
	var ipv4TOS uint8
	var ipv4TotalLen uint16
	var ipv4ID uint16
	var ipv4Flags uint8
	var ipv4Frag uint16
	var ipv4TTL uint8
	var ipv4Checksum uint16
	if err := c.conn.QueryRow(ctx, query, captureID, packetID).Scan(
		&ts,
		&parsedOK,
		&parseErr,
		&protocol,
		&src4,
		&dst4,
		&ipv4IHL,
		&ipv4TOS,
		&ipv4TotalLen,
		&ipv4ID,
		&ipv4Flags,
		&ipv4Frag,
		&ipv4TTL,
		&ipv4Checksum,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("missing ipv4 component for %s/%d", captureID, packetID)
		}
		return nil, fmt.Errorf("fetch ipv4: %w", err)
	}
	return &components.IPv4Component{
		CaptureID:       captureID,
		PacketID:        packetID,
		Timestamp:       ts,
		ParsedOK:        parsedOK,
		ParseErr:        parseErr,
		Protocol:        protocol,
		SrcIP4:          parseAddr(src4),
		DstIP4:          parseAddr(dst4),
		IPv4IHL:         ipv4IHL,
		IPv4TOS:         ipv4TOS,
		IPv4TotalLen:    ipv4TotalLen,
		IPv4ID:          ipv4ID,
		IPv4Flags:       ipv4Flags,
		IPv4FragOffset:  ipv4Frag,
		IPv4TTL:         ipv4TTL,
		IPv4HdrChecksum: ipv4Checksum,
	}, nil
}

func (c *Client) fetchIPv4Options(ctx context.Context, captureID uuid.UUID, packetID uint64) (*components.IPv4OptionsComponent, error) {
	query := fmt.Sprintf("SELECT options_raw FROM %s WHERE capture_id = ? AND packet_id = ? LIMIT 1", c.ipv4OptionsTable())
	var raw string
	if err := c.conn.QueryRow(ctx, query, captureID, packetID).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("missing ipv4 options component for %s/%d", captureID, packetID)
		}
		return nil, fmt.Errorf("fetch ipv4 options: %w", err)
	}
	return &components.IPv4OptionsComponent{
		CaptureID:  captureID,
		PacketID:   packetID,
		OptionsRaw: []byte(raw),
	}, nil
}

func (c *Client) fetchIPv6(ctx context.Context, captureID uuid.UUID, packetID uint64) (*components.IPv6Component, error) {
	query := fmt.Sprintf(`SELECT ts, parsed_ok, parse_err, protocol, src_ip_v6, dst_ip_v6,
  ipv6_payload_len, ipv6_hop_limit, ipv6_flow_label, ipv6_traffic_class
FROM %s WHERE capture_id = ? AND packet_id = ? LIMIT 1`, c.ipv6Table())
	var ts time.Time
	var parsedOK uint8
	var parseErr string
	var protocol uint8
	var src6 string
	var dst6 string
	var ipv6PayloadLen uint16
	var ipv6HopLimit uint8
	var ipv6FlowLabel uint32
	var ipv6TrafficClass uint8
	if err := c.conn.QueryRow(ctx, query, captureID, packetID).Scan(
		&ts,
		&parsedOK,
		&parseErr,
		&protocol,
		&src6,
		&dst6,
		&ipv6PayloadLen,
		&ipv6HopLimit,
		&ipv6FlowLabel,
		&ipv6TrafficClass,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("missing ipv6 component for %s/%d", captureID, packetID)
		}
		return nil, fmt.Errorf("fetch ipv6: %w", err)
	}
	return &components.IPv6Component{
		CaptureID:        captureID,
		PacketID:         packetID,
		Timestamp:        ts,
		ParsedOK:         parsedOK,
		ParseErr:         parseErr,
		Protocol:         protocol,
		SrcIP6:           parseAddr(src6),
		DstIP6:           parseAddr(dst6),
		IPv6PayloadLen:   ipv6PayloadLen,
		IPv6HopLimit:     ipv6HopLimit,
		IPv6FlowLabel:    ipv6FlowLabel,
		IPv6TrafficClass: ipv6TrafficClass,
	}, nil
}

func (c *Client) fetchIPv6Ext(ctx context.Context, captureID uuid.UUID, packetID uint64) ([]components.ClickhouseMappedDecoder, error) {
	query := fmt.Sprintf("SELECT ext_index, ext_type, ext_raw FROM %s WHERE capture_id = ? AND packet_id = ? ORDER BY ext_index ASC", c.ipv6ExtTable())
	rows, err := c.conn.Query(ctx, query, captureID, packetID)
	if err != nil {
		return nil, fmt.Errorf("fetch ipv6 ext: %w", err)
	}
	defer rows.Close()

	var componentsList []components.ClickhouseMappedDecoder
	for rows.Next() {
		var index uint16
		var extType uint16
		var raw string
		if err := rows.Scan(&index, &extType, &raw); err != nil {
			return nil, fmt.Errorf("scan ipv6 ext: %w", err)
		}
		componentsList = append(componentsList, &components.IPv6ExtComponent{
			CaptureID: captureID,
			PacketID:  packetID,
			ExtIndex:  index,
			ExtType:   extType,
			ExtRaw:    []byte(raw),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ipv6 ext: %w", err)
	}
	if len(componentsList) == 0 {
		return nil, fmt.Errorf("missing ipv6 ext component for %s/%d", captureID, packetID)
	}
	return componentsList, nil
}

func (c *Client) fetchRawTail(ctx context.Context, captureID uuid.UUID, packetID uint64) (*components.RawTailComponent, error) {
	query := fmt.Sprintf("SELECT tail_offset, bytes FROM %s WHERE capture_id = ? AND packet_id = ? LIMIT 1", c.rawTailTable())
	var offset uint16
	var raw string
	if err := c.conn.QueryRow(ctx, query, captureID, packetID).Scan(&offset, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("missing raw tail for %s/%d", captureID, packetID)
		}
		return nil, fmt.Errorf("fetch raw tail: %w", err)
	}
	return &components.RawTailComponent{
		CaptureID:  captureID,
		PacketID:   packetID,
		TailOffset: offset,
		Bytes:      []byte(raw),
	}, nil
}

func parseAddr(value string) netip.Addr {
	if value == "" {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

func writePCAPHeader(w io.Writer, meta captureMetaRow) error {
	if len(meta.GlobalHeaderRaw) == 24 {
		_, err := w.Write(meta.GlobalHeaderRaw)
		return err
	}
	if meta.TimeResolution != "" && meta.TimeResolution != "us" {
		return fmt.Errorf("unsupported time resolution: %s", meta.TimeResolution)
	}

	order := byteOrder(meta.Endianness)
	var header [24]byte
	order.PutUint32(header[0:4], 0xA1B2C3D4)
	order.PutUint16(header[4:6], 2)
	order.PutUint16(header[6:8], 4)
	order.PutUint32(header[8:12], 0)
	order.PutUint32(header[12:16], 0)
	order.PutUint32(header[16:20], meta.Snaplen)
	order.PutUint32(header[20:24], meta.LinkType)
	_, err := w.Write(header[:])
	return err
}

func debugPacketDump(captureID uuid.UUID, packetID uint64, nucleus components.PacketNucleus, comps []components.ClickhouseMappedDecoder) {
	fmt.Fprintf(os.Stderr, "caphouse: debug packet capture_id=%s packet_id=%d\n", captureID, packetID)
	fmt.Fprintf(os.Stderr, "caphouse: nucleus incl_len=%d orig_len=%d tail_offset=%d frame_raw_len=%d frame_hash_len=%d\n",
		nucleus.InclLen, nucleus.OrigLen, nucleus.TailOffset, len(nucleus.FrameRaw), len(nucleus.FrameHash))
	fmt.Fprintf(os.Stderr, "caphouse: components=%d mask=%v\n", len(comps), nucleus.Components)
	for i, comp := range comps {
		switch c := comp.(type) {
		case *components.EthernetComponent:
			fmt.Fprintf(os.Stderr, "caphouse: component[%d]=ethernet src_mac_len=%d dst_mac_len=%d eth_type=%d eth_len=%d\n",
				i, len(c.SrcMAC), len(c.DstMAC), c.EtherType, c.Length)
		case *components.Dot1QComponent:
			fmt.Fprintf(os.Stderr, "caphouse: component[%d]=dot1q tag_index=%d vlan_id=%d eth_type=%d\n",
				i, c.TagIndex, c.VLANID, c.EtherType)
		case *components.LinuxSLLComponent:
			fmt.Fprintf(os.Stderr, "caphouse: component[%d]=linuxsll l2_len=%d l2_hdr_raw_len=%d\n",
				i, c.L2Len, len(c.L2HdrRaw))
		case *components.IPv4Component:
			fmt.Fprintf(os.Stderr, "caphouse: component[%d]=ipv4 src=%s dst=%s ihl=%d total_len=%d\n",
				i, c.SrcIP4, c.DstIP4, c.IPv4IHL, c.IPv4TotalLen)
		case *components.IPv4OptionsComponent:
			fmt.Fprintf(os.Stderr, "caphouse: component[%d]=ipv4_options len=%d\n",
				i, len(c.OptionsRaw))
		case *components.IPv6Component:
			fmt.Fprintf(os.Stderr, "caphouse: component[%d]=ipv6 src=%s dst=%s payload_len=%d\n",
				i, c.SrcIP6, c.DstIP6, c.IPv6PayloadLen)
		case *components.IPv6ExtComponent:
			fmt.Fprintf(os.Stderr, "caphouse: component[%d]=ipv6_ext index=%d type=%d len=%d\n",
				i, c.ExtIndex, c.ExtType, len(c.ExtRaw))
		case *components.RawTailComponent:
			fmt.Fprintf(os.Stderr, "caphouse: component[%d]=raw_tail offset=%d len=%d\n",
				i, c.TailOffset, len(c.Bytes))
		default:
			fmt.Fprintf(os.Stderr, "caphouse: component[%d]=%T\n", i, comp)
		}
	}
}

func writePacketRecord(w io.Writer, order binary.ByteOrder, ts time.Time, incl uint32, orig uint32, frame []byte) error {
	if incl == 0 {
		incl = uint32(len(frame))
	}
	if incl != uint32(len(frame)) {
		incl = uint32(len(frame))
	}
	if orig == 0 || orig < incl {
		orig = incl
	}

	sec := ts.Unix()
	usec := ts.Nanosecond() / 1000
	if sec < 0 {
		sec = 0
		usec = 0
	}
	if sec > math.MaxUint32 {
		sec = math.MaxUint32
	}

	var header [16]byte
	order.PutUint32(header[0:4], uint32(sec))
	order.PutUint32(header[4:8], uint32(usec))
	order.PutUint32(header[8:12], incl)
	order.PutUint32(header[12:16], orig)
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write packet header: %w", err)
	}
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("write packet frame: %w", err)
	}
	return nil
}

func byteOrder(endian string) binary.ByteOrder {
	if endian == "be" {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

var errUnsupportedMagic = errors.New("unsupported pcap magic")

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
	case 0xA1B23C4D, 0x4D3CB2A1:
		return CaptureMeta{}, errors.New("nanosecond pcap not supported")
	default:
		return CaptureMeta{}, errUnsupportedMagic
	}

	order := byteOrder(meta.Endianness)
	meta.Snaplen = order.Uint32(raw[16:20])
	meta.LinkType = order.Uint32(raw[20:24])
	meta.GlobalHeaderRaw = raw[:24]
	return meta, nil
}
