package caphouse

import (
	"bufio"
	"caphouse/components"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
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

// captureComponents holds component rows for a batch of packets, keyed by packet_id.
type captureComponents struct {
	ethernet    map[uint64]*components.EthernetComponent
	dot1q       map[uint64][]*components.Dot1QComponent
	linuxSLL    map[uint64]*components.LinuxSLLComponent
	ipv4        map[uint64]*components.IPv4Component
	ipv4Options map[uint64]*components.IPv4OptionsComponent
	ipv6        map[uint64]*components.IPv6Component
	ipv6Ext     map[uint64][]*components.IPv6ExtComponent
	rawTail     map[uint64]*components.RawTailComponent
}

// CountPackets returns the number of packets stored for the given capture.
// The count is an estimate (no FINAL deduplication) and is suitable for
// driving a progress bar.
func (c *Client) CountPackets(ctx context.Context, captureID uuid.UUID) (int64, error) {
	query := fmt.Sprintf("SELECT count() FROM %s WHERE capture_id = ?", c.packetsTable())
	var n uint64
	if err := c.conn.QueryRow(ctx, query, captureID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count packets: %w", err)
	}
	return int64(n), nil
}

// ExportCapture returns a reader that streams a classic PCAP file.
func (c *Client) ExportCapture(ctx context.Context, captureID uuid.UUID) (io.ReadCloser, error) {
	return c.ExportCaptureWithProgress(ctx, captureID, nil)
}

// ExportCaptureWithProgress is like ExportCapture but increments packetsWritten
// after each packet is written to the stream. packetsWritten may be nil.
func (c *Client) ExportCaptureWithProgress(ctx context.Context, captureID uuid.UUID, packetsWritten *atomic.Int64) (io.ReadCloser, error) {
	meta, err := c.fetchCaptureMeta(ctx, captureID)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		if err := c.streamCapture(ctx, meta, captureID, pw, packetsWritten); err != nil {
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

func (c *Client) streamCapture(ctx context.Context, meta captureMetaRow, captureID uuid.UUID, w io.Writer, packetsWritten *atomic.Int64) error {
	buf := bufio.NewWriterSize(w, 128*1024)
	if err := writePCAPHeader(buf, meta); err != nil {
		return err
	}

	query := fmt.Sprintf("SELECT packet_id, ts, incl_len, orig_len, components, tail_offset, frame_raw, frame_hash FROM %s FINAL WHERE capture_id = ? ORDER BY packet_id ASC", c.packetsTable())
	rows, err := c.conn.Query(ctx, query, captureID)
	if err != nil {
		return fmt.Errorf("query packets: %w", err)
	}
	defer rows.Close()

	type nucleusRow struct {
		packetID      uint64
		ts            time.Time
		incl, orig    uint32
		componentMask *big.Int
		tailOffset    uint16
		frameRaw      string
		frameHash     string
	}

	order := byteOrder(meta.Endianness)
	batchSize := c.cfg.BatchSize
	batch := make([]nucleusRow, 0, batchSize)

	flushBatch := func() error {
		if len(batch) == 0 {
			return nil
		}
		packetIDs := make([]uint64, len(batch))
		for i, row := range batch {
			packetIDs[i] = row.packetID
		}

		comps, err := c.fetchComponentsForBatch(ctx, captureID, packetIDs)
		if err != nil {
			return err
		}

		for _, row := range batch {
			nucleus := components.PacketNucleus{
				CaptureID:  captureID,
				PacketID:   row.packetID,
				Timestamp:  row.ts,
				InclLen:    row.incl,
				OrigLen:    row.orig,
				Components: row.componentMask,
				TailOffset: row.tailOffset,
				FrameRaw:   []byte(row.frameRaw),
				FrameHash:  []byte(row.frameHash),
			}
			componentList, err := resolveComponents(nucleus, comps)
			if err != nil {
				return err
			}
			frame, err := ReconstructFrame(nucleus, componentList)
			if err != nil {
				if c.cfg.Debug {
					debugPacketDump(captureID, row.packetID, nucleus, componentList)
				}
				return fmt.Errorf("reconstruct packet %d: %w", row.packetID, err)
			}
			if err := writePacketRecord(buf, order, row.ts, row.incl, row.orig, frame); err != nil {
				return err
			}
			if packetsWritten != nil {
				packetsWritten.Add(1)
			}
		}

		batch = batch[:0]
		return nil
	}

	for rows.Next() {
		componentMask := new(big.Int)
		var row nucleusRow
		row.componentMask = componentMask
		if err := rows.Scan(&row.packetID, &row.ts, &row.incl, &row.orig, componentMask, &row.tailOffset, &row.frameRaw, &row.frameHash); err != nil {
			return fmt.Errorf("scan packet: %w", err)
		}
		batch = append(batch, row)
		if len(batch) >= batchSize {
			if err := flushBatch(); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate packets: %w", err)
	}
	if err := flushBatch(); err != nil {
		return err
	}
	if err := buf.Flush(); err != nil {
		return fmt.Errorf("flush pcap stream: %w", err)
	}
	return nil
}

// resolveComponents builds the component list for one packet from a pre-fetched batch map.
func resolveComponents(nucleus components.PacketNucleus, comps captureComponents) ([]components.ClickhouseMappedDecoder, error) {
	captureID := nucleus.CaptureID
	packetID := nucleus.PacketID
	var list []components.ClickhouseMappedDecoder

	if components.ComponentHas(nucleus.Components, components.ComponentEthernet) {
		eth, ok := comps.ethernet[packetID]
		if !ok {
			return nil, fmt.Errorf("missing ethernet component for %s/%d", captureID, packetID)
		}
		list = append(list, eth)
	}
	if components.ComponentHas(nucleus.Components, components.ComponentDot1Q) {
		tags, ok := comps.dot1q[packetID]
		if !ok || len(tags) == 0 {
			return nil, fmt.Errorf("missing dot1q component for %s/%d", captureID, packetID)
		}
		for _, tag := range tags {
			list = append(list, tag)
		}
	}
	if components.ComponentHas(nucleus.Components, components.ComponentLinuxSLL) {
		sll, ok := comps.linuxSLL[packetID]
		if !ok {
			return nil, fmt.Errorf("missing linux sll component for %s/%d", captureID, packetID)
		}
		list = append(list, sll)
	}
	if components.ComponentHas(nucleus.Components, components.ComponentIPv4) {
		ipv4, ok := comps.ipv4[packetID]
		if !ok {
			return nil, fmt.Errorf("missing ipv4 component for %s/%d", captureID, packetID)
		}
		list = append(list, ipv4)
	}
	if components.ComponentHas(nucleus.Components, components.ComponentIPv4Options) {
		options, ok := comps.ipv4Options[packetID]
		if !ok {
			return nil, fmt.Errorf("missing ipv4 options component for %s/%d", captureID, packetID)
		}
		list = append(list, options)
	}
	if components.ComponentHas(nucleus.Components, components.ComponentIPv6) {
		ipv6, ok := comps.ipv6[packetID]
		if !ok {
			return nil, fmt.Errorf("missing ipv6 component for %s/%d", captureID, packetID)
		}
		list = append(list, ipv6)
	}
	if components.ComponentHas(nucleus.Components, components.ComponentIPv6Ext) {
		exts, ok := comps.ipv6Ext[packetID]
		if !ok || len(exts) == 0 {
			return nil, fmt.Errorf("missing ipv6 ext component for %s/%d", captureID, packetID)
		}
		for _, ext := range exts {
			list = append(list, ext)
		}
	}
	if components.ComponentHas(nucleus.Components, components.ComponentRawTail) {
		tail, ok := comps.rawTail[packetID]
		if !ok {
			return nil, fmt.Errorf("missing raw tail for %s/%d", captureID, packetID)
		}
		list = append(list, tail)
	}
	return list, nil
}

// batchArgs returns the IN-clause placeholder and args slice for a batch query.
// args[0] is captureID; args[1:] are the packet IDs.
func batchArgs(captureID uuid.UUID, packetIDs []uint64) (string, []any) {
	var b strings.Builder
	b.WriteByte('(')
	for i := range packetIDs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('?')
	}
	b.WriteByte(')')
	args := make([]any, 1+len(packetIDs))
	args[0] = captureID
	for i, pid := range packetIDs {
		args[i+1] = pid
	}
	return b.String(), args
}

func (c *Client) fetchComponentsForBatch(ctx context.Context, captureID uuid.UUID, packetIDs []uint64) (captureComponents, error) {
	var cc captureComponents
	var err error

	if cc.ethernet, err = c.fetchEthernetBatch(ctx, captureID, packetIDs); err != nil {
		return captureComponents{}, err
	}
	if cc.dot1q, err = c.fetchDot1QBatch(ctx, captureID, packetIDs); err != nil {
		return captureComponents{}, err
	}
	if cc.linuxSLL, err = c.fetchLinuxSLLBatch(ctx, captureID, packetIDs); err != nil {
		return captureComponents{}, err
	}
	if cc.ipv4, err = c.fetchIPv4Batch(ctx, captureID, packetIDs); err != nil {
		return captureComponents{}, err
	}
	if cc.ipv4Options, err = c.fetchIPv4OptionsBatch(ctx, captureID, packetIDs); err != nil {
		return captureComponents{}, err
	}
	if cc.ipv6, err = c.fetchIPv6Batch(ctx, captureID, packetIDs); err != nil {
		return captureComponents{}, err
	}
	if cc.ipv6Ext, err = c.fetchIPv6ExtBatch(ctx, captureID, packetIDs); err != nil {
		return captureComponents{}, err
	}
	if cc.rawTail, err = c.fetchRawTailBatch(ctx, captureID, packetIDs); err != nil {
		return captureComponents{}, err
	}
	return cc, nil
}

func (c *Client) fetchEthernetBatch(ctx context.Context, captureID uuid.UUID, packetIDs []uint64) (map[uint64]*components.EthernetComponent, error) {
	inClause, args := batchArgs(captureID, packetIDs)
	query := fmt.Sprintf("SELECT packet_id, src_mac, dst_mac, eth_type, eth_len FROM %s WHERE capture_id = ? AND packet_id IN %s", c.ethernetTable(), inClause)
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch ethernet: %w", err)
	}
	defer rows.Close()

	m := make(map[uint64]*components.EthernetComponent)
	for rows.Next() {
		var packetID uint64
		var src, dst string
		var ethType, ethLen uint16
		if err := rows.Scan(&packetID, &src, &dst, &ethType, &ethLen); err != nil {
			return nil, fmt.Errorf("scan ethernet: %w", err)
		}
		m[packetID] = &components.EthernetComponent{
			CaptureID: captureID,
			PacketID:  packetID,
			SrcMAC:    []byte(src),
			DstMAC:    []byte(dst),
			EtherType: ethType,
			Length:    ethLen,
		}
	}
	return m, rows.Err()
}

func (c *Client) fetchDot1QBatch(ctx context.Context, captureID uuid.UUID, packetIDs []uint64) (map[uint64][]*components.Dot1QComponent, error) {
	inClause, args := batchArgs(captureID, packetIDs)
	query := fmt.Sprintf("SELECT packet_id, tag_index, priority, drop_eligible, vlan_id, eth_type FROM %s FINAL WHERE capture_id = ? AND packet_id IN %s ORDER BY packet_id, tag_index ASC", c.dot1qTable(), inClause)
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch dot1q: %w", err)
	}
	defer rows.Close()

	m := make(map[uint64][]*components.Dot1QComponent)
	for rows.Next() {
		var packetID uint64
		var index uint16
		var priority, dropEligible uint8
		var vlanID, ethType uint16
		if err := rows.Scan(&packetID, &index, &priority, &dropEligible, &vlanID, &ethType); err != nil {
			return nil, fmt.Errorf("scan dot1q: %w", err)
		}
		m[packetID] = append(m[packetID], &components.Dot1QComponent{
			CaptureID:    captureID,
			PacketID:     packetID,
			TagIndex:     index,
			Priority:     priority,
			VLANID:       vlanID,
			EtherType:    ethType,
			DropEligible: dropEligible,
		})
	}
	return m, rows.Err()
}

func (c *Client) fetchLinuxSLLBatch(ctx context.Context, captureID uuid.UUID, packetIDs []uint64) (map[uint64]*components.LinuxSLLComponent, error) {
	inClause, args := batchArgs(captureID, packetIDs)
	query := fmt.Sprintf("SELECT packet_id, l2_len, l2_hdr_raw FROM %s WHERE capture_id = ? AND packet_id IN %s", c.linuxSLLTable(), inClause)
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch linux sll: %w", err)
	}
	defer rows.Close()

	m := make(map[uint64]*components.LinuxSLLComponent)
	for rows.Next() {
		var packetID uint64
		var l2Len uint16
		var raw string
		if err := rows.Scan(&packetID, &l2Len, &raw); err != nil {
			return nil, fmt.Errorf("scan linux sll: %w", err)
		}
		m[packetID] = &components.LinuxSLLComponent{
			CaptureID: captureID,
			PacketID:  packetID,
			L2Len:     l2Len,
			L2HdrRaw:  []byte(raw),
		}
	}
	return m, rows.Err()
}

func (c *Client) fetchIPv4Batch(ctx context.Context, captureID uuid.UUID, packetIDs []uint64) (map[uint64]*components.IPv4Component, error) {
	inClause, args := batchArgs(captureID, packetIDs)
	query := fmt.Sprintf(`SELECT packet_id, ts, parsed_ok, parse_err, protocol, src_ip_v4, dst_ip_v4,
  ipv4_ihl, ipv4_tos, ipv4_total_len, ipv4_id, ipv4_flags, ipv4_frag_offset, ipv4_ttl, ipv4_hdr_checksum
FROM %s WHERE capture_id = ? AND packet_id IN %s`, c.ipv4Table(), inClause)
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch ipv4: %w", err)
	}
	defer rows.Close()

	m := make(map[uint64]*components.IPv4Component)
	for rows.Next() {
		var packetID uint64
		var ts time.Time
		var parsedOK uint8
		var parseErr string
		var protocol uint8
		var src4, dst4 string
		var ihl, tos, ttl uint8
		var totalLen, id, frag, checksum uint16
		var flags uint8
		if err := rows.Scan(&packetID, &ts, &parsedOK, &parseErr, &protocol, &src4, &dst4,
			&ihl, &tos, &totalLen, &id, &flags, &frag, &ttl, &checksum); err != nil {
			return nil, fmt.Errorf("scan ipv4: %w", err)
		}
		m[packetID] = &components.IPv4Component{
			CaptureID:       captureID,
			PacketID:        packetID,
			Timestamp:       ts,
			ParsedOK:        parsedOK,
			ParseErr:        parseErr,
			Protocol:        protocol,
			SrcIP4:          parseAddr(src4),
			DstIP4:          parseAddr(dst4),
			IPv4IHL:         ihl,
			IPv4TOS:         tos,
			IPv4TotalLen:    totalLen,
			IPv4ID:          id,
			IPv4Flags:       flags,
			IPv4FragOffset:  frag,
			IPv4TTL:         ttl,
			IPv4HdrChecksum: checksum,
		}
	}
	return m, rows.Err()
}

func (c *Client) fetchIPv4OptionsBatch(ctx context.Context, captureID uuid.UUID, packetIDs []uint64) (map[uint64]*components.IPv4OptionsComponent, error) {
	inClause, args := batchArgs(captureID, packetIDs)
	query := fmt.Sprintf("SELECT packet_id, options_raw FROM %s WHERE capture_id = ? AND packet_id IN %s", c.ipv4OptionsTable(), inClause)
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch ipv4 options: %w", err)
	}
	defer rows.Close()

	m := make(map[uint64]*components.IPv4OptionsComponent)
	for rows.Next() {
		var packetID uint64
		var raw string
		if err := rows.Scan(&packetID, &raw); err != nil {
			return nil, fmt.Errorf("scan ipv4 options: %w", err)
		}
		m[packetID] = &components.IPv4OptionsComponent{
			CaptureID:  captureID,
			PacketID:   packetID,
			OptionsRaw: []byte(raw),
		}
	}
	return m, rows.Err()
}

func (c *Client) fetchIPv6Batch(ctx context.Context, captureID uuid.UUID, packetIDs []uint64) (map[uint64]*components.IPv6Component, error) {
	inClause, args := batchArgs(captureID, packetIDs)
	query := fmt.Sprintf(`SELECT packet_id, ts, parsed_ok, parse_err, protocol, src_ip_v6, dst_ip_v6,
  ipv6_payload_len, ipv6_hop_limit, ipv6_flow_label, ipv6_traffic_class
FROM %s WHERE capture_id = ? AND packet_id IN %s`, c.ipv6Table(), inClause)
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch ipv6: %w", err)
	}
	defer rows.Close()

	m := make(map[uint64]*components.IPv6Component)
	for rows.Next() {
		var packetID uint64
		var ts time.Time
		var parsedOK uint8
		var parseErr string
		var protocol uint8
		var src6, dst6 string
		var payloadLen uint16
		var hopLimit, trafficClass uint8
		var flowLabel uint32
		if err := rows.Scan(&packetID, &ts, &parsedOK, &parseErr, &protocol, &src6, &dst6,
			&payloadLen, &hopLimit, &flowLabel, &trafficClass); err != nil {
			return nil, fmt.Errorf("scan ipv6: %w", err)
		}
		m[packetID] = &components.IPv6Component{
			CaptureID:        captureID,
			PacketID:         packetID,
			Timestamp:        ts,
			ParsedOK:         parsedOK,
			ParseErr:         parseErr,
			Protocol:         protocol,
			SrcIP6:           parseAddr(src6),
			DstIP6:           parseAddr(dst6),
			IPv6PayloadLen:   payloadLen,
			IPv6HopLimit:     hopLimit,
			IPv6FlowLabel:    flowLabel,
			IPv6TrafficClass: trafficClass,
		}
	}
	return m, rows.Err()
}

func (c *Client) fetchIPv6ExtBatch(ctx context.Context, captureID uuid.UUID, packetIDs []uint64) (map[uint64][]*components.IPv6ExtComponent, error) {
	inClause, args := batchArgs(captureID, packetIDs)
	query := fmt.Sprintf("SELECT packet_id, ext_index, ext_type, ext_raw FROM %s FINAL WHERE capture_id = ? AND packet_id IN %s ORDER BY packet_id, ext_index ASC", c.ipv6ExtTable(), inClause)
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch ipv6 ext: %w", err)
	}
	defer rows.Close()

	m := make(map[uint64][]*components.IPv6ExtComponent)
	for rows.Next() {
		var packetID uint64
		var index, extType uint16
		var raw string
		if err := rows.Scan(&packetID, &index, &extType, &raw); err != nil {
			return nil, fmt.Errorf("scan ipv6 ext: %w", err)
		}
		m[packetID] = append(m[packetID], &components.IPv6ExtComponent{
			CaptureID: captureID,
			PacketID:  packetID,
			ExtIndex:  index,
			ExtType:   extType,
			ExtRaw:    []byte(raw),
		})
	}
	return m, rows.Err()
}

func (c *Client) fetchRawTailBatch(ctx context.Context, captureID uuid.UUID, packetIDs []uint64) (map[uint64]*components.RawTailComponent, error) {
	inClause, args := batchArgs(captureID, packetIDs)
	query := fmt.Sprintf("SELECT packet_id, tail_offset, bytes FROM %s WHERE capture_id = ? AND packet_id IN %s", c.rawTailTable(), inClause)
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch raw tail: %w", err)
	}
	defer rows.Close()

	m := make(map[uint64]*components.RawTailComponent)
	for rows.Next() {
		var packetID uint64
		var offset uint16
		var raw string
		if err := rows.Scan(&packetID, &offset, &raw); err != nil {
			return nil, fmt.Errorf("scan raw tail: %w", err)
		}
		m[packetID] = &components.RawTailComponent{
			CaptureID:  captureID,
			PacketID:   packetID,
			TailOffset: offset,
			Bytes:      []byte(raw),
		}
	}
	return m, rows.Err()
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
