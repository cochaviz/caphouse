package caphouse

import (
	"bufio"
	"caphouse/components"
	"caphouse/query"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// CountPackets returns the deduplicated number of packets stored for the given session.
func (c *Client) CountPackets(ctx context.Context, sessionID uint64) (int64, error) {
	q := fmt.Sprintf("SELECT count() FROM %s FINAL WHERE session_id = ?", c.packetsTable())
	var n uint64
	if err := c.conn.QueryRow(ctx, q, sessionID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count packets: %w", err)
	}
	return int64(n), nil
}

// ExportCapture returns a reader that streams the complete session as a classic
// PCAP file. The caller must close the returned reader.
func (c *Client) ExportCapture(ctx context.Context, sessionID uint64) (io.ReadCloser, error) {
	return c.ExportCaptureWithProgress(ctx, sessionID, nil)
}

// ExportCaptureWithProgress is like ExportCapture but increments packetsWritten
// after each packet is written to the stream. packetsWritten may be nil.
func (c *Client) ExportCaptureWithProgress(ctx context.Context, sessionID uint64, packetsWritten *atomic.Int64) (io.ReadCloser, error) {
	meta, err := c.fetchCaptureMeta(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		if err := c.streamCapture(ctx, meta, sessionID, nil, pw, packetsWritten); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	return pr, nil
}

// ExportCaptureBytes reads the entire session into memory.
func (c *Client) ExportCaptureBytes(ctx context.Context, sessionID uint64) ([]byte, error) {
	rc, err := c.ExportCapture(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// streamCapture writes a PCAP stream to w. If ranges is nil, all packets for
// the session are streamed. If non-nil, only packets whose IDs fall within the
// given ranges are included; ranges must be pre-computed via toRanges.
func (c *Client) streamCapture(ctx context.Context, meta CaptureMeta, sessionID uint64, ranges []idRange, w io.Writer, packetsWritten *atomic.Int64) error {
	buf := bufio.NewWriterSize(w, 128*1024)
	if len(meta.GlobalHeaderRaw) != 24 {
		c.log.Warn("exporting session with synthetic PCAP header: original was pcapng or header was not preserved; output may differ from source",
			"session_id", sessionID)
	}
	if err := writePCAPHeader(buf, meta); err != nil {
		return err
	}
	if len(ranges) == 0 && ranges != nil {
		return buf.Flush()
	}

	type nucleusRow struct {
		packetID      uint32
		tsNs          int64
		incl          uint32
		truncExtra    uint32
		componentMask *big.Int
		frameRaw      string
		frameHash     string
	}

	order := byteOrder(meta.Endianness)
	batchSize := c.cfg.BatchSize

	flushBatch := func(batch []nucleusRow) error {
		if len(batch) == 0 {
			return nil
		}
		ids := make([]uint32, len(batch))
		for i, row := range batch {
			ids[i] = row.packetID
		}
		all, err := c.fetchComponentsForBatch(ctx, sessionID, ids)
		if err != nil {
			return err
		}
		for _, row := range batch {
			ts := time.Unix(0, row.tsNs)
			nucleus := components.PacketNucleus{
				SessionID:  sessionID,
				PacketID:   row.packetID,
				Timestamp:  ts,
				InclLen:    row.incl,
				OrigLen:    row.incl + row.truncExtra,
				Components: row.componentMask,
				FrameRaw:   []byte(row.frameRaw),
				FrameHash:  []byte(row.frameHash),
			}
			componentList, err := resolveComponents(nucleus, all)
			if err != nil {
				return err
			}
			frame, err := reconstructFrame(nucleus, componentList)
			if err != nil {
				c.debugPacketDump(sessionID, row.packetID, nucleus, componentList)
				return fmt.Errorf("reconstruct packet %d: %w", row.packetID, err)
			}
			if err := writePacketRecord(buf, order, meta.TimeResolution, ts, row.incl, row.incl+row.truncExtra, frame); err != nil {
				return err
			}
			if packetsWritten != nil {
				packetsWritten.Add(1)
			}
		}
		return nil
	}

	const selectCols = "SELECT packet_id, ts, incl_len, trunc_extra, components, frame_raw, frame_hash"

	if ranges == nil {
		// Stream all packets for the session.
		q := fmt.Sprintf("%s FROM %s FINAL WHERE session_id = ? ORDER BY packet_id ASC", selectCols, c.packetsTable())
		rows, err := c.conn.Query(ctx, q, sessionID)
		if err != nil {
			return fmt.Errorf("query packets: %w", err)
		}
		defer rows.Close()

		batch := make([]nucleusRow, 0, batchSize)
		for rows.Next() {
			componentMask := new(big.Int)
			var row nucleusRow
			row.componentMask = componentMask
			if err := rows.Scan(&row.packetID, &row.tsNs, &row.incl, &row.truncExtra, componentMask, &row.frameRaw, &row.frameHash); err != nil {
				return fmt.Errorf("scan packet: %w", err)
			}
			batch = append(batch, row)
			if len(batch) >= batchSize {
				if err := flushBatch(batch); err != nil {
					return err
				}
				batch = batch[:0]
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate packets: %w", err)
		}
		if err := flushBatch(batch); err != nil {
			return err
		}
	} else {
		// Stream only packets within the given ranges, chunked to keep queries small.
		for start := 0; start < len(ranges); start += maxRangesPerQuery {
			end := min(start+maxRangesPerQuery, len(ranges))
			chunk := ranges[start:end]
			whereClause, whereArgs := rangeArgs(sessionID, chunk)
			q := fmt.Sprintf("%s FROM %s FINAL WHERE session_id = ? AND %s ORDER BY packet_id ASC",
				selectCols, c.packetsTable(), whereClause)
			rows, err := c.conn.Query(ctx, q, whereArgs...)
			if err != nil {
				return fmt.Errorf("query filtered packets: %w", err)
			}
			batch := make([]nucleusRow, 0)
			for rows.Next() {
				componentMask := new(big.Int)
				var row nucleusRow
				row.componentMask = componentMask
				if err := rows.Scan(&row.packetID, &row.tsNs, &row.incl, &row.truncExtra, componentMask, &row.frameRaw, &row.frameHash); err != nil {
					rows.Close()
					return fmt.Errorf("scan filtered packet: %w", err)
				}
				batch = append(batch, row)
			}
			iterErr := rows.Err()
			rows.Close()
			if iterErr != nil {
				return fmt.Errorf("iterate filtered packets: %w", iterErr)
			}
			if err := flushBatch(batch); err != nil {
				return err
			}
		}
	}

	if err := buf.Flush(); err != nil {
		return fmt.Errorf("flush pcap stream: %w", err)
	}
	return nil
}

type idRange struct{ lo, hi uint32 }

// toRanges compresses packet IDs into the minimal set of contiguous ranges.
func toRanges(ids []uint32) []idRange {
	if len(ids) == 0 {
		return nil
	}
	sorted := make([]uint32, len(ids))
	copy(sorted, ids)
	slices.Sort(sorted)

	ranges := []idRange{{sorted[0], sorted[0]}}
	for _, id := range sorted[1:] {
		if id == ranges[len(ranges)-1].hi+1 {
			ranges[len(ranges)-1].hi = id
		} else {
			ranges = append(ranges, idRange{id, id})
		}
	}
	return ranges
}

// rangeArgs returns the WHERE clause fragment and args for a set of id ranges.
// args[0] is sessionID; subsequent pairs are (lo, hi) per range.
func rangeArgs(sessionID uint64, ranges []idRange) (string, []any) {
	var b strings.Builder
	args := make([]any, 1+2*len(ranges))
	args[0] = sessionID
	b.WriteByte('(')
	for i, r := range ranges {
		if i > 0 {
			b.WriteString(" OR ")
		}
		b.WriteString("packet_id BETWEEN ? AND ?")
		args[1+2*i] = r.lo
		args[2+2*i] = r.hi
	}
	b.WriteByte(')')
	return b.String(), args
}

// maxRangesPerQuery caps the BETWEEN clauses per query so that even degenerate
// (fully non-contiguous) ID sets stay within ClickHouse's max_query_size.
const maxRangesPerQuery = 1000

func (c *Client) fetchComponentBatch(
	ctx context.Context, sessionID uint64, packetIDs []uint32,
	ctor func() components.Component,
) (map[uint32][]components.Component, error) {
	m := make(map[uint32][]components.Component)
	ranges := toRanges(packetIDs)
	for len(ranges) > 0 {
		chunk := ranges
		if len(chunk) > maxRangesPerQuery {
			chunk = ranges[:maxRangesPerQuery]
		}
		ranges = ranges[len(chunk):]

		proto := ctor()
		whereClause, args := rangeArgs(sessionID, chunk)
		scanCols, err := proto.DataColumns("")
		if err != nil {
			return nil, fmt.Errorf("data columns for %s: %w", proto.Table(), err)
		}
		q := fmt.Sprintf(
			"SELECT %s FROM %s FINAL WHERE session_id = ? AND %s ORDER BY %s ASC",
			strings.Join(scanCols, ", "),
			c.tableRef(proto.Table()), whereClause, proto.FetchOrderBy(),
		)
		rows, err := c.conn.Query(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", proto.Table(), err)
		}
		for rows.Next() {
			item := ctor()
			pid, err := item.ScanRow(sessionID, rows)
			if err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan %s: %w", proto.Table(), err)
			}
			m[pid] = append(m[pid], item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return m, nil
}

type fetchResult struct {
	kind uint
	rows map[uint32][]components.Component
	err  error
}

func (c *Client) fetchComponentsForBatch(
	ctx context.Context, sessionID uint64, packetIDs []uint32,
) (map[uint]map[uint32][]components.Component, error) {
	n := len(components.ComponentFactories)
	results := make(chan fetchResult, n)
	for kind, ctor := range components.ComponentFactories {
		go func() {
			rows, err := c.fetchComponentBatch(ctx, sessionID, packetIDs, ctor)
			results <- fetchResult{kind, rows, err}
		}()
	}
	all := make(map[uint]map[uint32][]components.Component, n)
	for range n {
		r := <-results
		if r.err != nil {
			return nil, r.err
		}
		all[r.kind] = r.rows
	}
	return all, nil
}

// resolveComponents builds the component list for one packet from a pre-fetched batch map.
func resolveComponents(
	nucleus components.PacketNucleus,
	all map[uint]map[uint32][]components.Component,
) ([]components.Component, error) {
	var list []components.Component
	for _, kind := range components.KnownComponentKinds {
		if !components.ComponentHas(nucleus.Components, kind) {
			continue
		}
		rows := all[kind][nucleus.PacketID]
		if len(rows) == 0 {
			return nil, fmt.Errorf("missing component %d for session %d/%d", kind, nucleus.SessionID, nucleus.PacketID)
		}
		list = append(list, rows...)
	}
	return list, nil
}

func (c *Client) debugPacketDump(sessionID uint64, packetID uint32, nucleus components.PacketNucleus, comps []components.Component) {
	c.log.Debug("packet reconstruction failed",
		"session_id", sessionID,
		"packet_id", packetID,
		"incl_len", nucleus.InclLen,
		"orig_len", nucleus.OrigLen,
		"frame_raw_len", len(nucleus.FrameRaw),
		"frame_hash_len", len(nucleus.FrameHash),
		"component_count", len(comps),
		"mask", nucleus.Components,
	)
	for i, comp := range comps {
		switch x := comp.(type) {
		case *components.EthernetComponent:
			c.log.Debug("component", "index", i, "type", "ethernet",
				"src_mac_len", len(x.SrcMAC), "dst_mac_len", len(x.DstMAC),
				"eth_type", x.EtherType, "eth_len", x.Length)
		case *components.Dot1QComponent:
			c.log.Debug("component", "index", i, "type", "dot1q",
				"tag_index", x.TagIndex, "vlan_id", x.VLANID, "eth_type", x.EtherType)
		case *components.LinuxSLLComponent:
			c.log.Debug("component", "index", i, "type", "linuxsll",
				"l2_len", x.L2Len, "l2_hdr_raw_len", len(x.L2HdrRaw))
		case *components.IPv4Component:
			c.log.Debug("component", "index", i, "type", "ipv4",
				"src", x.SrcIP4, "dst", x.DstIP4,
				"ihl", x.IPv4IHL, "total_len", x.IPv4TotalLen,
				"options_len", len(x.OptionsRaw))
		case *components.IPv6Component:
			c.log.Debug("component", "index", i, "type", "ipv6",
				"src", x.SrcIP6, "dst", x.DstIP6, "payload_len", x.IPv6PayloadLen)
		case *components.IPv6ExtComponent:
			c.log.Debug("component", "index", i, "type", "ipv6_ext",
				"ext_index", x.ExtIndex, "ext_type", x.ExtType, "len", len(x.ExtRaw))
		default:
			c.log.Debug("component", "index", i, "type", fmt.Sprintf("%T", comp))
		}
	}
}

// timedPacketRef is a packet reference augmented with its absolute timestamp.
type timedPacketRef struct {
	sessionID uint64
	packetID  uint32
	absNs     int64
}

// fetchSortedPacketRefs queries packets whose timestamp falls in [from, to]
// (Unix nanoseconds), returning them sorted by (ts ASC, sessionID ASC, packetID ASC).
// When sessionIDs is nil or empty, all sessions are searched.
func (c *Client) fetchSortedPacketRefs(ctx context.Context, sessionIDs []uint64, from, to int64) ([]timedPacketRef, error) {
	var whereExtra string
	if len(sessionIDs) > 0 {
		whereExtra = " AND " + query.SessionInSQL(sessionIDs)
	}
	q := fmt.Sprintf(
		`SELECT session_id, packet_id, ts FROM %s FINAL
		 WHERE ts BETWEEN ? AND ?%s
		 ORDER BY ts ASC, session_id ASC, packet_id ASC`,
		c.packetsTable(), whereExtra,
	)
	rows, err := c.conn.Query(ctx, q, from, to)
	if err != nil {
		return nil, fmt.Errorf("fetch sorted packet refs: %w", err)
	}
	defer rows.Close()
	var refs []timedPacketRef
	for rows.Next() {
		var r timedPacketRef
		if err := rows.Scan(&r.sessionID, &r.packetID, &r.absNs); err != nil {
			return nil, fmt.Errorf("scan timed packet ref: %w", err)
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}

// reconstructedPkt holds a single reconstructed packet ready for export.
type reconstructedPkt struct {
	ts    time.Time
	incl  uint32
	orig  uint32
	frame []byte
}

// fetchReconstructedPackets fetches nucleus data and all components for the
// given packet IDs in sessionID, then returns reconstructed packets keyed by packetID.
func (c *Client) fetchReconstructedPackets(ctx context.Context, sessionID uint64, packetIDs []uint32) (map[uint32]reconstructedPkt, error) {
	if len(packetIDs) == 0 {
		return nil, nil
	}
	ranges := toRanges(packetIDs)
	const selectCols = "SELECT packet_id, ts, incl_len, trunc_extra, components, frame_raw, frame_hash"
	type nucleusRow struct {
		packetID      uint32
		tsNs          int64
		incl          uint32
		truncExtra    uint32
		componentMask *big.Int
		frameRaw      string
		frameHash     string
	}
	var nuclei []nucleusRow
	for start := 0; start < len(ranges); start += maxRangesPerQuery {
		end := min(start+maxRangesPerQuery, len(ranges))
		chunk := ranges[start:end]
		whereClause, whereArgs := rangeArgs(sessionID, chunk)
		q := fmt.Sprintf("%s FROM %s FINAL WHERE session_id = ? AND %s ORDER BY packet_id ASC",
			selectCols, c.packetsTable(), whereClause)
		rows, err := c.conn.Query(ctx, q, whereArgs...)
		if err != nil {
			return nil, fmt.Errorf("fetch nuclei for session %d: %w", sessionID, err)
		}
		for rows.Next() {
			componentMask := new(big.Int)
			var row nucleusRow
			row.componentMask = componentMask
			if err := rows.Scan(&row.packetID, &row.tsNs, &row.incl, &row.truncExtra, componentMask, &row.frameRaw, &row.frameHash); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan nucleus: %w", err)
			}
			nuclei = append(nuclei, row)
		}
		iterErr := rows.Err()
		rows.Close()
		if iterErr != nil {
			return nil, fmt.Errorf("iterate nuclei: %w", iterErr)
		}
	}

	all, err := c.fetchComponentsForBatch(ctx, sessionID, packetIDs)
	if err != nil {
		return nil, err
	}

	result := make(map[uint32]reconstructedPkt, len(nuclei))
	for _, row := range nuclei {
		ts := time.Unix(0, row.tsNs)
		nucleus := components.PacketNucleus{
			SessionID:  sessionID,
			PacketID:   row.packetID,
			Timestamp:  ts,
			InclLen:    row.incl,
			OrigLen:    row.incl + row.truncExtra,
			Components: row.componentMask,
			FrameRaw:   []byte(row.frameRaw),
			FrameHash:  []byte(row.frameHash),
		}
		componentList, err := resolveComponents(nucleus, all)
		if err != nil {
			return nil, err
		}
		frame, err := reconstructFrame(nucleus, componentList)
		if err != nil {
			c.debugPacketDump(sessionID, row.packetID, nucleus, componentList)
			return nil, fmt.Errorf("reconstruct packet %d in session %d: %w", row.packetID, sessionID, err)
		}
		result[row.packetID] = reconstructedPkt{
			ts:    ts,
			incl:  row.incl,
			orig:  row.incl + row.truncExtra,
			frame: frame,
		}
	}
	return result, nil
}

// ExportAllCapturesFiltered finds all sessions with packets in the given time
// window and exports them as a single merged PCAP file sorted by absolute
// packet time. Ties are broken by session ID, then by packet ID.
// f is an optional query filter; an empty f.Clause selects all packets.
//
// packetsWritten is incremented after each packet (may be nil).
func (c *Client) ExportAllCapturesFiltered(ctx context.Context, from, to time.Time, f query.Query, packetsWritten *atomic.Int64) (rc io.ReadCloser, total int64, err error) {
	refs, err := c.fetchSortedPacketRefs(ctx, nil, from.UnixNano(), to.UnixNano())
	if err != nil {
		return nil, 0, err
	}

	if f.Clause != "" {
		filterRefs, err := c.QueryPackets(ctx, nil, f)
		if err != nil {
			return nil, 0, fmt.Errorf("export filter: %w", err)
		}
		type key struct {
			sessionID uint64
			packetID  uint32
		}
		allowed := make(map[key]struct{}, len(filterRefs))
		for _, r := range filterRefs {
			allowed[key{r.SessionID, r.PacketID}] = struct{}{}
		}
		filtered := refs[:0]
		for _, r := range refs {
			if _, ok := allowed[key{r.sessionID, r.packetID}]; ok {
				filtered = append(filtered, r)
			}
		}
		refs = filtered
	}

	captureMap, err := c.fetchCaptureMetaMap(ctx, uniqueSessionIDs(refs))
	if err != nil {
		return nil, 0, err
	}

	pr, pw := io.Pipe()
	go func() {
		if err := c.streamMergedCaptures(ctx, refs, captureMap, pw, packetsWritten); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	return pr, int64(len(refs)), nil
}

// uniqueSessionIDs returns the deduplicated set of session IDs referenced by refs.
func uniqueSessionIDs(refs []timedPacketRef) []uint64 {
	seen := make(map[uint64]bool, len(refs))
	var out []uint64
	for _, r := range refs {
		if !seen[r.sessionID] {
			seen[r.sessionID] = true
			out = append(out, r.sessionID)
		}
	}
	return out
}

// fetchCaptureMetaMap fetches CaptureMeta for each of the given session IDs
// and returns them as a map keyed by session ID.
func (c *Client) fetchCaptureMetaMap(ctx context.Context, sessionIDs []uint64) (map[uint64]CaptureMeta, error) {
	if len(sessionIDs) == 0 {
		return nil, nil
	}
	cols := strings.Join(CaptureMeta{}.ScanColumns(), ", ")
	q := fmt.Sprintf(
		"SELECT %s FROM %s FINAL WHERE %s",
		cols, c.capturesTable(), query.SessionInSQL(sessionIDs),
	)
	rows, err := c.conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("fetch capture meta map: %w", err)
	}
	defer rows.Close()
	result := make(map[uint64]CaptureMeta, len(sessionIDs))
	for rows.Next() {
		m, err := scanCaptureMeta(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan capture meta: %w", err)
		}
		result[m.SessionID] = m
	}
	return result, rows.Err()
}

// streamMergedCaptures writes all packets described by refs (in their given
// order) to w as a single PCAP stream with a synthetic LE/µs header.
func (c *Client) streamMergedCaptures(
	ctx context.Context,
	refs []timedPacketRef,
	captureMap map[uint64]CaptureMeta,
	w io.Writer,
	packetsWritten *atomic.Int64,
) error {
	var linkType, snaplen uint32
	linkType = 1
	snaplen = 65535
	seenLinkTypes := map[uint32]bool{}
	for _, ref := range refs {
		if m, ok := captureMap[ref.sessionID]; ok {
			seenLinkTypes[m.LinkType] = true
			if m.Snaplen > snaplen {
				snaplen = m.Snaplen
			}
		}
	}
	if len(seenLinkTypes) == 1 {
		for lt := range seenLinkTypes {
			linkType = lt
		}
	} else if len(seenLinkTypes) > 1 {
		c.log.Warn("merged export contains sessions with different link types; using first encountered link type",
			"link_types", seenLinkTypes)
		if m, ok := captureMap[refs[0].sessionID]; ok {
			linkType = m.LinkType
		}
	}

	syntheticMeta := CaptureMeta{
		Endianness:     "le",
		TimeResolution: "us",
		Snaplen:        snaplen,
		LinkType:       linkType,
	}

	buf := bufio.NewWriterSize(w, 128*1024)
	c.log.Warn("exporting merged capture with synthetic PCAP header",
		"session_count", len(captureMap),
		"packet_count", len(refs))
	if err := writePCAPHeader(buf, syntheticMeta); err != nil {
		return err
	}

	if len(refs) == 0 {
		return buf.Flush()
	}

	order := byteOrder(syntheticMeta.Endianness)

	// Group packet IDs by sessionID for batch fetching.
	packetsBySession := make(map[uint64][]uint32)
	for _, ref := range refs {
		packetsBySession[ref.sessionID] = append(packetsBySession[ref.sessionID], ref.packetID)
	}

	// Fetch and reconstruct all packets for each session.
	allPackets := make(map[uint64]map[uint32]reconstructedPkt, len(packetsBySession))
	for sessionID, ids := range packetsBySession {
		pkts, err := c.fetchReconstructedPackets(ctx, sessionID, ids)
		if err != nil {
			return err
		}
		allPackets[sessionID] = pkts
	}

	// Write packets in the globally-sorted ref order.
	for _, ref := range refs {
		pkt, ok := allPackets[ref.sessionID][ref.packetID]
		if !ok {
			return fmt.Errorf("packet %d from session %d not reconstructed", ref.packetID, ref.sessionID)
		}
		if err := writePacketRecord(buf, order, syntheticMeta.TimeResolution, pkt.ts, pkt.incl, pkt.orig, pkt.frame); err != nil {
			return err
		}
		if packetsWritten != nil {
			packetsWritten.Add(1)
		}
	}
	return buf.Flush()
}

// writePCAPHeader writes a classic PCAP global header to w. If
// meta.GlobalHeaderRaw is a valid 24-byte header it is written byte-for-byte;
// otherwise a synthetic LE/µs header is generated from meta fields.
func writePCAPHeader(w io.Writer, meta CaptureMeta) error {
	if len(meta.GlobalHeaderRaw) == 24 {
		_, err := w.Write(meta.GlobalHeaderRaw)
		return err
	}
	endian := meta.Endianness
	if endian == "" {
		endian = "le"
	}
	order := byteOrder(endian)
	var header [24]byte
	magic := uint32(0xA1B2C3D4)
	if meta.TimeResolution == "ns" {
		magic = 0xA1B23C4D
	}
	order.PutUint32(header[0:4], magic)
	order.PutUint16(header[4:6], 2)
	order.PutUint16(header[6:8], 4)
	order.PutUint32(header[8:12], 0)
	order.PutUint32(header[12:16], 0)
	order.PutUint32(header[16:20], meta.Snaplen)
	order.PutUint32(header[20:24], meta.LinkType)
	_, err := w.Write(header[:])
	return err
}

// writePacketRecord writes a single classic PCAP packet record to w.
func writePacketRecord(w io.Writer, order binary.ByteOrder, timeRes string, ts time.Time, incl uint32, orig uint32, frame []byte) error {
	if incl != uint32(len(frame)) {
		incl = uint32(len(frame))
	}
	if orig == 0 || orig < incl {
		orig = incl
	}

	sec := ts.Unix()
	var frac int
	if timeRes == "ns" {
		frac = ts.Nanosecond()
	} else {
		frac = ts.Nanosecond() / 1000
	}
	if sec < 0 {
		sec = 0
		frac = 0
	}
	if sec > math.MaxUint32 {
		sec = math.MaxUint32
	}

	var header [16]byte
	order.PutUint32(header[0:4], uint32(sec))
	order.PutUint32(header[4:8], uint32(frac))
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
