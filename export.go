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
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// CountPackets returns the deduplicated number of packets stored for the given capture.
func (c *Client) CountPackets(ctx context.Context, captureID uuid.UUID) (int64, error) {
	query := fmt.Sprintf("SELECT count() FROM %s FINAL WHERE capture_id = ?", c.packetsTable())
	var n uint64
	if err := c.conn.QueryRow(ctx, query, captureID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count packets: %w", err)
	}
	return int64(n), nil
}

// ExportCapture returns a reader that streams the complete capture as a classic
// PCAP file. The caller must close the returned reader. For progress tracking
// use ExportCaptureWithProgress.
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
		if err := c.streamCapture(ctx, meta, captureID, nil, pw, packetsWritten); err != nil {
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

// streamCapture writes a PCAP stream to w. If ranges is nil, all packets for
// the capture are streamed. If non-nil, only packets whose IDs fall within the
// given ranges are included; ranges must be pre-computed via toRanges.
func (c *Client) streamCapture(ctx context.Context, meta CaptureMeta, captureID uuid.UUID, ranges []idRange, w io.Writer, packetsWritten *atomic.Int64) error {
	buf := bufio.NewWriterSize(w, 128*1024)
	if len(meta.GlobalHeaderRaw) != 24 {
		c.log.Warn("exporting capture with synthetic PCAP header: original was pcapng or header was not preserved; output may differ from source",
			"capture_id", captureID)
	}
	if err := writePCAPHeader(buf, meta); err != nil {
		return err
	}
	if len(ranges) == 0 && ranges != nil {
		return buf.Flush()
	}

	type nucleusRow struct {
		packetID      uint64
		tsOffsetNs    uint64
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
		ids := make([]uint64, len(batch))
		for i, row := range batch {
			ids[i] = row.packetID
		}
		all, err := c.fetchComponentsForBatch(ctx, captureID, ids)
		if err != nil {
			return err
		}
		for _, row := range batch {
			ts := meta.CreatedAt.Add(time.Duration(row.tsOffsetNs))
			nucleus := components.PacketNucleus{
				CaptureID:  captureID,
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
				c.debugPacketDump(captureID, row.packetID, nucleus, componentList)
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
		// Stream all packets for the capture.
		query := fmt.Sprintf("%s FROM %s FINAL WHERE capture_id = ? ORDER BY packet_id ASC", selectCols, c.packetsTable())
		rows, err := c.conn.Query(ctx, query, captureID)
		if err != nil {
			return fmt.Errorf("query packets: %w", err)
		}
		defer rows.Close()

		batch := make([]nucleusRow, 0, batchSize)
		for rows.Next() {
			componentMask := new(big.Int)
			var row nucleusRow
			row.componentMask = componentMask
			if err := rows.Scan(&row.packetID, &row.tsOffsetNs, &row.incl, &row.truncExtra, componentMask, &row.frameRaw, &row.frameHash); err != nil {
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
			whereClause, whereArgs := rangeArgs(captureID, chunk)
			query := fmt.Sprintf("%s FROM %s FINAL WHERE capture_id = ? AND %s ORDER BY packet_id ASC",
				selectCols, c.packetsTable(), whereClause)
			rows, err := c.conn.Query(ctx, query, whereArgs...)
			if err != nil {
				return fmt.Errorf("query filtered packets: %w", err)
			}
			batch := make([]nucleusRow, 0)
			for rows.Next() {
				componentMask := new(big.Int)
				var row nucleusRow
				row.componentMask = componentMask
				if err := rows.Scan(&row.packetID, &row.tsOffsetNs, &row.incl, &row.truncExtra, componentMask, &row.frameRaw, &row.frameHash); err != nil {
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

type idRange struct{ lo, hi uint64 }

// toRanges compresses packet IDs into the minimal set of contiguous ranges.
// For sequential ingests (IDs 0,1,2,...) the whole batch becomes one range.
func toRanges(ids []uint64) []idRange {
	if len(ids) == 0 {
		return nil
	}
	sorted := make([]uint64, len(ids))
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
// args[0] is captureID; subsequent pairs are (lo, hi) per range.
func rangeArgs(captureID uuid.UUID, ranges []idRange) (string, []any) {
	var b strings.Builder
	args := make([]any, 1+2*len(ranges))
	args[0] = captureID
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
	ctx context.Context, captureID uuid.UUID, packetIDs []uint64,
	ctor func() components.Component,
) (map[uint64][]components.Component, error) {
	m := make(map[uint64][]components.Component)
	ranges := toRanges(packetIDs)
	for len(ranges) > 0 {
		chunk := ranges
		if len(chunk) > maxRangesPerQuery {
			chunk = ranges[:maxRangesPerQuery]
		}
		ranges = ranges[len(chunk):]

		proto := ctor()
		whereClause, args := rangeArgs(captureID, chunk)
		query := fmt.Sprintf(
			"SELECT %s FROM %s FINAL WHERE capture_id = ? AND %s ORDER BY %s ASC",
			strings.Join(proto.ScanColumns(), ", "),
			c.tableRef(proto.Table()), whereClause, proto.FetchOrderBy(),
		)
		rows, err := c.conn.Query(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", proto.Table(), err)
		}
		for rows.Next() {
			item := ctor()
			pid, err := item.ScanRow(captureID, rows)
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
	rows map[uint64][]components.Component
	err  error
}

func (c *Client) fetchComponentsForBatch(
	ctx context.Context, captureID uuid.UUID, packetIDs []uint64,
) (map[uint]map[uint64][]components.Component, error) {
	n := len(components.ComponentFactories)
	results := make(chan fetchResult, n)
	for kind, ctor := range components.ComponentFactories {
		go func() {
			rows, err := c.fetchComponentBatch(ctx, captureID, packetIDs, ctor)
			results <- fetchResult{kind, rows, err}
		}()
	}
	all := make(map[uint]map[uint64][]components.Component, n)
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
	all map[uint]map[uint64][]components.Component,
) ([]components.Component, error) {
	var list []components.Component
	for _, kind := range components.KnownComponentKinds {
		if !components.ComponentHas(nucleus.Components, kind) {
			continue
		}
		rows := all[kind][nucleus.PacketID]
		if len(rows) == 0 {
			return nil, fmt.Errorf("missing component %d for %s/%d", kind, nucleus.CaptureID, nucleus.PacketID)
		}
		list = append(list, rows...)
	}
	return list, nil
}

func (c *Client) debugPacketDump(captureID uuid.UUID, packetID uint64, nucleus components.PacketNucleus, comps []components.Component) {
	c.log.Debug("packet reconstruction failed",
		"capture_id", captureID,
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

// timedPacketRef is a packet reference augmented with absolute-time sort keys
// for merging across captures.
type timedPacketRef struct {
	captureID        uuid.UUID
	packetID         uint64
	absNs            int64
	captureCreatedAt time.Time
}

// fetchSortedPacketRefs queries packets whose absolute timestamp falls in
// [from, to] (Unix nanoseconds), returning them sorted by
// (absNs ASC, captureCreatedAt ASC, captureID ASC, packetID ASC).
// When captureIDs is nil or empty, all captures are searched.
func (c *Client) fetchSortedPacketRefs(ctx context.Context, captureIDs []uuid.UUID, from, to int64) ([]timedPacketRef, error) {
	capScope := captureScope(captureIDs)
	// PREWHERE created_at <= to prunes captures that started after the query
	// window. We cannot apply a lower-bound prewhere because a capture that
	// started before `from` can still have packets inside [from, to].
	query := fmt.Sprintf(`
		SELECT capture_id, packet_id, abs_ns, capture_created_at
		FROM (
			SELECT p.capture_id, p.packet_id,
			       toInt64(toUnixTimestamp64Nano(cap.created_at)) + toInt64(p.ts) AS abs_ns,
			       cap.created_at AS capture_created_at
			FROM %s p FINAL
			INNER JOIN (
				SELECT capture_id, created_at FROM %s FINAL %s
				PREWHERE toInt64(toUnixTimestamp64Nano(created_at)) <= ?
			) cap ON p.capture_id = cap.capture_id
		)
		WHERE abs_ns BETWEEN ? AND ?
		ORDER BY abs_ns ASC, capture_created_at ASC, capture_id ASC, packet_id ASC`,
		c.packetsTable(), c.capturesTable(), capScope,
	)
	rows, err := c.conn.Query(ctx, query, to, from, to)
	if err != nil {
		return nil, fmt.Errorf("fetch sorted packet refs: %w", err)
	}
	defer rows.Close()
	var refs []timedPacketRef
	for rows.Next() {
		var r timedPacketRef
		if err := rows.Scan(&r.captureID, &r.packetID, &r.absNs, &r.captureCreatedAt); err != nil {
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
// given packet IDs in captureID, then returns reconstructed packets keyed by
// packetID.
func (c *Client) fetchReconstructedPackets(ctx context.Context, captureID uuid.UUID, meta CaptureMeta, packetIDs []uint64) (map[uint64]reconstructedPkt, error) {
	if len(packetIDs) == 0 {
		return nil, nil
	}
	ranges := toRanges(packetIDs)
	const selectCols = "SELECT packet_id, ts, incl_len, trunc_extra, components, frame_raw, frame_hash"
	type nucleusRow struct {
		packetID      uint64
		tsOffsetNs    uint64
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
		whereClause, whereArgs := rangeArgs(captureID, chunk)
		query := fmt.Sprintf("%s FROM %s FINAL WHERE capture_id = ? AND %s ORDER BY packet_id ASC",
			selectCols, c.packetsTable(), whereClause)
		rows, err := c.conn.Query(ctx, query, whereArgs...)
		if err != nil {
			return nil, fmt.Errorf("fetch nuclei for capture %s: %w", captureID, err)
		}
		for rows.Next() {
			componentMask := new(big.Int)
			var row nucleusRow
			row.componentMask = componentMask
			if err := rows.Scan(&row.packetID, &row.tsOffsetNs, &row.incl, &row.truncExtra, componentMask, &row.frameRaw, &row.frameHash); err != nil {
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

	all, err := c.fetchComponentsForBatch(ctx, captureID, packetIDs)
	if err != nil {
		return nil, err
	}

	result := make(map[uint64]reconstructedPkt, len(nuclei))
	for _, row := range nuclei {
		ts := meta.CreatedAt.Add(time.Duration(row.tsOffsetNs))
		nucleus := components.PacketNucleus{
			CaptureID:  captureID,
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
			c.debugPacketDump(captureID, row.packetID, nucleus, componentList)
			return nil, fmt.Errorf("reconstruct packet %d in capture %s: %w", row.packetID, captureID, err)
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

// ExportAllCapturesFiltered finds all captures with a start time at or before
// the upper bound of f's time filter, then exports all matching packets as a
// single merged PCAP file sorted by absolute packet time. Ties are broken by
// capture start time, then by capture ID.
//
// f must contain a time filter; if it does not, an error is returned.
// packetsWritten is incremented after each packet (may be nil).
func (c *Client) ExportAllCapturesFiltered(ctx context.Context, f Query, packetsWritten *atomic.Int64) (rc io.ReadCloser, total int64, err error) {
	from, to, ok := f.TimeRange()
	if !ok {
		return nil, 0, errors.New("--capture all requires a time range filter (e.g. 'time 2024-01-01T00:00:00Z to 2024-01-02T00:00:00Z')")
	}

	// Query across all captures — no capture ID pre-filter.
	refs, err := c.fetchSortedPacketRefs(ctx, nil, from, to)
	if err != nil {
		return nil, 0, err
	}

	// Build capture metadata map only for captures that have matching packets.
	captureMap, err := c.fetchCaptureMetaMap(ctx, uniqueCaptureIDs(refs))
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

// uniqueCaptureIDs returns the deduplicated set of capture IDs referenced by refs.
func uniqueCaptureIDs(refs []timedPacketRef) []uuid.UUID {
	seen := make(map[uuid.UUID]bool, len(refs))
	var out []uuid.UUID
	for _, r := range refs {
		if !seen[r.captureID] {
			seen[r.captureID] = true
			out = append(out, r.captureID)
		}
	}
	return out
}

// fetchCaptureMetaMap fetches CaptureMeta for each of the given capture IDs
// and returns them as a map keyed by capture ID.
func (c *Client) fetchCaptureMetaMap(ctx context.Context, captureIDs []uuid.UUID) (map[uuid.UUID]CaptureMeta, error) {
	if len(captureIDs) == 0 {
		return nil, nil
	}
	cols := strings.Join(CaptureMeta{}.ScanColumns(), ", ")
	query := fmt.Sprintf(
		"SELECT %s FROM %s FINAL WHERE %s",
		cols, c.capturesTable(), captureInSQL(captureIDs),
	)
	rows, err := c.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("fetch capture meta map: %w", err)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]CaptureMeta, len(captureIDs))
	for rows.Next() {
		m, err := scanCaptureMeta(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan capture meta: %w", err)
		}
		result[m.CaptureID] = m
	}
	return result, rows.Err()
}

// streamMergedCaptures writes all packets described by refs (in their given
// order) to w as a single PCAP stream with a synthetic LE/µs header.
func (c *Client) streamMergedCaptures(
	ctx context.Context,
	refs []timedPacketRef,
	captureMap map[uuid.UUID]CaptureMeta,
	w io.Writer,
	packetsWritten *atomic.Int64,
) error {
	// Determine link type and snaplen from the captures present in refs.
	var linkType, snaplen uint32
	linkType = 1    // Ethernet default
	snaplen = 65535 // default
	seenLinkTypes := map[uint32]bool{}
	for _, ref := range refs {
		if m, ok := captureMap[ref.captureID]; ok {
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
		c.log.Warn("merged export contains captures with different link types; using first encountered link type",
			"link_types", seenLinkTypes)
		// Use link type from the first ref's capture.
		if m, ok := captureMap[refs[0].captureID]; ok {
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
		"capture_count", len(captureMap),
		"packet_count", len(refs))
	if err := writePCAPHeader(buf, syntheticMeta); err != nil {
		return err
	}

	if len(refs) == 0 {
		return buf.Flush()
	}

	order := byteOrder(syntheticMeta.Endianness)

	// Group packet IDs by captureID for batch fetching.
	packetsByCapture := make(map[uuid.UUID][]uint64)
	for _, ref := range refs {
		packetsByCapture[ref.captureID] = append(packetsByCapture[ref.captureID], ref.packetID)
	}

	// Fetch and reconstruct all packets for each capture.
	allPackets := make(map[uuid.UUID]map[uint64]reconstructedPkt, len(packetsByCapture))
	for captureID, ids := range packetsByCapture {
		meta, ok := captureMap[captureID]
		if !ok {
			return fmt.Errorf("missing capture meta for %s", captureID)
		}
		pkts, err := c.fetchReconstructedPackets(ctx, captureID, meta, ids)
		if err != nil {
			return err
		}
		allPackets[captureID] = pkts
	}

	// Write packets in the globally-sorted ref order.
	for _, ref := range refs {
		pkt, ok := allPackets[ref.captureID][ref.packetID]
		if !ok {
			return fmt.Errorf("packet %d from capture %s not reconstructed", ref.packetID, ref.captureID)
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
	magic := uint32(0xA1B2C3D4) // µs magic; same value works for both LE and BE via order.PutUint32
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
// timeRes must be "us" (microsecond timestamps) or "ns" (nanosecond timestamps),
// matching the magic number in the file's global header.
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
