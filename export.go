package caphouse

import (
	"bufio"
	"caphouse/components"
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
			frame, err := ReconstructFrame(nucleus, componentList)
			if err != nil {
				c.debugPacketDump(captureID, row.packetID, nucleus, componentList)
				return fmt.Errorf("reconstruct packet %d: %w", row.packetID, err)
			}
			if err := writePacketRecord(buf, order, ts, row.incl, row.incl+row.truncExtra, frame); err != nil {
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

// writePacketRecord writes a single classic PCAP packet record to w.
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
