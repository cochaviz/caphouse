package caphouse

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cochaviz/caphouse/components"
)

// ExportOpts configures a call to Export.
type ExportOpts struct {
	// SessionID restricts the export to a single capture session.
	// When nil, packets from all sessions in the time window are exported.
	SessionID *uint64
	// Filter selects a subset of packets. An empty Filter selects all packets.
	Filter Filter
	// From and To bound the export by absolute packet timestamp. Zero = unset.
	From time.Time
	To   time.Time
	// PacketsWritten is incremented after each packet is written. May be nil.
	PacketsWritten *atomic.Int64
}

// Export streams matching packets as a classic PCAP file.
// Returns a ReadCloser (caller must close), the total matched packet count,
// and any setup error. The stream uses a wide JOIN so no packet ID list is
// ever materialised in Go.
func (c *Client) Export(ctx context.Context, opts ExportOpts) (io.ReadCloser, int64, error) {
	var sessionIDs []uint64
	if opts.SessionID != nil {
		sessionIDs = []uint64{*opts.SessionID}
	}
	var fromNs, toNs int64
	if !opts.From.IsZero() {
		fromNs = opts.From.UnixNano()
	}
	if !opts.To.IsZero() {
		toNs = opts.To.UnixNano()
	}

	// Count matched packets using IDsSQL as a subquery.
	idsSub, err := opts.Filter.IDsSQL(c.tableRef, c.packetsTable(), sessionIDs, 0, 0, fromNs, toNs, true, nil)
	if err != nil {
		return nil, 0, err
	}
	var total uint64
	if err := c.conn.QueryRow(ctx, "SELECT count() FROM ("+idsSub+")").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count export packets: %w", err)
	}

	// Resolve PCAP header metadata.
	var meta CaptureMeta
	if opts.SessionID != nil {
		meta, err = c.fetchCaptureMeta(ctx, *opts.SessionID)
		if err != nil {
			return nil, 0, err
		}
	} else {
		meta, err = c.fetchExportMeta(ctx, idsSub)
		if err != nil {
			return nil, 0, err
		}
	}

	pr, pw := io.Pipe()
	go func() {
		err := c.streamExportPaginated(ctx, sessionIDs, fromNs, toNs, opts.Filter, meta, pw, opts.PacketsWritten)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	return pr, int64(total), nil
}

// fetchExportMeta returns a synthetic CaptureMeta by scanning the session
// metadata for all sessions referenced by matchedSQL.
func (c *Client) fetchExportMeta(ctx context.Context, matchedSQL string) (CaptureMeta, error) {
	sessionQuery := fmt.Sprintf("SELECT DISTINCT session_id FROM (%s)", matchedSQL)
	rows, err := c.conn.Query(ctx, sessionQuery)
	if err != nil {
		return CaptureMeta{}, fmt.Errorf("fetch export sessions: %w", err)
	}
	defer rows.Close()
	var sessionIDs []uint64
	for rows.Next() {
		var sid uint64
		if err := rows.Scan(&sid); err != nil {
			return CaptureMeta{}, err
		}
		sessionIDs = append(sessionIDs, sid)
	}
	if err := rows.Err(); err != nil {
		return CaptureMeta{}, err
	}

	captureMap, err := c.fetchCaptureMetaMap(ctx, sessionIDs)
	if err != nil {
		return CaptureMeta{}, err
	}

	// Build synthetic header: max snaplen, first consistent link type.
	var snaplen, linkType uint32
	snaplen = 65535
	linkType = 1
	seenLinkTypes := map[uint32]bool{}
	for _, m := range captureMap {
		seenLinkTypes[m.LinkType] = true
		if m.Snaplen > snaplen {
			snaplen = m.Snaplen
		}
	}
	if len(seenLinkTypes) == 1 {
		for lt := range seenLinkTypes {
			linkType = lt
		}
	} else if len(seenLinkTypes) > 1 {
		c.log.Warn("merged export: sessions have different link types; using ethernet(1)",
			"link_types", seenLinkTypes)
	}
	if len(sessionIDs) > 0 {
		c.log.Warn("exporting merged capture with synthetic PCAP header",
			"session_count", len(captureMap))
	}
	return CaptureMeta{
		Endianness:     "le",
		TimeResolution: "us",
		Snaplen:        snaplen,
		LinkType:       linkType,
	}, nil
}

// buildExportSQL constructs the wide JOIN streaming SQL using the component
// registry. Repeatable components (OrderRepeatable) are aggregated into arrays
// via CTEs; all others use direct LEFT JOINs. The SELECT column order matches
// KnownComponentKinds, which exportRowScanTargets must also follow.
func (c *Client) buildExportSQL(matchedSQL string) (string, error) {
	var sb strings.Builder

	// --- CTEs ---
	sb.WriteString("WITH\nmatched AS (\n")
	sb.WriteString(matchedSQL)
	sb.WriteString("\n)")

	for _, kind := range components.KnownComponentKinds {
		proto := components.ComponentFactories[kind]()
		if !components.OrderRepeatable[proto.Order()] {
			continue
		}
		alias := proto.Name()
		cteAlias := alias + "_agg"
		dataCols, _ := proto.DataColumns(alias)

		sb.WriteString(",\n")
		sb.WriteString(cteAlias)
		sb.WriteString(" AS (\n    SELECT session_id, packet_id")
		for _, expr := range dataCols {
			bare, cteName := splitCTECol(expr)
			fmt.Fprintf(&sb, ",\n        groupArray(%s) AS %s", bare, cteName)
		}
		// Inner query selects raw columns ordered so groupArray preserves index order.
		sb.WriteString("\n    FROM (\n        SELECT session_id, packet_id")
		for _, expr := range dataCols {
			bare, _ := splitCTECol(expr)
			sb.WriteString(", ")
			sb.WriteString(bare)
		}
		fmt.Fprintf(&sb, "\n        FROM %s FINAL\n        ORDER BY session_id ASC, %s ASC\n    )\n    GROUP BY session_id, packet_id\n)",
			c.tableRef(components.ComponentTable(proto)), proto.FetchOrderBy())
	}

	// --- SELECT (nucleus + all components in KnownComponentKinds order) ---
	sb.WriteString("\nSELECT\n    p.session_id, p.packet_id, p.ts, p.incl_len, p.trunc_extra, p.components, p.payload")

	for _, kind := range components.KnownComponentKinds {
		proto := components.ComponentFactories[kind]()
		alias := proto.Name()
		dataCols, _ := proto.DataColumns(alias)

		if components.OrderRepeatable[proto.Order()] {
			cteAlias := alias + "_agg"
			for _, expr := range dataCols {
				_, cteName := splitCTECol(expr)
				fmt.Fprintf(&sb, ",\n    %s.%s", cteAlias, cteName)
			}
		} else {
			for _, expr := range dataCols {
				fmt.Fprintf(&sb, ",\n    %s", expr)
			}
		}
	}

	// --- FROM + JOINs (same KnownComponentKinds order) ---
	fmt.Fprintf(&sb, "\nFROM %s AS p FINAL\nINNER JOIN matched USING (session_id, packet_id)\n", c.packetsTable())

	for _, kind := range components.KnownComponentKinds {
		proto := components.ComponentFactories[kind]()
		alias := proto.Name()

		if components.OrderRepeatable[proto.Order()] {
			fmt.Fprintf(&sb, "LEFT JOIN %s_agg USING (session_id, packet_id)\n", alias)
		} else {
			fmt.Fprintf(&sb, "LEFT JOIN %s AS %s USING (session_id, packet_id)\n", c.tableRef(components.ComponentTable(proto)), alias)
		}
	}

	sb.WriteString("ORDER BY p.ts ASC, p.session_id ASC, p.packet_id ASC\n")
	sb.WriteString("LIMIT 1 BY p.session_id, p.packet_id")
	return sb.String(), nil
}

// splitCTECol parses a DataColumns expression like "alias.col AS alias_col"
// into the bare column name ("col") and the output alias ("alias_col").
func splitCTECol(expr string) (bare, cteName string) {
	if i := strings.Index(expr, " AS "); i >= 0 {
		cteName = strings.TrimSpace(expr[i+4:])
		qualified := expr[:i]
		if dot := strings.LastIndex(qualified, "."); dot >= 0 {
			bare = qualified[dot+1:]
		} else {
			bare = qualified
		}
		return
	}
	// No alias — treat as bare column name.
	return expr, expr
}

// exportCursor holds the keyset pagination position after each page.
// A zero-value cursor means "start from the beginning".
type exportCursor struct {
	Ts        int64
	SessionID uint64
	PacketID  uint32
}

// exportPageSize is the number of packets fetched per paginated export query.
// Smaller pages reduce peak memory and avoid ClickHouse connection timeouts on
// large captures at the cost of more round-trips.
const exportPageSize = 50_000

// scanEntry holds per-component scan state reused across rows within a page.
type scanEntry struct {
	comp       components.Component
	scanBuf    *components.ScanBuf
	repeatable components.RepeatableExporter
}

// streamExportPaginated writes a complete PCAP stream to w by issuing repeated
// paginated queries of exportPageSize rows each. Pagination avoids ClickHouse
// connection drops that occur when sorting millions of rows in a single query.
func (c *Client) streamExportPaginated(
	ctx context.Context,
	sessionIDs []uint64,
	fromNs, toNs int64,
	filter Filter,
	meta CaptureMeta,
	w io.Writer,
	packetsWritten *atomic.Int64,
) error {
	if len(meta.GlobalHeaderRaw) != 24 {
		c.log.Warn("exporting with synthetic PCAP header: original not available or not pcap",
			"global_header_len", len(meta.GlobalHeaderRaw))
	}

	buf := bufio.NewWriterSize(w, 128*1024)
	if err := writePCAPHeader(buf, meta); err != nil {
		return err
	}

	order := byteOrder(meta.Endianness)

	// Pre-allocate scan entries once; reused across all pages.
	entries := make([]scanEntry, len(components.KnownComponentKinds))
	for i, kind := range components.KnownComponentKinds {
		comp := components.ComponentFactories[kind]()
		e := scanEntry{comp: comp}
		if re, ok := comp.(components.RepeatableExporter); ok {
			e.repeatable = re
		} else {
			sb, err := components.NewScanBuf(comp, false)
			if err != nil {
				return fmt.Errorf("build scan buf for %s: %w", comp.Name(), err)
			}
			e.scanBuf = sb
		}
		entries[i] = e
	}

	var cursor *exportCursor
	for page := 0; ; page++ {
		idsSub, err := filter.IDsSQL(c.tableRef, c.packetsTable(), sessionIDs,
			exportPageSize, 0, fromNs, toNs, true, cursor)
		if err != nil {
			return fmt.Errorf("build page ids (page %d): %w", page, err)
		}
		exportSQL, err := c.buildExportSQL(idsSub)
		if err != nil {
			return fmt.Errorf("build export sql (page %d): %w", page, err)
		}

		n, next, err := c.streamExportPage(ctx, exportSQL, buf, order, entries, meta.TimeResolution, packetsWritten)
		if err != nil {
			return fmt.Errorf("export page %d: %w", page, err)
		}
		c.log.Debug("export page", "page", page, "rows", n)
		if n < exportPageSize {
			break // last page
		}
		cursor = &next
	}

	if err := buf.Flush(); err != nil {
		return fmt.Errorf("flush pcap stream: %w", err)
	}
	return nil
}

// streamExportPage executes one page query and writes the resulting packet
// records into buf. Returns the number of rows written and the cursor pointing
// past the last row, for keyset pagination.
func (c *Client) streamExportPage(
	ctx context.Context,
	exportSQL string,
	buf *bufio.Writer,
	order binary.ByteOrder,
	entries []scanEntry,
	timeResolution string,
	packetsWritten *atomic.Int64,
) (n int, next exportCursor, retErr error) {
	rows, err := c.conn.Query(ctx, exportSQL)
	if err != nil {
		return 0, exportCursor{}, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	// Nucleus scan targets (7 columns); component targets appended per row.
	var (
		sessionID           uint64
		packetID            uint32
		tsNs                int64
		inclLen, truncExtra uint32
		componentMask       = new(big.Int)
		payload             string
	)
	nucleusTargets := []any{
		&sessionID, &packetID, &tsNs,
		&inclLen, &truncExtra,
		componentMask,
		&payload,
	}

	for rows.Next() {
		componentMask.SetInt64(0)

		targets := nucleusTargets
		for _, e := range entries {
			if e.repeatable != nil {
				targets = append(targets, e.repeatable.ExportScanTargets()...)
			} else {
				targets = append(targets, e.scanBuf.Targets...)
			}
		}
		if err := rows.Scan(targets...); err != nil {
			return n, next, fmt.Errorf("scan row %d: %w", n, err)
		}
		for _, e := range entries {
			if e.scanBuf != nil {
				e.scanBuf.Apply()
			}
		}

		ts := time.Unix(0, tsNs)
		nucleus := components.PacketNucleus{
			SessionID:  sessionID,
			PacketID:   packetID,
			Timestamp:  ts,
			InclLen:    inclLen,
			OrigLen:    inclLen + truncExtra,
			Components: componentMask,
			Payload:    []byte(payload),
		}

		var compList []components.Component
		for i, kind := range components.KnownComponentKinds {
			if components.ComponentHas(nucleus.Components, kind) {
				e := entries[i]
				if e.repeatable != nil {
					compList = append(compList, e.repeatable.ExportExpand(sessionID, packetID)...)
				} else {
					compList = append(compList, components.ExpandOne(e.comp, sessionID, packetID)...)
				}
			}
		}

		frame, err := reconstructFrame(nucleus, compList)
		if err != nil {
			return n, next, fmt.Errorf("reconstruct packet %d in session %d: %w", packetID, sessionID, err)
		}

		if err := writePacketRecord(buf, order, timeResolution, ts,
			inclLen, inclLen+truncExtra, frame); err != nil {
			return n, next, err
		}
		if packetsWritten != nil {
			packetsWritten.Add(1)
		}
		n++
		next = exportCursor{Ts: tsNs, SessionID: sessionID, PacketID: packetID}
	}
	if err := rows.Err(); err != nil {
		return n, next, fmt.Errorf("iterate rows after %d: %w", n, err)
	}
	return n, next, nil
}

// CountPackets returns the deduplicated number of packets stored for the given session.
func (c *Client) CountPackets(ctx context.Context, sessionID uint64) (int64, error) {
	q := fmt.Sprintf("SELECT count() FROM %s FINAL WHERE session_id = ?", c.packetsTable())
	var n uint64
	if err := c.conn.QueryRow(ctx, q, sessionID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count packets: %w", err)
	}
	return int64(n), nil
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
		cols, c.capturesTable(), sessionInSQL(sessionIDs),
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
