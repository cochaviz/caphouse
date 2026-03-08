package caphouse

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"strings"
	"time"

	"caphouse/components"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

// CreateCapture inserts a capture row if it does not exist.
func (c *Client) CreateCapture(ctx context.Context, meta CaptureMeta) (uuid.UUID, error) {
	if meta.CaptureID == uuid.Nil {
		meta.CaptureID = uuid.New()
	}
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now()
	}
	if meta.Endianness == "" {
		meta.Endianness = "le"
	}
	if meta.TimeResolution == "" {
		meta.TimeResolution = "us"
	}
	if meta.Snaplen == 0 {
		meta.Snaplen = 65535
	}
	if meta.CodecVersion == 0 {
		meta.CodecVersion = components.CodecVersionV1
	}
	if meta.CodecProfile == "" {
		meta.CodecProfile = components.CodecProfileV1
	}

	query := fmt.Sprintf("SELECT capture_id FROM %s WHERE capture_id = ? LIMIT 1", c.capturesTable())
	var existing uuid.UUID
	if err := c.conn.QueryRow(ctx, query, meta.CaptureID).Scan(&existing); err == nil {
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("check capture: %w", err)
	}

	rawHeader := meta.GlobalHeaderRaw
	if rawHeader == nil {
		rawHeader = []byte{}
	}

	insert := fmt.Sprintf(`INSERT INTO %s
(capture_id, sensor_id, created_at, endianness, snaplen, linktype, time_res, global_header_raw, codec_version, codec_profile)
VALUES`, c.capturesTable())

	capBatch, err := c.conn.PrepareBatch(ctx, insert)
	if err != nil {
		return uuid.Nil, fmt.Errorf("prepare capture batch: %w", err)
	}
	if err := capBatch.Append(
		meta.CaptureID,
		meta.SensorID,
		meta.CreatedAt,
		meta.Endianness,
		meta.Snaplen,
		meta.LinkType,
		meta.TimeResolution,
		rawHeader,
		meta.CodecVersion,
		meta.CodecProfile,
	); err != nil {
		return uuid.Nil, fmt.Errorf("append capture: %w", err)
	}
	if err := capBatch.Send(); err != nil {
		return uuid.Nil, fmt.Errorf("insert capture: %w", err)
	}

	c.storeCaptureStart(meta.CaptureID, meta.CreatedAt)
	return meta.CaptureID, nil
}

// IngestPacket queues one packet for batch insert.
func (c *Client) IngestPacket(ctx context.Context, linkType uint32, p Packet) error {
	normalizePacket(&p)
	return c.appendToBatch(ctx, EncodePacket(linkType, p))
}

// appendToBatch adds an encoded packet to the pending batch and flushes if needed.
func (c *Client) appendToBatch(ctx context.Context, encoded CodecPacket) error {
	if c.streams != nil {
		c.streams.Observe(encoded.Nucleus, encoded.Components)
	}
	c.mu.Lock()
	c.batch = append(c.batch, encoded)
	shouldFlush := c.cfg.BatchSize > 0 && len(c.batch) >= c.cfg.BatchSize
	if !shouldFlush && c.cfg.FlushInterval > 0 && time.Since(c.lastFlush) >= c.cfg.FlushInterval {
		shouldFlush = true
	}
	if !shouldFlush {
		c.mu.Unlock()
		return nil
	}
	batch := c.batch
	c.batch = nil
	c.lastFlush = time.Now()
	c.mu.Unlock()
	return c.insertBatchWithRetry(ctx, batch)
}

// Flush sends any buffered packets to ClickHouse.
func (c *Client) Flush(ctx context.Context) error {
	c.mu.Lock()
	if len(c.batch) == 0 {
		c.mu.Unlock()
		return nil
	}
	batch := c.batch
	c.batch = nil
	c.lastFlush = time.Now()
	c.mu.Unlock()
	return c.insertBatchWithRetry(ctx, batch)
}

const (
	retryBaseDelay   = 500 * time.Millisecond
	retryMaxDelay    = 30 * time.Second
	retryMaxAttempts = 5
)

func (c *Client) insertBatchWithRetry(ctx context.Context, batch []CodecPacket) error {
	var lastErr error
	delay := retryBaseDelay
	for attempt := 0; attempt < retryMaxAttempts; attempt++ {
		if attempt > 0 {
			jitter := time.Duration(rand.Int64N(int64(delay / 2)))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay/2 + jitter):
			}
			if delay *= 2; delay > retryMaxDelay {
				delay = retryMaxDelay
			}
		}
		if lastErr = c.insertBatch(ctx, batch); lastErr == nil {
			return nil
		}
		if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) {
			return lastErr
		}
		c.log.Warn("batch insert failed, retrying",
			"attempt", attempt+1,
			"max", retryMaxAttempts,
			"err", lastErr,
			"next_delay", delay,
		)
	}
	return fmt.Errorf("batch insert failed after %d attempts: %w", retryMaxAttempts, lastErr)
}

func (c *Client) insertBatch(ctx context.Context, batch []CodecPacket) error {
	if len(batch) == 0 {
		return nil
	}

	nucleusInsert := fmt.Sprintf(`INSERT INTO %s
(capture_id, packet_id, ts, incl_len, trunc_extra, components, frame_raw, frame_hash, block_raw)
VALUES`, c.packetsTable())

	nucleusBatch, err := c.conn.PrepareBatch(ctx, nucleusInsert)
	if err != nil {
		return fmt.Errorf("prepare nucleus batch: %w", err)
	}

	compBatches := map[string]chdriver.Batch{}

	for _, p := range batch {
		captureStart, ok := c.lookupCaptureStart(p.Nucleus.CaptureID)
		if !ok {
			return fmt.Errorf("unknown capture start for %s; call CreateCapture before IngestPacket", p.Nucleus.CaptureID)
		}
		var tsOffsetNs uint64
		if d := p.Nucleus.Timestamp.Sub(captureStart); d > 0 {
			tsOffsetNs = uint64(d.Nanoseconds())
		}
		blockRaw := p.BlockRaw
		if blockRaw == nil {
			blockRaw = []byte{}
		}
		if err := nucleusBatch.Append(
			p.Nucleus.CaptureID,
			p.Nucleus.PacketID,
			tsOffsetNs,
			p.Nucleus.InclLen,
			p.Nucleus.OrigLen-p.Nucleus.InclLen,
			p.Nucleus.Components,
			p.Nucleus.FrameRaw,
			p.Nucleus.FrameHash,
			blockRaw,
		); err != nil {
			return fmt.Errorf("append nucleus: %w", err)
		}

		for _, comp := range p.Components {
			table := c.tableRef(comp.Table())
			if compBatches[table] == nil {
				cols, err := comp.ClickhouseColumns()
				if err != nil {
					return fmt.Errorf("columns %s: %w", table, err)
				}
				stmt := fmt.Sprintf("INSERT INTO %s (%s) VALUES", table, strings.Join(cols, ", "))
				if compBatches[table], err = c.conn.PrepareBatch(ctx, stmt); err != nil {
					return fmt.Errorf("prepare %s: %w", table, err)
				}
			}
			vals, err := comp.ClickhouseValues()
			if err != nil {
				return fmt.Errorf("values %s: %w", table, err)
			}
			if err := compBatches[table].Append(vals...); err != nil {
				return fmt.Errorf("append %s: %w", table, err)
			}
		}
	}

	allBatches := make(map[string]chdriver.Batch, 1+len(compBatches))
	allBatches[c.packetsTable()] = nucleusBatch
	maps.Copy(allBatches, compBatches)

	type sendResult struct {
		name string
		err  error
	}
	ch := make(chan sendResult, len(allBatches))
	for name, b := range allBatches {
		go func() { ch <- sendResult{name, b.Send()} }()
	}
	for range allBatches {
		if r := <-ch; r.err != nil {
			return fmt.Errorf("send %s: %w", r.name, r.err)
		}
	}
	return nil
}

func normalizePacket(p *Packet) {
	if p.InclLen != uint32(len(p.Frame)) {
		p.InclLen = uint32(len(p.Frame))
	}
	if p.OrigLen == 0 || p.OrigLen < p.InclLen {
		p.OrigLen = p.InclLen
	}
}

// IngestPCAPStream reads a classic PCAP or pcapng stream, creates a capture
// record, and ingests all packets. captureID may be uuid.Nil to let
// CreateCapture generate one. packetIDBase is ORed into each packet's ID;
// pass 0 for sequential IDs starting at 0. onPacket, if non-nil, is called
// after each packet is successfully queued.
//
// CreatedAt on the capture is derived from the first packet's timestamp so
// that per-packet time offsets are always non-negative, which is important for
// archived PCAP files whose timestamps pre-date the ingest time.
func (c *Client) IngestPCAPStream(
	ctx context.Context,
	r io.Reader,
	captureID uuid.UUID,
	sensor string,
	packetIDBase uint64,
	onPacket func(),
) (uuid.UUID, error) {
	br := bufio.NewReader(r)

	header := make([]byte, 24)
	if _, err := io.ReadFull(br, header); err != nil {
		return uuid.Nil, fmt.Errorf("read pcap header: %w", err)
	}

	meta, err := ParseGlobalHeader(header)
	if errors.Is(err, ErrPcapNG) {
		return c.ingestNgStream(ctx, io.MultiReader(bytes.NewReader(header), br), captureID, sensor, packetIDBase, onPacket)
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse pcap header: %w", err)
	}

	meta.CaptureID = captureID
	meta.SensorID = sensor
	meta.GlobalHeaderRaw = header

	reader, err := pcapgo.NewReader(io.MultiReader(bytes.NewReader(header), br))
	if err != nil {
		return uuid.Nil, fmt.Errorf("pcap reader: %w", err)
	}

	return c.ingestPackets(ctx, meta, reader, packetIDBase, onPacket)
}

// ingestNgStream handles the pcapng path for IngestPCAPStream.
// It uses ReadNgRaw so that raw block bytes are preserved for byte-exact export.
func (c *Client) ingestNgStream(
	ctx context.Context,
	r io.Reader,
	captureID uuid.UUID,
	sensor string,
	packetIDBase uint64,
	onPacket func(),
) (uuid.UUID, error) {
	meta, headerRaw, rawPackets, err := ReadNgRaw(r)
	if err != nil {
		return uuid.Nil, err
	}
	meta.CaptureID = captureID
	meta.SensorID = sensor
	meta.GlobalHeaderRaw = headerRaw

	if len(rawPackets) == 0 {
		meta.CreatedAt = time.Now()
		capID, err := c.CreateCapture(ctx, meta)
		if err != nil {
			return uuid.Nil, err
		}
		if err := c.Flush(ctx); err != nil {
			return uuid.Nil, err
		}
		return capID, c.FinalizeStreams(ctx)
	}

	meta.CreatedAt = rawPackets[0].Timestamp
	capID, err := c.CreateCapture(ctx, meta)
	if err != nil {
		return uuid.Nil, err
	}

	for i, rp := range rawPackets {
		encoded := EncodePacket(meta.LinkType, Packet{
			CaptureID: capID,
			PacketID:  packetIDBase | uint64(i),
			Timestamp: rp.Timestamp,
			InclLen:   rp.InclLen,
			OrigLen:   rp.OrigLen,
			Frame:     rp.Frame,
		})
		encoded.BlockRaw = rp.BlockRaw
		if err := c.appendToBatch(ctx, encoded); err != nil {
			return uuid.Nil, err
		}
		if onPacket != nil {
			onPacket()
		}
	}

	if err := c.Flush(ctx); err != nil {
		return uuid.Nil, err
	}
	return capID, c.FinalizeStreams(ctx)
}

// packetReader is satisfied by both pcapgo.Reader and pcapgo.NgReader.
type packetStreamReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// ingestPackets reads from reader, seeds CreatedAt from the first packet
// timestamp, creates the capture record, ingests all packets, and flushes.
func (c *Client) ingestPackets(
	ctx context.Context,
	meta CaptureMeta,
	reader packetStreamReader,
	packetIDBase uint64,
	onPacket func(),
) (uuid.UUID, error) {
	// Read first packet to determine CreatedAt.
	firstData, firstCI, err := reader.ReadPacketData()
	if errors.Is(err, io.EOF) {
		// Empty stream: create the capture with current time.
		meta.CreatedAt = time.Now()
		capID, err := c.CreateCapture(ctx, meta)
		if err != nil {
			return uuid.Nil, err
		}
		if err := c.Flush(ctx); err != nil {
			return uuid.Nil, err
		}
		return capID, c.FinalizeStreams(ctx)
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("read first packet: %w", err)
	}

	meta.CreatedAt = firstCI.Timestamp
	capID, err := c.CreateCapture(ctx, meta)
	if err != nil {
		return uuid.Nil, err
	}

	ingest := func(data []byte, ci gopacket.CaptureInfo, seq uint64) error {
		return c.IngestPacket(ctx, meta.LinkType, Packet{
			CaptureID: capID,
			PacketID:  packetIDBase | seq,
			Timestamp: ci.Timestamp,
			InclLen:   uint32(ci.CaptureLength),
			OrigLen:   uint32(ci.Length),
			Frame:     data,
		})
	}

	var seq uint64
	if err := ingest(firstData, firstCI, seq); err != nil {
		return uuid.Nil, err
	}
	if onPacket != nil {
		onPacket()
	}
	seq++

	for {
		data, ci, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return uuid.Nil, fmt.Errorf("read packet: %w", err)
		}
		if err := ingest(data, ci, seq); err != nil {
			return uuid.Nil, err
		}
		if onPacket != nil {
			onPacket()
		}
		seq++
	}

	if err := c.Flush(ctx); err != nil {
		return uuid.Nil, err
	}
	return capID, c.FinalizeStreams(ctx)
}
