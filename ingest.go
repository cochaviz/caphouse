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

	"github.com/cochaviz/caphouse/components"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// CreateCapture inserts a session record. If a session with the same ID already
// exists it is a no-op (ReplacingMergeTree deduplicates on merge). Zero fields
// in meta are filled with safe defaults. Call CreateCapture before any
// IngestPacket calls for the same session ID.
func (c *Client) CreateCapture(ctx context.Context, meta CaptureMeta) (uint64, error) {
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

	query := fmt.Sprintf("SELECT session_id FROM %s WHERE session_id = ? LIMIT 1", c.capturesTable())
	var existing uint64
	if err := c.conn.QueryRow(ctx, query, meta.SessionID).Scan(&existing); err == nil {
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("check capture: %w", err)
	}

	cols, err := meta.ClickhouseColumns()
	if err != nil {
		return 0, fmt.Errorf("capture columns: %w", err)
	}
	insert := fmt.Sprintf("INSERT INTO %s (%s) VALUES", c.capturesTable(), strings.Join(cols, ", "))
	capBatch, err := c.conn.PrepareBatch(ctx, insert)
	if err != nil {
		return 0, fmt.Errorf("prepare capture batch: %w", err)
	}
	vals, err := meta.ClickhouseValues()
	if err != nil {
		return 0, fmt.Errorf("capture values: %w", err)
	}
	if err := capBatch.Append(vals...); err != nil {
		return 0, fmt.Errorf("append capture: %w", err)
	}
	if err := capBatch.Send(); err != nil {
		return 0, fmt.Errorf("insert capture: %w", err)
	}

	return meta.SessionID, nil
}

// IngestPacket encodes p into its protocol layers and queues it for batch
// insert. Batches are flushed automatically when BatchSize is reached or
// FlushInterval elapses; call Flush to force an immediate flush.
// CreateCapture must be called for p.SessionID before IngestPacket.
func (c *Client) IngestPacket(ctx context.Context, linkType uint32, p Packet) error {
	c.mu.Lock()
	batchEmpty := len(c.batch) == 0
	c.mu.Unlock()
	if batchEmpty {
		if err := c.enforceStorageCap(ctx, p.SessionID); err != nil {
			return err
		}
	}
	normalizePacket(&p)
	return c.appendToBatch(ctx, encodePacket(linkType, p))
}

// appendToBatch adds an encoded packet to the pending batch and flushes if needed.
func (c *Client) appendToBatch(ctx context.Context, encoded codecPacket) error {
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

func (c *Client) insertBatchWithRetry(ctx context.Context, batch []codecPacket) error {
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

func (c *Client) insertBatch(ctx context.Context, batch []codecPacket) error {
	if len(batch) == 0 {
		return nil
	}

	nucleusInsert := fmt.Sprintf(`INSERT INTO %s
(session_id, packet_id, ts, incl_len, trunc_extra, components, payload)
VALUES`, c.packetsTable())

	nucleusBatch, err := c.conn.PrepareBatch(ctx, nucleusInsert)
	if err != nil {
		return fmt.Errorf("prepare nucleus batch: %w", err)
	}

	compBatches := map[string]chdriver.Batch{}

	for _, p := range batch {
		tsNs := int64(p.Nucleus.Timestamp.UnixNano())
		if err := nucleusBatch.Append(
			p.Nucleus.SessionID,
			p.Nucleus.PacketID,
			tsNs,
			p.Nucleus.InclLen,
			p.Nucleus.OrigLen-p.Nucleus.InclLen,
			p.Nucleus.Components,
			p.Nucleus.Payload,
		); err != nil {
			return fmt.Errorf("append nucleus: %w", err)
		}

		for _, comp := range p.Components {
			table := c.tableRef(components.ComponentTable(comp))
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

// IngestPCAPStream reads a classic PCAP or pcapng stream, creates a session
// record, and ingests all packets. sessionID must be a non-zero value derived
// from the file hash (see sumToSessionID). onPacket, if non-nil, is called
// after each packet is successfully queued.
func (c *Client) IngestPCAPStream(
	ctx context.Context,
	r io.Reader,
	sessionID uint64,
	sensor string,
	onPacket func(),
) (uint64, error) {
	br := bufio.NewReader(r)

	header := make([]byte, 24)
	if _, err := io.ReadFull(br, header); err != nil {
		return 0, fmt.Errorf("read pcap header: %w", err)
	}

	meta, err := ParseGlobalHeader(header)
	if errors.Is(err, ErrPcapNG) {
		return c.ingestNgStream(ctx, io.MultiReader(bytes.NewReader(header), br), sessionID, sensor, onPacket)
	}
	if err != nil {
		return 0, fmt.Errorf("parse pcap header: %w", err)
	}

	meta.SessionID = sessionID
	meta.Sensor = sensor
	meta.GlobalHeaderRaw = header

	reader, err := pcapgo.NewReader(io.MultiReader(bytes.NewReader(header), br))
	if err != nil {
		return 0, fmt.Errorf("pcap reader: %w", err)
	}
	// Some writers (e.g. dpkt) set an incorrect snaplen in the global header.
	// Override to 65535 so we don't reject packets that exceed the declared limit.
	reader.SetSnaplen(65535)

	return c.ingestPackets(ctx, meta, reader, onPacket)
}

// ingestNgStream handles the pcapng path for IngestPCAPStream.
func (c *Client) ingestNgStream(
	ctx context.Context,
	r io.Reader,
	sessionID uint64,
	sensor string,
	onPacket func(),
) (uint64, error) {
	meta, ngr, err := ParseNgCaptureMeta(r)
	if err != nil {
		return 0, err
	}
	meta.SessionID = sessionID
	meta.Sensor = sensor
	return c.ingestPackets(ctx, meta, ngr, onPacket)
}

// packetReader is satisfied by both pcapgo.Reader and pcapgo.NgReader.
type packetStreamReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// ingestPackets creates the session record, ingests all packets, and flushes.
func (c *Client) ingestPackets(
	ctx context.Context,
	meta CaptureMeta,
	reader packetStreamReader,
	onPacket func(),
) (uint64, error) {
	if err := c.enforceStorageCap(ctx); err != nil {
		return 0, err
	}
	sessionID, err := c.CreateCapture(ctx, meta)
	if err != nil {
		return 0, err
	}

	ingest := func(data []byte, ci gopacket.CaptureInfo, seq uint32) error {
		return c.IngestPacket(ctx, meta.LinkType, Packet{
			SessionID: sessionID,
			PacketID:  seq,
			Timestamp: ci.Timestamp,
			InclLen:   uint32(ci.CaptureLength),
			OrigLen:   uint32(ci.Length),
			Frame:     data,
		})
	}

	var seq uint32
	for {
		data, ci, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("read packet: %w", err)
		}
		if err := ingest(data, ci, seq); err != nil {
			return 0, err
		}
		if onPacket != nil {
			onPacket()
		}
		seq++
	}

	if err := c.Flush(ctx); err != nil {
		return 0, err
	}
	if err := c.FinalizeStreams(ctx); err != nil {
		return 0, err
	}
	return sessionID, nil
}
