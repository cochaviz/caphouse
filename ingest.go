package caphouse

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"strings"
	"time"

	"caphouse/components"

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
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, c.capturesTable())

	if err := c.conn.Exec(ctx, insert,
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
		return uuid.Nil, fmt.Errorf("insert capture: %w", err)
	}

	c.storeCaptureStart(meta.CaptureID, meta.CreatedAt)
	return meta.CaptureID, nil
}

// IngestPacket queues one packet for batch insert.
func (c *Client) IngestPacket(ctx context.Context, linkType uint32, p Packet) error {
	normalizePacket(&p)
	encoded := EncodePacket(linkType, p)
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
(capture_id, packet_id, ts, incl_len, trunc_extra, components, frame_raw, frame_hash)
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
		if err := nucleusBatch.Append(
			p.Nucleus.CaptureID,
			p.Nucleus.PacketID,
			tsOffsetNs,
			p.Nucleus.InclLen,
			p.Nucleus.OrigLen-p.Nucleus.InclLen,
			p.Nucleus.Components,
			p.Nucleus.FrameRaw,
			p.Nucleus.FrameHash,
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
