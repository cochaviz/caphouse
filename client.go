package caphouse

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"caphouse/streams"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

const (
	defaultBatchSize     = 1000
	defaultFlushInterval = time.Second
)

// Client wraps a ClickHouse connection with batch ingest and export helpers.
type Client struct {
	conn clickhouse.Conn
	cfg  Config // cfg.Database is always the resolved database name after New()
	log  *slog.Logger

	mu        sync.Mutex
	batch     []codecPacket
	lastFlush time.Time

	capturesMu sync.RWMutex
	// captureStarts maps capture_id → capture CreatedAt so that insertBatch
	// can store ts as a nanosecond offset from capture start rather than an
	// absolute timestamp.
	captureStarts map[uuid.UUID]time.Time

	// streams tracks TCP stream state for L7 protocol detection.
	streams *streams.Tracker
}

// New initializes a ClickHouse client.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.DSN == "" {
		return nil, errors.New("dsn is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	opts, err := clickhouse.ParseDSN(cfg.DSN)
	if err != nil {
		opts = &clickhouse.Options{Addr: []string{cfg.DSN}}
	}

	if cfg.Debug {
		opts.Debug = true
		if opts.Debugf == nil {
			opts.Debugf = func(format string, args ...any) {
				logger.Debug(fmt.Sprintf(format, args...))
			}
		}
	}

	if cfg.Database != "" {
		opts.Auth.Database = cfg.Database
	}

	if opts.Auth.Database == "" {
		opts.Auth.Database = "default"
	}

	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}

	if opts.Protocol == clickhouse.HTTP {
		return nil, errors.New("http dsn not supported; use clickhouse:// with native port")
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}

	// Resolve the database name: explicit config takes precedence over DSN,
	// both of which were already merged into opts.Auth.Database above.
	if cfg.Database == "" {
		cfg.Database = opts.Auth.Database
	}
	if err := validateIdent(cfg.Database); err != nil {
		return nil, err
	}
	c := &Client{
		conn:          conn,
		cfg:           cfg,
		log:           logger,
		lastFlush:     time.Now(),
		captureStarts: make(map[uuid.UUID]time.Time),
	}
	if !cfg.DisableStreamTracking {
		c.streams = streams.NewTracker()
	}
	return c, nil
}

// Close closes the underlying connection.
// Conn returns the underlying ClickHouse connection.
func (c *Client) Conn() clickhouse.Conn { return c.conn }

func (c *Client) Close() error {
	return c.conn.Close()
}

// FinalizeStreams drains the stream tracker and inserts qualifying streams
// into stream_captures (and per-protocol tables for session protocols).
// Call this after Flush() to persist all observed TCP streams.
func (c *Client) FinalizeStreams(ctx context.Context) error {
	if c.streams == nil {
		return nil
	}
	qualifying := c.streams.QualifyingStreams()
	if len(qualifying) == 0 {
		return nil
	}

	streamCapturesTable := c.streamCapturesTable()
	streamCapsBatch, err := c.conn.PrepareBatch(ctx, fmt.Sprintf(
		"INSERT INTO %s (capture_id, stream_id, l7_proto, proto, src_ip, dst_ip, src_port, dst_port, is_complete, first_packet_id, last_packet_id, packet_count, byte_count) VALUES",
		streamCapturesTable,
	))
	if err != nil {
		return fmt.Errorf("prepare stream_captures batch: %w", err)
	}

	sessionBatches := map[string]chdriver.Batch{}

	for _, s := range qualifying {
		protoName := ""
		if s.Proto != nil {
			protoName = s.Proto.Name()
		}
		srcIP := addrToIPv6String(s.SynSrcIP)
		dstIP := addrToIPv6String(s.SynDstIP)
		if err := streamCapsBatch.Append(
			s.CaptureID, s.StreamID, protoName, uint8(6),
			srcIP, dstIP,
			s.SynSrcPort, s.SynDstPort,
			s.HasSYN && s.HasSYNACK,
			s.FirstPacketID, s.LastPacketID,
			s.PacketCount, s.ByteCount,
		); err != nil {
			return fmt.Errorf("append stream_captures: %w", err)
		}

		if s.Session == nil {
			continue
		}
		table := c.tableRef(s.Session.Table())
		if sessionBatches[table] == nil {
			cols := s.Session.Columns()
			stmt := fmt.Sprintf("INSERT INTO %s (%s) VALUES", table, strings.Join(cols, ", "))
			if sessionBatches[table], err = c.conn.PrepareBatch(ctx, stmt); err != nil {
				return fmt.Errorf("prepare %s batch: %w", table, err)
			}
		}
		if err := sessionBatches[table].Append(s.Session.Values()...); err != nil {
			return fmt.Errorf("append %s: %w", table, err)
		}
	}

	if err := streamCapsBatch.Send(); err != nil {
		return fmt.Errorf("send stream_captures: %w", err)
	}
	for table, b := range sessionBatches {
		if err := b.Send(); err != nil {
			return fmt.Errorf("send %s: %w", table, err)
		}
	}
	return nil
}

// addrToIPv6String converts a netip.Addr to an IPv6 string for ClickHouse storage.
// IPv4 addresses are represented as IPv4-in-IPv6 (::ffff:x.x.x.x).
func addrToIPv6String(addr netip.Addr) string {
	if !addr.IsValid() {
		return "::"
	}
	if addr.Is4() {
		return netip.AddrFrom16(addr.As16()).String()
	}
	return addr.String()
}

func (c *Client) storeCaptureStart(id uuid.UUID, t time.Time) {
	c.capturesMu.Lock()
	c.captureStarts[id] = t
	c.capturesMu.Unlock()
}

func (c *Client) lookupCaptureStart(id uuid.UUID) (time.Time, bool) {
	c.capturesMu.RLock()
	t, ok := c.captureStarts[id]
	c.capturesMu.RUnlock()
	return t, ok
}
