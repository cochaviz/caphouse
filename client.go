package caphouse

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
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
	batch     []CodecPacket
	lastFlush time.Time

	// captureStarts maps capture_id → capture CreatedAt so that insertBatch
	// can store ts as a nanosecond offset from capture start rather than an
	// absolute timestamp.
	capturesMu   sync.RWMutex
	captureStarts map[uuid.UUID]time.Time
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
	return &Client{
		conn:          conn,
		cfg:           cfg,
		log:           logger,
		lastFlush:     time.Now(),
		captureStarts: make(map[uuid.UUID]time.Time),
	}, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	return c.conn.Close()
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
