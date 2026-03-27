package caphouse

import (
	"log/slog"
	"time"

	"caphouse/components"
)

// Config controls the ClickHouse connection and ingest behavior.
type Config struct {
	DSN           string // clickhouse connection string or host:port
	Database      string
	Sensor        string
	BatchSize     int // packets per batch (ingest) and export window
	FlushInterval time.Duration
	Debug         bool
	Logger        *slog.Logger // nil uses slog.Default()

	// DisableStreamTracking skips TCP stream reassembly and L7 protocol
	// detection during ingest. Stream tracking is enabled by default.
	DisableStreamTracking bool
}

// Packet holds one captured frame with metadata.
type Packet struct {
	SessionID uint64
	PacketID  uint32
	Timestamp time.Time
	InclLen   uint32
	OrigLen   uint32
	Frame     []byte
}

// codecPacket bundles the nucleus with ClickHouse-mapped layer decoders.
type codecPacket struct {
	Nucleus    components.PacketNucleus
	Components []components.Component
}

// clickhouseMapper covers generic ClickHouse INSERT and SELECT column concerns
// for any type that is stored in ClickHouse.
type clickhouseMapper interface {
	// Table returns the unqualified ClickHouse table name for this type.
	Table() string
	// ClickhouseColumns returns the ordered column names used in INSERT
	// statements. Must align with ClickhouseValues.
	ClickhouseColumns() ([]string, error)
	// ClickhouseValues returns the ordered values to INSERT, aligned with
	// ClickhouseColumns. nil slices should be replaced with empty equivalents
	// so ClickHouse does not reject the row.
	ClickhouseValues() ([]any, error)
	// ScanColumns returns the ordered column names used in SELECT statements.
	// Implementations must accept a matching Scan call with the same arity.
	ScanColumns() []string
}
