package caphouse

import (
	"log/slog"
	"time"

	"caphouse/components"

	"github.com/google/uuid"
)

// Config controls the ClickHouse connection and ingest behavior.
type Config struct {
	DSN           string // clickhouse connection string or host:port
	Database      string
	SensorID      string
	BatchSize     int // packets per batch (ingest) and export window
	FlushInterval time.Duration
	Debug         bool
	Logger        *slog.Logger // nil uses slog.Default()

	// DisableStreamTracking skips TCP stream reassembly and L7 protocol
	// detection during ingest. Stream tracking is enabled by default.
	DisableStreamTracking bool
}

// PacketNucleus is an alias of the component nucleus type.
type PacketNucleus = components.PacketNucleus

// Packet holds one captured frame with metadata.
type Packet struct {
	CaptureID uuid.UUID
	PacketID  uint64
	Timestamp time.Time
	InclLen   uint32
	OrigLen   uint32
	Frame     []byte
}

// CodecPacket bundles the nucleus with ClickHouse-mapped layer decoders.
type CodecPacket struct {
	Nucleus    PacketNucleus
	Components []components.Component
	// BlockRaw holds the raw pcapng EPB/SPB bytes for byte-exact re-export.
	// Empty for classic PCAP packets.
	BlockRaw []byte
}

// ClickhouseMapper covers generic ClickHouse INSERT and SELECT column concerns
// for any type that is stored in ClickHouse.
type ClickhouseMapper interface {
	Table() string
	ClickhouseColumns() ([]string, error)
	ClickhouseValues() ([]any, error)
	ScanColumns() []string
}
