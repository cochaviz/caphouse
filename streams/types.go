package streams

import "github.com/google/uuid"

// Protocol is implemented by each supported L7 protocol.
type Protocol interface {
	Name() string               // e.g. "HTTP", "TLS", "SSH"
	Detect(payload []byte) bool // true if payload matches this protocol
}

// SessionProtocol extends Protocol for protocols that extract queryable L7 fields
// and have their own per-stream table.
type SessionProtocol interface {
	Protocol
	NewSession(streamID, captureID uuid.UUID) Session
}

// Session accumulates L7 data from payload bytes for a single stream.
type Session interface {
	Feed(payload []byte)
	Table() string
	Columns() []string
	Values() []any
}
