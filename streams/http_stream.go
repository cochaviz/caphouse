package streams

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/google/uuid"
)

var httpRequestPrefixes = [][]byte{
	[]byte("GET "),
	[]byte("POST"),
	[]byte("HEAD"),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
}

// HTTPProtocol detects HTTP/1.x by matching well-known request method
// prefixes or a response status line.
type HTTPProtocol struct{}

func (HTTPProtocol) Name() string { return "HTTP" }

func (HTTPProtocol) Detect(payload []byte) bool {
	for _, prefix := range httpRequestPrefixes {
		if bytes.HasPrefix(payload, prefix) {
			return true
		}
	}
	return bytes.HasPrefix(payload, []byte("HTTP/"))
}

func (HTTPProtocol) NewSession(streamID uuid.UUID, sessionID uint64) Session {
	return &HTTPSession{streamID: streamID, sessionID: sessionID}
}

// HTTPSession extracts the request method, host and path from the first
// payload chunk of an HTTP/1.x stream.
type HTTPSession struct {
	streamID  uuid.UUID
	sessionID uint64
	method    string
	host      string
	path      string
	seenFirst bool // true once the request line has been parsed
	done      bool
}

// Feed scans payload lines looking for the request line and Host header.
// Stops feeding once both method and host are found.
func (s *HTTPSession) Feed(payload []byte) {
	if s.done {
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	for scanner.Scan() {
		line := scanner.Text()
		if !s.seenFirst {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 2 {
				s.method = parts[0]
				s.path = parts[1]
			}
			s.seenFirst = true
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "host:") {
			s.host = strings.TrimSpace(line[5:])
		}
		if s.method != "" && s.host != "" {
			s.done = true
			return
		}
	}
}

func (s *HTTPSession) Table() string { return "stream_http" }
func (s *HTTPSession) Columns() []string {
	return []string{"session_id", "stream_id", "method", "host", "path"}
}
func (s *HTTPSession) Values() []any {
	return []any{s.sessionID, s.streamID, s.method, s.host, s.path}
}
