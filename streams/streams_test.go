package streams_test

import (
	"testing"

	"caphouse/streams"
	"github.com/google/uuid"
)

func TestDetectL7Proto(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string // "" means nil (no match)
	}{
		// TLS
		{name: "tls handshake", payload: []byte{0x16, 0x03, 0x01, 0x00, 0x10}, want: "TLS"},
		{name: "tls tls1.2 hint", payload: []byte{0x16, 0x03, 0x03, 0x00, 0x10}, want: "TLS"},
		{name: "not tls wrong content type", payload: []byte{0x17, 0x03, 0x01}, want: ""},
		{name: "not tls wrong version", payload: []byte{0x16, 0x02, 0x01}, want: ""},

		// SSH
		{name: "ssh banner", payload: []byte("SSH-2.0-OpenSSH_8.9"), want: "SSH"},
		{name: "ssh banner v1", payload: []byte("SSH-1.99-foo"), want: "SSH"},
		{name: "not ssh", payload: []byte("GET / HTTP/1.1"), want: "HTTP"},

		// HTTP request methods
		{name: "http get", payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"), want: "HTTP"},
		{name: "http post", payload: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n"), want: "HTTP"},
		{name: "http head", payload: []byte("HEAD / HTTP/1.1\r\n"), want: "HTTP"},
		{name: "http put", payload: []byte("PUT /x HTTP/1.1\r\n"), want: "HTTP"},
		{name: "http delete", payload: []byte("DELETE /x HTTP/1.1\r\n"), want: "HTTP"},
		{name: "http options", payload: []byte("OPTIONS * HTTP/1.1\r\n"), want: "HTTP"},
		{name: "http patch", payload: []byte("PATCH /x HTTP/1.1\r\n"), want: "HTTP"},

		// HTTP response
		{name: "http response", payload: []byte("HTTP/1.1 200 OK\r\n"), want: "HTTP"},

		// Unknown
		{name: "empty", payload: []byte{}, want: ""},
		{name: "random bytes", payload: []byte{0xde, 0xad, 0xbe, 0xef}, want: ""},
		{name: "too short tls", payload: []byte{0x16, 0x03}, want: ""},
		{name: "too short ssh", payload: []byte("SSH"), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proto := streams.Detect(tt.payload)
			if tt.want == "" {
				if proto != nil {
					t.Fatalf("expected nil, got %q", proto.Name())
				}
			} else {
				if proto == nil {
					t.Fatalf("expected %q, got nil", tt.want)
				}
				if proto.Name() != tt.want {
					t.Fatalf("expected %q, got %q", tt.want, proto.Name())
				}
			}
		})
	}
}

func TestHTTPSession(t *testing.T) {
	tests := []struct {
		name       string
		payloads   []string
		wantMethod string
		wantHost   string
		wantPath   string
	}{
		{
			name: "simple GET request",
			payloads: []string{
				"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go\r\n\r\n",
			},
			wantMethod: "GET",
			wantHost:   "example.com",
			wantPath:   "/index.html",
		},
		{
			name: "POST with path",
			payloads: []string{
				"POST /api/v1/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n",
			},
			wantMethod: "POST",
			wantHost:   "api.example.com",
			wantPath:   "/api/v1/users",
		},
		{
			name: "host in second payload",
			payloads: []string{
				"GET /page HTTP/1.1\r\n",
				"Host: split.example.com\r\n\r\n",
			},
			wantMethod: "GET",
			wantHost:   "split.example.com",
			wantPath:   "/page",
		},
		{
			name: "stops feeding after done",
			payloads: []string{
				"DELETE /resource HTTP/1.1\r\nHost: done.example.com\r\n\r\n",
				"ANOTHER payload that should be ignored",
			},
			wantMethod: "DELETE",
			wantHost:   "done.example.com",
			wantPath:   "/resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proto := streams.Detect([]byte(tt.payloads[0]))
			if proto == nil || proto.Name() != "HTTP" {
				t.Fatalf("expected HTTP detection, got %v", proto)
			}
			sp, ok := proto.(streams.SessionProtocol)
			if !ok {
				t.Fatalf("HTTP protocol should implement SessionProtocol")
			}
			session := sp.NewSession(uuid.Nil, 0)
			for _, payload := range tt.payloads {
				session.Feed([]byte(payload))
			}

			vals := session.Values()
			// Values: capture_id, stream_id, method, host, path
			if len(vals) != 5 {
				t.Fatalf("expected 5 values, got %d", len(vals))
			}
			method, _ := vals[2].(string)
			host, _ := vals[3].(string)
			path, _ := vals[4].(string)

			if method != tt.wantMethod {
				t.Fatalf("method: got %q want %q", method, tt.wantMethod)
			}
			if host != tt.wantHost {
				t.Fatalf("host: got %q want %q", host, tt.wantHost)
			}
			if path != tt.wantPath {
				t.Fatalf("path: got %q want %q", path, tt.wantPath)
			}
		})
	}
}
