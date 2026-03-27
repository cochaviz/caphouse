package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"caphouse"
	"caphouse/geoip"
	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/danielgtaylor/huma/v2"
)

// queryError returns a 422 huma error when err is a ClickHouse Exception
// (i.e. the user's query is syntactically or semantically invalid), and nil
// otherwise (letting the caller fall through to a generic 500).
func queryError(err error) error {
	var ex *clickhouse.Exception
	if errors.As(err, &ex) {
		return huma.Error422UnprocessableEntity(fmt.Sprintf("invalid query: %s", ex.Message))
	}
	return nil
}

// clientGone returns a 499 huma error when the request context was cancelled
// (i.e. the HTTP client disconnected before the response was sent).  Handlers
// should check this before connectivityError so that a broken-pipe caused by
// the client going away is not mis-classified as a ClickHouse connectivity
// problem.
func clientGone(ctx context.Context, err error) error {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return huma.NewError(499, "client closed request")
	}
	return nil
}

// connectivityError returns a 503 huma error when err indicates a network-level
// failure reaching ClickHouse (timeout, connection refused, EOF, etc.), and nil
// otherwise.
func connectivityError(err error) error {
	var netErr net.Error
	var opErr *net.OpError
	if errors.As(err, &netErr) || errors.As(err, &opErr) || errors.Is(err, io.EOF) {
		return huma.NewError(http.StatusServiceUnavailable, "connection with ClickHouse DB lost")
	}
	return nil
}

// SearchInput is the request body for POST /v1/search.
type SearchInput struct {
	Body struct {
		// Query is a ClickHouse WHERE clause body referencing component tables
		// by name, e.g. "ipv4.dst = '1.1.1.1' AND tcp.dst = 443".
		// An empty query matches all packets.
		Query string `json:"query" required:"true" doc:"ClickHouse WHERE clause, e.g. \"ipv4.dst = '1.1.1.1' and tcp.dst = 443\". An empty string matches all packets."`

		// From and To bound the search to a time window (RFC 3339).
		// Both must be provided together; when omitted all time is searched.
		From time.Time `json:"from,omitempty" doc:"Start of the time window (RFC 3339). Requires 'to'."`
		To   time.Time `json:"to,omitempty" doc:"End of the time window (RFC 3339). Requires 'from'."`

		// CaptureIDs restricts the search to specific captures.
		// When empty or omitted, all captures are searched.
		CaptureIDs []string `json:"capture_ids,omitempty" doc:"Optional list of session IDs (uint64) to restrict the search. Searches all sessions when omitted."`

		// Components lists protocol component tables to LEFT JOIN into the result,
		// e.g. ["ipv4", "tcp"]. Valid values: ethernet, dot1q, linuxsll, ipv4,
		// ipv6, ipv6_ext, tcp, udp, dns, ntp, arp.
		Components []string `json:"components,omitempty" doc:"Protocol component tables to include in the result (e.g. ipv4, tcp, udp, dns). Valid values: ethernet, dot1q, linuxsll, ipv4, ipv6, ipv6_ext, tcp, udp, dns, ntp, arp."`

		// Limit is the page size. Defaults to 1000; maximum 10000.
		Limit int `json:"limit,omitempty" doc:"Page size (default: 1000, max: 10000)."`

		// Offset is the number of rows to skip for pagination.
		Offset int `json:"offset,omitempty" doc:"Number of rows to skip (default: 0)."`

		// Order controls the timestamp sort direction: "asc" or "desc" (default).
		Order string `json:"order,omitempty" doc:"Timestamp sort direction: 'asc' or 'desc' (default: 'desc')."`
	}
}

// SearchOutput is the response for POST /v1/search.
type SearchOutput struct {
	Body struct {
		// Packets holds one map per matched packet. Each map always contains
		// session_id, packet_id, timestamp_ns (Unix nanoseconds), incl_len,
		// and orig_len, plus any columns from the requested component tables.
		Packets []map[string]any `json:"packets" doc:"Matched packet rows. Each entry includes session_id, packet_id, timestamp_ns, incl_len, orig_len, and any requested component fields."`

		// Count is the number of matched packets.
		Count int `json:"count" doc:"Total number of matched packets."`
	}
}

// CountsInput is the request body for POST /v1/stats/counts.
type CountsInput struct {
	Body struct {
		// Query is a ClickHouse WHERE clause body (same syntax as /v1/search).
		Query string `json:"query" required:"true" doc:"ClickHouse WHERE clause, e.g. \"ipv4.dst = '1.1.1.1' and tcp.dst = 443\". An empty string matches all packets."`

		// From and To bound the histogram to a time window (RFC 3339).
		// Both must be provided together; when omitted all time is searched.
		From time.Time `json:"from,omitempty" doc:"Start of the time window (RFC 3339). Requires 'to'."`
		To   time.Time `json:"to,omitempty" doc:"End of the time window (RFC 3339). Requires 'from'."`

		// CaptureIDs restricts the search to specific captures.
		CaptureIDs []string `json:"capture_ids,omitempty" doc:"Optional list of session IDs (uint64) to restrict the search. Searches all sessions when omitted."`

		// BinSeconds is the histogram bin width in seconds. Defaults to 60.
		BinSeconds int64 `json:"bin_seconds,omitempty" doc:"Bin width in seconds (default: 60, minimum: 1)."`

		// TzOffsetSeconds is the client's UTC offset in seconds (e.g. 7200 for UTC+2).
		// Used to align daily (and other) bins to local midnight instead of UTC midnight.
		TzOffsetSeconds int64 `json:"tz_offset_seconds,omitempty" doc:"Client UTC offset in seconds (e.g. 7200 for UTC+2). Aligns bins to local midnight."`

		// Breakdown is an optional field expression to group by (e.g. "ipv4.src", "tcp.dst", "ipv4.addr").
		// When provided, the response includes breakdown_bins instead of bins.
		Breakdown string `json:"breakdown,omitempty" doc:"Optional field expression to group the histogram by (e.g. 'ipv4.src', 'tcp.dst', 'ipv4.addr'). When provided, breakdown_bins is populated instead of bins."`
	}
}

// CountsOutput is the response for POST /v1/stats/counts.
type CountsOutput struct {
	Body struct {
		// Bins holds one entry per non-empty time bin.
		Bins []caphouse.CountBin `json:"bins,omitempty" doc:"Packet counts per time bin. Only bins that contain at least one matched packet are returned."`

		// BinSeconds is the bin width used, echoed back for convenience.
		BinSeconds int64 `json:"bin_seconds" doc:"Bin width in seconds used for this response."`

		// BreakdownBins holds per-(bin, value) counts when a breakdown was requested. Nil otherwise.
		BreakdownBins []caphouse.BreakdownBin `json:"breakdown_bins,omitempty" doc:"Per-(bin, value) counts when breakdown was requested."`
	}
}

// PacketDetailsInput is the request for GET /v1/captures/{capture_id}/packets/{packet_id}.
type PacketDetailsInput struct {
	CaptureID string `path:"capture_id" doc:"Session ID (uint64) of the capture."`
	PacketID  uint32 `path:"packet_id" doc:"Packet ID within the capture."`
}

// PacketDetailsOutput is the response for GET /v1/captures/{capture_id}/packets/{packet_id}.
type PacketDetailsOutput struct {
	Body struct {
		Components map[string]any `json:"components" doc:"All parsed component fields for the packet, keyed by column name."`
	}
}

// PacketFrameInput is the request for GET /v1/captures/{capture_id}/packets/{packet_id}/frame.
type PacketFrameInput struct {
	CaptureID string `path:"capture_id" doc:"Session ID (uint64) of the capture."`
	PacketID  uint32 `path:"packet_id" doc:"Packet ID within the capture."`
}

// PacketFrameOutput is the response for GET /v1/captures/{capture_id}/packets/{packet_id}/frame.
type PacketFrameOutput struct {
	Body struct {
		Hex string `json:"hex" doc:"Reconstructed frame bytes as a lowercase hex string."`
	}
}

// ExportCaptureInput is the request for POST /v1/captures/{capture_id}/export.
type ExportCaptureInput struct {
	// CaptureID is the session ID of the capture to export.
	CaptureID string `path:"capture_id" doc:"Session ID (uint64) of the capture to export."`

	Body struct {
		// Query is an optional ClickHouse WHERE clause. When omitted all packets are exported.
		Query string `json:"query,omitempty" doc:"Optional ClickHouse WHERE clause. All packets are exported when omitted."`
	}
}

// ExportAllInput is the request for POST /v1/export.
type ExportAllInput struct {
	Body struct {
		// From is the start of the time window (RFC 3339).
		From time.Time `json:"from" required:"true" doc:"Start of the time window (RFC 3339), e.g. '2024-01-01T00:00:00Z'."`

		// To is the end of the time window (RFC 3339).
		To time.Time `json:"to" required:"true" doc:"End of the time window (RFC 3339), e.g. '2024-01-02T00:00:00Z'."`

		// Query is an optional ClickHouse WHERE clause to further filter packets.
		Query string `json:"query,omitempty" doc:"Optional ClickHouse WHERE clause, e.g. \"ipv4.dst = '1.1.1.1'\""`
	}
}

// timeRangeNs returns fromNs and toNs for a From/To pair.
// Returns 0, 0 when either is zero (unset).
func timeRangeNs(from, to time.Time) (fromNs, toNs int64) {
	if from.IsZero() || to.IsZero() {
		return 0, 0
	}
	return from.UnixNano(), to.UnixNano()
}

// registerHandlers registers all API routes on the given huma.API.
func registerHandlers(api huma.API, client *caphouse.Client) {
	// POST /v1/search
	huma.Register(api, huma.Operation{
		OperationID: "search-packets",
		Method:      "POST",
		Path:        "/v1/search",
		Summary:     "Search packets",
		Description: "Filter packets across one or more captures using a ClickHouse WHERE clause. " +
			"Returns JSON rows with basic packet metadata (session_id, packet_id, timestamp_ns, incl_len, orig_len) " +
			"plus any protocol component fields requested via the components list.",
		Tags: []string{"search"},
	}, func(ctx context.Context, input *SearchInput) (*SearchOutput, error) {
		q, err := caphouse.Parse(input.Body.Query)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid query: %s", err))
		}

		captureIDs, err := parseSessionIDs(input.Body.CaptureIDs)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid capture_id: %s", err))
		}

		limit := input.Body.Limit
		if limit <= 0 || limit > 10000 {
			limit = 1000
		}
		fromNs, toNs := timeRangeNs(input.Body.From, input.Body.To)
		asc := input.Body.Order == "asc"
		packets, err := client.QueryJSON(ctx, captureIDs, q, input.Body.Components, limit, input.Body.Offset, fromNs, toNs, asc)
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			if cerr := connectivityError(err); cerr != nil {
				return nil, cerr
			}
			if qerr := queryError(err); qerr != nil {
				return nil, qerr
			}
			return nil, fmt.Errorf("search: %w", err)
		}
		if packets == nil {
			packets = []map[string]any{}
		}

		out := &SearchOutput{}
		out.Body.Packets = packets
		out.Body.Count = len(packets)
		return out, nil
	})

	// POST /v1/stats/hist
	huma.Register(api, huma.Operation{
		OperationID: "stats-hist",
		Method:      "POST",
		Path:        "/v1/stats/hist",
		Summary:     "Packet count histogram",
		Description: "Returns a time-bucketed packet count histogram for packets matching the filter. " +
			"Only bins containing at least one matched packet are returned. " +
			"Bin timestamps (bin_start_ns) are Unix nanoseconds.",
		Tags: []string{"stats"},
	}, func(ctx context.Context, input *CountsInput) (*CountsOutput, error) {
		q, err := caphouse.Parse(input.Body.Query)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid query: %s", err))
		}

		captureIDs, err := parseSessionIDs(input.Body.CaptureIDs)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid capture_id: %s", err))
		}

		binSeconds := input.Body.BinSeconds
		if binSeconds < 1 {
			binSeconds = 60
		}

		fromNs, toNs := timeRangeNs(input.Body.From, input.Body.To)

		if input.Body.Breakdown != "" {
			bd, err := client.ParseBreakdownSpec(input.Body.Breakdown)
			if err != nil {
				return nil, huma.Error400BadRequest(fmt.Sprintf("invalid breakdown: %s", err))
			}
			breakdownBins, err := client.QueryCountsBreakdown(ctx, captureIDs, q, binSeconds, fromNs, toNs, input.Body.TzOffsetSeconds, bd)
			if err != nil {
				if cerr := clientGone(ctx, err); cerr != nil {
					return nil, cerr
				}
				if cerr := connectivityError(err); cerr != nil {
					return nil, cerr
				}
				if qerr := queryError(err); qerr != nil {
					return nil, qerr
				}
				return nil, fmt.Errorf("breakdown counts: %w", err)
			}
			if breakdownBins == nil {
				breakdownBins = []caphouse.BreakdownBin{}
			}
			out := &CountsOutput{}
			out.Body.BinSeconds = binSeconds
			out.Body.BreakdownBins = breakdownBins
			return out, nil
		}

		bins, err := client.QueryCounts(ctx, captureIDs, q, binSeconds, fromNs, toNs, input.Body.TzOffsetSeconds)
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			if cerr := connectivityError(err); cerr != nil {
				return nil, cerr
			}
			if qerr := queryError(err); qerr != nil {
				return nil, qerr
			}
			return nil, fmt.Errorf("counts: %w", err)
		}
		if bins == nil {
			bins = []caphouse.CountBin{}
		}

		out := &CountsOutput{}
		out.Body.Bins = bins
		out.Body.BinSeconds = binSeconds
		return out, nil
	})

	// GET /v1/captures/{capture_id}/packets/{packet_id}
	huma.Register(api, huma.Operation{
		OperationID: "get-packet-details",
		Method:      "GET",
		Path:        "/v1/captures/{capture_id}/packets/{packet_id}",
		Summary:     "Get packet details",
		Description: "Returns all parsed component fields for a single packet, organised by layer.",
		Tags:        []string{"search"},
	}, func(ctx context.Context, input *PacketDetailsInput) (*PacketDetailsOutput, error) {
		sessionID, err := strconv.ParseUint(input.CaptureID, 10, 64)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid capture_id: %s", err))
		}
		pkt, err := client.QueryPacketComponents(ctx, sessionID, input.PacketID)
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			if cerr := connectivityError(err); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("get packet components: %w", err)
		}
		if pkt == nil {
			return nil, huma.Error404NotFound("packet not found")
		}
		out := &PacketDetailsOutput{}
		out.Body.Components = pkt
		return out, nil
	})

	// GET /v1/captures/{capture_id}/packets/{packet_id}/frame
	huma.Register(api, huma.Operation{
		OperationID: "get-packet-frame",
		Method:      "GET",
		Path:        "/v1/captures/{capture_id}/packets/{packet_id}/frame",
		Summary:     "Get reconstructed packet frame",
		Description: "Returns the fully reconstructed original frame bytes as a hex string.",
		Tags:        []string{"search"},
	}, func(ctx context.Context, input *PacketFrameInput) (*PacketFrameOutput, error) {
		sessionID, err := strconv.ParseUint(input.CaptureID, 10, 64)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid capture_id: %s", err))
		}
		frame, err := client.QueryPacketFrame(ctx, sessionID, input.PacketID)
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			if cerr := connectivityError(err); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("get packet frame: %w", err)
		}
		if frame == nil {
			return nil, huma.Error404NotFound("packet not found")
		}
		out := &PacketFrameOutput{}
		out.Body.Hex = fmt.Sprintf("%x", frame)
		return out, nil
	})

	// POST /v1/captures/{capture_id}/export
	huma.Register(api, huma.Operation{
		OperationID: "export-capture",
		Method:      "POST",
		Path:        "/v1/export/{capture_id}",
		Summary:     "Export capture as PCAP",
		Description: "Stream a stored capture as a classic PCAP file (application/vnd.tcpdump.pcap). " +
			"An optional ClickHouse WHERE clause restricts which packets are included. " +
			"When no filter is provided the entire capture is exported.",
		Tags: []string{"export"},
	}, func(ctx context.Context, input *ExportCaptureInput) (*huma.StreamResponse, error) {
		sessionID, err := strconv.ParseUint(input.CaptureID, 10, 64)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid capture_id: %s", err))
		}

		var rc io.ReadCloser
		if input.Body.Query != "" {
			q, err := caphouse.Parse(input.Body.Query)
			if err != nil {
				return nil, huma.Error400BadRequest(fmt.Sprintf("invalid query: %s", err))
			}
			rc, _, err = client.Export(ctx, caphouse.ExportOpts{SessionID: &sessionID, Filter: q})
			if err != nil {
				if cerr := clientGone(ctx, err); cerr != nil {
					return nil, cerr
				}
				if cerr := connectivityError(err); cerr != nil {
					return nil, cerr
				}
				return nil, fmt.Errorf("export: %w", err)
			}
		} else {
			rc, _, err = client.Export(ctx, caphouse.ExportOpts{SessionID: &sessionID})
			if err != nil {
				if cerr := clientGone(ctx, err); cerr != nil {
					return nil, cerr
				}
				if cerr := connectivityError(err); cerr != nil {
					return nil, cerr
				}
				return nil, fmt.Errorf("export: %w", err)
			}
		}

		return &huma.StreamResponse{
			Body: func(hctx huma.Context) {
				defer rc.Close()
				hctx.SetHeader("Content-Type", "application/vnd.tcpdump.pcap")
				hctx.SetHeader("Content-Disposition", fmt.Sprintf(`attachment; filename="%d.pcap"`, sessionID))
				w := hctx.BodyWriter()
				io.Copy(w, rc) //nolint:errcheck
			},
		}, nil
	})

	// POST /v1/export
	huma.Register(api, huma.Operation{
		OperationID: "export-all",
		Method:      "POST",
		Path:        "/v1/export",
		Summary:     "Export all captures as merged PCAP",
		Description: "Stream packets from all captures within the given time window as a single time-sorted PCAP file. " +
			"An optional ClickHouse WHERE clause can further filter packets. " +
			"The X-Total-Packets response header reports the number of matched packets.",
		Tags: []string{"export"},
	}, func(ctx context.Context, input *ExportAllInput) (*huma.StreamResponse, error) {
		if !input.Body.From.Before(input.Body.To) {
			return nil, huma.Error400BadRequest("'from' must be before 'to'")
		}

		f, err := caphouse.Parse(input.Body.Query)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid query: %s", err))
		}
		var written atomic.Int64
		rc, total, err := client.Export(ctx, caphouse.ExportOpts{Filter: f, From: input.Body.From, To: input.Body.To, PacketsWritten: &written})
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			if cerr := connectivityError(err); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("export: %w", err)
		}

		return &huma.StreamResponse{
			Body: func(hctx huma.Context) {
				defer rc.Close()
				hctx.SetHeader("Content-Type", "application/vnd.tcpdump.pcap")
				hctx.SetHeader("Content-Disposition", `attachment; filename="merged.pcap"`)
				hctx.SetHeader("X-Total-Packets", fmt.Sprintf("%d", total))
				w := hctx.BodyWriter()
				io.Copy(w, rc) //nolint:errcheck
			},
		}, nil
	})

	// POST /v1/geoip/batch
	type GeoIPBatchInput struct {
		Body struct {
			IPs []string `json:"ips" doc:"List of IP addresses to look up"`
		}
	}
	type GeoIPBatchOutput struct {
		Body map[string]geoip.GeoInfo `doc:"Map of IP address to geolocation and ASN info"`
	}
	huma.Register(api, huma.Operation{
		OperationID: "geoip-batch",
		Method:      "POST",
		Path:        "/v1/geoip/batch",
		Summary:     "Batch IP geolocation",
		Description: "Look up country codes for a list of IP addresses using the ClickHouse ip_trie dictionary.",
		Tags:        []string{"geoip"},
	}, func(ctx context.Context, input *GeoIPBatchInput) (*GeoIPBatchOutput, error) {
		result, err := client.GeoIPLookupBatch(ctx, input.Body.IPs)
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			if cerr := connectivityError(err); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("geoip batch: %w", err)
		}
		return &GeoIPBatchOutput{Body: result}, nil
	})

	// POST /v1/streams
	huma.Register(api, huma.Operation{
		OperationID: "list-streams",
		Method:      "POST",
		Path:        "/v1/streams",
		Summary:     "List streams",
		Description: "Returns TCP stream rows from stream_captures, optionally filtered by session and L7 protocol.",
		Tags:        []string{"streams"},
	}, func(ctx context.Context, input *StreamsInput) (*StreamsOutput, error) {
		captureIDs, err := parseSessionIDs(input.Body.CaptureIDs)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid capture_id: %s", err))
		}

		limit := input.Body.Limit
		if limit <= 0 || limit > 1000 {
			limit = 100
		}

		fromNs, toNs := timeRangeNs(input.Body.From, input.Body.To)

		streams, err := client.QueryStreams(ctx, captureIDs, input.Body.L7Proto, fromNs, toNs, limit, input.Body.Offset)
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			if cerr := connectivityError(err); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("query streams: %w", err)
		}
		if streams == nil {
			streams = []caphouse.StreamRow{}
		}

		total, err := client.CountStreams(ctx, captureIDs, input.Body.L7Proto, fromNs, toNs)
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			if cerr := connectivityError(err); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("count streams: %w", err)
		}

		out := &StreamsOutput{}
		out.Body.Streams = streams
		out.Body.Total = total
		return out, nil
	})
}

// StreamsInput is the request body for POST /v1/streams.
type StreamsInput struct {
	Body struct {
		CaptureIDs []string  `json:"capture_ids,omitempty" doc:"Optional list of session IDs (uint64) to restrict the search. Searches all sessions when omitted."`
		L7Proto    string    `json:"l7_proto,omitempty" doc:"Filter by protocol: HTTP, TLS, SSH. Empty matches all."`
		From       time.Time `json:"from,omitempty" doc:"Start of the time window (RFC 3339). Filters by first-packet timestamp."`
		To         time.Time `json:"to,omitempty" doc:"End of the time window (RFC 3339)."`
		Limit      int       `json:"limit,omitempty" doc:"Page size (default 100, max 1000)."`
		Offset     int       `json:"offset,omitempty" doc:"Number of rows to skip (default 0)."`
	}
}

// StreamsOutput is the response for POST /v1/streams.
type StreamsOutput struct {
	Body struct {
		Streams []caphouse.StreamRow `json:"streams"`
		Total   uint64               `json:"total"`
	}
}

// parseSessionIDs parses a slice of decimal uint64 session ID strings, returning nil when the input is empty.
func parseSessionIDs(ids []string) ([]uint64, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	result := make([]uint64, len(ids))
	for i, s := range ids {
		id, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", s, err)
		}
		result[i] = id
	}
	return result, nil
}
