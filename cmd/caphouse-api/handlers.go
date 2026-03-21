package main

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"

	"caphouse"
	"caphouse/query"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

// SearchInput is the request body for POST /v1/search.
type SearchInput struct {
	Body struct {
		// Query is a tcpdump-style filter expression.
		// Supported primitives: host <ip>, src/dst host <ip>, port <n>,
		// src/dst port <n>, time <rfc3339> to <rfc3339>.
		// Combine with and, or, not, and parentheses.
		Query string `json:"query" required:"true" doc:"tcpdump-style filter expression, e.g. 'host 1.2.3.4 and port 80'"`

		// CaptureIDs restricts the search to specific captures.
		// When empty or omitted, all captures are searched.
		CaptureIDs []string `json:"capture_ids,omitempty" doc:"Optional list of capture UUIDs to restrict the search. Searches all captures when omitted."`

		// Components lists protocol component tables to LEFT JOIN into the result,
		// e.g. ["ipv4", "tcp"]. Valid values: ethernet, dot1q, linuxsll, ipv4,
		// ipv6, ipv6_ext, tcp, udp, dns, ntp.
		Components []string `json:"components,omitempty" doc:"Protocol component tables to include in the result (e.g. ipv4, tcp, udp, dns). Valid values: ethernet, dot1q, linuxsll, ipv4, ipv6, ipv6_ext, tcp, udp, dns, ntp."`

		// Limit is the page size. Defaults to 1000; maximum 10000.
		Limit int `json:"limit,omitempty" doc:"Page size (default: 1000, max: 10000)."`

		// Offset is the number of rows to skip for pagination.
		Offset int `json:"offset,omitempty" doc:"Number of rows to skip (default: 0)."`
	}
}

// SearchOutput is the response for POST /v1/search.
type SearchOutput struct {
	Body struct {
		// Packets holds one map per matched packet. Each map always contains
		// capture_id, packet_id, timestamp_ns (Unix nanoseconds), incl_len,
		// and orig_len, plus any columns from the requested component tables.
		Packets []map[string]any `json:"packets" doc:"Matched packet rows. Each entry includes capture_id, packet_id, timestamp_ns, incl_len, orig_len, and any requested component fields."`

		// Count is the number of matched packets.
		Count int `json:"count" doc:"Total number of matched packets."`
	}
}

// CountsInput is the request body for POST /v1/stats/counts.
type CountsInput struct {
	Body struct {
		// Query is a tcpdump-style filter expression (same syntax as /v1/search).
		Query string `json:"query" required:"true" doc:"tcpdump-style filter expression, e.g. 'host 1.2.3.4 and port 80'"`

		// CaptureIDs restricts the search to specific captures.
		CaptureIDs []string `json:"capture_ids,omitempty" doc:"Optional list of capture UUIDs to restrict the search. Searches all captures when omitted."`

		// BinSeconds is the histogram bin width in seconds. Defaults to 60.
		BinSeconds int64 `json:"bin_seconds,omitempty" doc:"Bin width in seconds (default: 60, minimum: 1)."`
	}
}

// CountsOutput is the response for POST /v1/stats/counts.
type CountsOutput struct {
	Body struct {
		// Bins holds one entry per non-empty time bin.
		Bins []caphouse.CountBin `json:"bins" doc:"Packet counts per time bin. Only bins that contain at least one matched packet are returned."`

		// BinSeconds is the bin width used, echoed back for convenience.
		BinSeconds int64 `json:"bin_seconds" doc:"Bin width in seconds used for this response."`
	}
}

// PacketDetailsInput is the request for GET /v1/captures/{capture_id}/packets/{packet_id}.
type PacketDetailsInput struct {
	CaptureID string `path:"capture_id" doc:"UUID of the capture."`
	PacketID  uint64 `path:"packet_id" doc:"Packet ID within the capture."`
}

// PacketDetailsOutput is the response for GET /v1/captures/{capture_id}/packets/{packet_id}.
type PacketDetailsOutput struct {
	Body struct {
		Components map[string]any `json:"components" doc:"All parsed component fields for the packet, keyed by column name."`
	}
}

// ExportCaptureInput is the request for POST /v1/captures/{capture_id}/export.
type ExportCaptureInput struct {
	// CaptureID is the UUID of the capture to export.
	CaptureID string `path:"capture_id" doc:"UUID of the capture to export."`

	Body struct {
		// Query is an optional filter. When omitted all packets are exported.
		Query string `json:"query,omitempty" doc:"Optional tcpdump-style filter. All packets are exported when omitted."`
	}
}

// ExportAllInput is the request for POST /v1/export.
type ExportAllInput struct {
	Body struct {
		// Query must contain a time range filter.
		Query string `json:"query" required:"true" doc:"tcpdump-style filter with a required time range, e.g. 'time 2024-01-01T00:00:00Z to 2024-01-02T00:00:00Z and host 1.2.3.4'"`
	}
}

// registerHandlers registers all API routes on the given huma.API.
func registerHandlers(api huma.API, client *caphouse.Client) {
	// POST /v1/search
	huma.Register(api, huma.Operation{
		OperationID: "search-packets",
		Method:      "POST",
		Path:        "/v1/search",
		Summary:     "Search packets",
		Description: "Filter packets across one or more captures using a tcpdump-style expression. " +
			"Returns JSON rows with basic packet metadata (capture_id, packet_id, timestamp_ns, incl_len, orig_len) " +
			"plus any protocol component fields requested via the components list.",
		Tags: []string{"search"},
	}, func(ctx context.Context, input *SearchInput) (*SearchOutput, error) {
		q, err := query.ParseQuery(input.Body.Query)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid query: %s", err))
		}

		captureIDs, err := parseUUIDs(input.Body.CaptureIDs)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid capture_id: %s", err))
		}

		limit := input.Body.Limit
		if limit <= 0 || limit > 10000 {
			limit = 1000
		}
		packets, err := client.QueryJSON(ctx, captureIDs, q, input.Body.Components, limit, input.Body.Offset)
		if err != nil {
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

	// POST /v1/stats/counts
	huma.Register(api, huma.Operation{
		OperationID: "stats-counts",
		Method:      "POST",
		Path:        "/v1/stats/counts",
		Summary:     "Packet count histogram",
		Description: "Returns a time-bucketed packet count histogram for packets matching the filter. " +
			"Only bins containing at least one matched packet are returned. " +
			"Bin timestamps (bin_start_ns) are Unix nanoseconds.",
		Tags: []string{"stats"},
	}, func(ctx context.Context, input *CountsInput) (*CountsOutput, error) {
		q, err := query.ParseQuery(input.Body.Query)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid query: %s", err))
		}

		captureIDs, err := parseUUIDs(input.Body.CaptureIDs)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid capture_id: %s", err))
		}

		binSeconds := input.Body.BinSeconds
		if binSeconds <= 0 {
			binSeconds = 60
		}

		bins, err := client.QueryCounts(ctx, captureIDs, q, binSeconds)
		if err != nil {
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
		captureID, err := uuid.Parse(input.CaptureID)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid capture_id: %s", err))
		}
		pkt, err := client.QueryPacketComponents(ctx, captureID, input.PacketID)
		if err != nil {
			return nil, fmt.Errorf("get packet components: %w", err)
		}
		if pkt == nil {
			return nil, huma.Error404NotFound("packet not found")
		}
		out := &PacketDetailsOutput{}
		out.Body.Components = pkt
		return out, nil
	})

	// POST /v1/captures/{capture_id}/export
	huma.Register(api, huma.Operation{
		OperationID: "export-capture",
		Method:      "POST",
		Path:        "/v1/captures/{capture_id}/export",
		Summary:     "Export capture as PCAP",
		Description: "Stream a stored capture as a classic PCAP file (application/vnd.tcpdump.pcap). " +
			"An optional filter expression restricts which packets are included. " +
			"When no filter is provided the entire capture is exported.",
		Tags: []string{"export"},
	}, func(ctx context.Context, input *ExportCaptureInput) (*huma.StreamResponse, error) {
		captureID, err := uuid.Parse(input.CaptureID)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid capture_id: %s", err))
		}

		var rc io.ReadCloser
		if input.Body.Query != "" {
			q, err := query.ParseQuery(input.Body.Query)
			if err != nil {
				return nil, huma.Error400BadRequest(fmt.Sprintf("invalid query: %s", err))
			}
			rc, _, err = client.ExportCaptureFiltered(ctx, captureID, q, nil)
			if err != nil {
				return nil, fmt.Errorf("export: %w", err)
			}
		} else {
			rc, err = client.ExportCapture(ctx, captureID)
			if err != nil {
				return nil, fmt.Errorf("export: %w", err)
			}
		}

		return &huma.StreamResponse{
			Body: func(hctx huma.Context) {
				defer rc.Close()
				hctx.SetHeader("Content-Type", "application/vnd.tcpdump.pcap")
				hctx.SetHeader("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pcap"`, captureID))
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
		Description: "Stream packets from all captures that match the filter as a single time-sorted PCAP file. " +
			"The query must include a time range (e.g. 'time 2024-01-01T00:00:00Z to 2024-01-02T00:00:00Z'). " +
			"The X-Total-Packets response header reports the number of matched packets.",
		Tags: []string{"export"},
	}, func(ctx context.Context, input *ExportAllInput) (*huma.StreamResponse, error) {
		q, err := query.ParseQuery(input.Body.Query)
		if err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid query: %s", err))
		}

		if _, _, ok := q.TimeRange(); !ok {
			return nil, huma.Error400BadRequest(
				"query must include a time range (e.g. 'time 2024-01-01T00:00:00Z to 2024-01-02T00:00:00Z')",
			)
		}

		var written atomic.Int64
		rc, total, err := client.ExportAllCapturesFiltered(ctx, q, &written)
		if err != nil {
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
}

// parseUUIDs parses a slice of UUID strings, returning nil when the input is empty.
func parseUUIDs(ids []string) ([]uuid.UUID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	result := make([]uuid.UUID, len(ids))
	for i, s := range ids {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", s, err)
		}
		result[i] = id
	}
	return result, nil
}
