package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/cochaviz/caphouse"
	"github.com/danielgtaylor/huma/v2"
)

// SearchInput is the request body for POST /v1/search.
type SearchInput struct {
	Body struct {
		Query      string    `json:"query" required:"true" doc:"ClickHouse WHERE clause, e.g. \"ipv4.dst = '1.1.1.1' and tcp.dst = 443\". An empty string matches all packets."`
		From       time.Time `json:"from,omitempty" doc:"Start of the time window (RFC 3339). Requires 'to'."`
		To         time.Time `json:"to,omitempty" doc:"End of the time window (RFC 3339). Requires 'from'."`
		CaptureIDs []string  `json:"capture_ids,omitempty" doc:"Optional list of session IDs (uint64) to restrict the search. Searches all sessions when omitted."`
		Components []string  `json:"components,omitempty" doc:"Protocol component tables to include in the result (e.g. ipv4, tcp, udp, dns). Valid values: ethernet, dot1q, linuxsll, ipv4, ipv6, ipv6_ext, tcp, udp, dns, ntp, arp."`
		Limit      int       `json:"limit,omitempty" doc:"Page size (default: 1000, max: 10000)."`
		Offset     int       `json:"offset,omitempty" doc:"Number of rows to skip (default: 0)."`
		Order      string    `json:"order,omitempty" doc:"Timestamp sort direction: 'asc' or 'desc' (default: 'desc')."`
	}
}

// SearchOutput is the response for POST /v1/search.
type SearchOutput struct {
	Body struct {
		Packets []map[string]any `json:"packets" doc:"Matched packet rows. Each entry includes session_id, packet_id, timestamp_ns, incl_len, orig_len, and any requested component fields."`
		Count   int              `json:"count" doc:"Total number of matched packets."`
	}
}

// CountsInput is the request body for POST /v1/stats/hist.
type CountsInput struct {
	Body struct {
		Query           string    `json:"query" required:"true" doc:"ClickHouse WHERE clause, e.g. \"ipv4.dst = '1.1.1.1' and tcp.dst = 443\". An empty string matches all packets."`
		From            time.Time `json:"from,omitempty" doc:"Start of the time window (RFC 3339). Requires 'to'."`
		To              time.Time `json:"to,omitempty" doc:"End of the time window (RFC 3339). Requires 'from'."`
		CaptureIDs      []string  `json:"capture_ids,omitempty" doc:"Optional list of session IDs (uint64) to restrict the search. Searches all sessions when omitted."`
		BinSeconds      int64     `json:"bin_seconds,omitempty" doc:"Bin width in seconds (default: 60, minimum: 1)."`
		TzOffsetSeconds int64     `json:"tz_offset_seconds,omitempty" doc:"Client UTC offset in seconds (e.g. 7200 for UTC+2). Aligns bins to local midnight."`
		Breakdown       string    `json:"breakdown,omitempty" doc:"Optional field expression to group the histogram by (e.g. 'ipv4.src', 'tcp.dst', 'ipv4.addr'). When provided, breakdown_bins is populated instead of bins."`
	}
}

// CountsOutput is the response for POST /v1/stats/hist.
type CountsOutput struct {
	Body struct {
		Bins          []caphouse.CountBin     `json:"bins,omitempty" doc:"Packet counts per time bin. Only bins that contain at least one matched packet are returned."`
		BinSeconds    int64                   `json:"bin_seconds" doc:"Bin width in seconds used for this response."`
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
		ComponentsMask string         `json:"components_mask" doc:"Packet component bitmask as a decimal string."`
		Components     map[string]any `json:"components" doc:"Parsed packet details grouped by component name. Only components present on the packet are included."`
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

func registerSearchHandlers(api huma.API, client *caphouse.Client) {
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
		pkt, err := client.QueryPacketDetails(ctx, sessionID, input.PacketID)
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
		out.Body.ComponentsMask = pkt.ComponentsMask
		out.Body.Components = pkt.Components
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
}
