package main

import (
	"context"
	"fmt"
	"time"

	"caphouse"
	"caphouse/geoip"
	"github.com/danielgtaylor/huma/v2"
)

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

func registerStreamsHandlers(api huma.API, client *caphouse.Client) {
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
}
