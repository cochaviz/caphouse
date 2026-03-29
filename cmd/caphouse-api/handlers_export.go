package main

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"
	"time"

	"caphouse"
	"github.com/danielgtaylor/huma/v2"
)

// ExportCaptureInput is the request for POST /v1/export/{capture_id}.
type ExportCaptureInput struct {
	CaptureID string `path:"capture_id" doc:"Session ID (uint64) of the capture to export."`
	Body      struct {
		Query string `json:"query,omitempty" doc:"Optional ClickHouse WHERE clause. All packets are exported when omitted."`
	}
}

// ExportAllInput is the request for POST /v1/export.
type ExportAllInput struct {
	Body struct {
		From  time.Time `json:"from" required:"true" doc:"Start of the time window (RFC 3339), e.g. '2024-01-01T00:00:00Z'."`
		To    time.Time `json:"to" required:"true" doc:"End of the time window (RFC 3339), e.g. '2024-01-02T00:00:00Z'."`
		Query string    `json:"query,omitempty" doc:"Optional ClickHouse WHERE clause, e.g. \"ipv4.dst = '1.1.1.1'\""`
	}
}

func registerExportHandlers(api huma.API, client *caphouse.Client) {
	// POST /v1/export/{capture_id}
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
		opts := caphouse.ExportOpts{SessionID: &sessionID}
		if input.Body.Query != "" {
			q, err := caphouse.Parse(input.Body.Query)
			if err != nil {
				return nil, huma.Error400BadRequest(fmt.Sprintf("invalid query: %s", err))
			}
			opts.Filter = q
		}
		rc, _, err := client.Export(ctx, opts)
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
				hctx.SetHeader("Content-Disposition", fmt.Sprintf(`attachment; filename="%d.pcap"`, sessionID))
				io.Copy(hctx.BodyWriter(), rc) //nolint:errcheck
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
				io.Copy(hctx.BodyWriter(), rc) //nolint:errcheck
			},
		}, nil
	})
}
