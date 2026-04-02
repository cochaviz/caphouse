package main

import (
	"context"
	"net/http"

	"caphouse"
	"github.com/danielgtaylor/huma/v2"
)

// ReEncodeInput is the request body for POST /v1/admin/re-encode.
type ReEncodeInput struct {
	Body struct {
		SessionIDs []string `json:"session_ids,omitempty" doc:"Restrict to these session IDs (decimal strings). Omit to scan all sessions."`
	}
}

// ReEncodeOutput is the response for POST /v1/admin/re-encode.
type ReEncodeOutput struct {
	Body caphouse.ReEncodeResult
}

func registerAdminHandlers(api huma.API, client *caphouse.Client) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-re-encode",
		Method:      http.MethodPost,
		Path:        "/v1/admin/re-encode",
		Summary:     "Re-encode under-parsed packets",
		Description: "Re-encodes packets that were stored without any L4-or-above component (e.g. ICMPv4/ICMPv6 packets ingested before those components were registered). Reconstructs each matching packet's original frame and re-encodes it with the current component registry. ReplacingMergeTree deduplication handles overwriting the old rows.",
		Tags:        []string{"admin"},
	}, func(ctx context.Context, input *ReEncodeInput) (*ReEncodeOutput, error) {
		sessionIDs, err := parseSessionIDs(input.Body.SessionIDs)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid session_ids: " + err.Error())
		}
		result, err := client.ReEncodePackets(ctx, sessionIDs)
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			if cerr := connectivityError(err); cerr != nil {
				return nil, cerr
			}
			return nil, err
		}
		return &ReEncodeOutput{Body: result}, nil
	})
}
