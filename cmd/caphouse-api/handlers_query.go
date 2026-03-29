package main

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"

	"caphouse"
	"github.com/danielgtaylor/huma/v2"
)

// QuerySchemaOutput is the response for GET /v1/query/schema.
type QuerySchemaOutput struct {
	Body struct {
		Tables []caphouse.TableSchema `json:"tables" doc:"Schema for each queryable table."`
	}
}

// QueryPreviewInput is the request body for POST /v1/query/preview.
type QueryPreviewInput struct {
	Body struct {
		Filter     string   `json:"filter,omitempty"     doc:"WHERE clause (caphouse filter syntax). Empty matches all packets."`
		Components []string `json:"components,omitempty" doc:"Component names to LEFT JOIN and include in the SELECT."`
		Captures   bool     `json:"captures,omitempty"   doc:"When true, LEFT JOIN pcap_captures to expose sensor and capture metadata."`
		Limit      int      `json:"limit,omitempty"      doc:"LIMIT applied to the generated SQL (default 1000, max 10000)."`
		From       string   `json:"from,omitempty"       doc:"Inclusive lower bound on packet timestamp (ISO 8601, treated as UTC)."`
		To         string   `json:"to,omitempty"         doc:"Exclusive upper bound on packet timestamp (ISO 8601, treated as UTC)."`
	}
}

// QueryPreviewOutput is the response for POST /v1/query/preview.
type QueryPreviewOutput struct {
	Body struct {
		SQL string `json:"sql" doc:"The assembled SELECT SQL, ready to copy-paste or send to /v1/query/execute."`
	}
}

// QueryExecuteInput is the request body for POST /v1/query/execute.
type QueryExecuteInput struct {
	Body struct {
		SQL string `json:"sql" doc:"SQL to execute."`
	}
}

// QueryExecuteOutput is the response for POST /v1/query/execute.
type QueryExecuteOutput struct {
	Body struct {
		Columns []string `json:"columns" doc:"Ordered column names returned by the query."`
		Rows    [][]any  `json:"rows"    doc:"Result rows; each row is an array aligned with columns. uint64 values are serialised as strings to avoid JS precision loss."`
	}
}

// parseTimeOptional parses an optional ISO 8601 / datetime-local string as UTC.
// Returns nil, nil when s is empty.
func parseTimeOptional(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("unrecognised datetime format %q", s)
}

func registerQueryHandlers(api huma.API, client *caphouse.Client) {
	// GET /v1/query/schema
	huma.Register(api, huma.Operation{
		OperationID: "query-schema",
		Method:      http.MethodGet,
		Path:        "/v1/query/schema",
		Summary:     "Get query schema",
		Description: "Returns the columns available in each queryable table.",
		Tags:        []string{"query"},
	}, func(ctx context.Context, _ *struct{}) (*QuerySchemaOutput, error) {
		out := &QuerySchemaOutput{}
		out.Body.Tables = client.DisplaySchema()
		return out, nil
	})

	// POST /v1/query/preview
	huma.Register(api, huma.Operation{
		OperationID: "query-preview",
		Method:      http.MethodPost,
		Path:        "/v1/query/preview",
		Summary:     "Preview generated SQL",
		Description: "Assembles and returns the SELECT SQL for the given filter and component selection without executing it.",
		Tags:        []string{"query"},
	}, func(ctx context.Context, input *QueryPreviewInput) (*QueryPreviewOutput, error) {
		limit := input.Body.Limit
		if limit <= 0 {
			limit = 1000
		}
		if limit > 10000 {
			limit = 10000
		}
		from, err := parseTimeOptional(input.Body.From)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid 'from' timestamp: " + err.Error())
		}
		to, err := parseTimeOptional(input.Body.To)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid 'to' timestamp: " + err.Error())
		}
		f, err := caphouse.Parse(input.Body.Filter)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid filter: " + err.Error())
		}
		var fromNs, toNs int64
		if from != nil {
			fromNs = from.UnixNano()
		}
		if to != nil {
			toNs = to.UnixNano()
		}
		if fromNs != 0 && toNs == 0 {
			toNs = math.MaxInt64
		}
		sql, err := client.SearchSQL(f, nil, input.Body.Components, limit, 0, fromNs, toNs, false, input.Body.Captures)
		if err != nil {
			if qerr := queryError(err); qerr != nil {
				return nil, qerr
			}
			return nil, fmt.Errorf("preview query: %w", err)
		}
		out := &QueryPreviewOutput{}
		out.Body.SQL = sql
		return out, nil
	})

	// POST /v1/query/execute
	huma.Register(api, huma.Operation{
		OperationID: "query-execute",
		Method:      http.MethodPost,
		Path:        "/v1/query/execute",
		Summary:     "Execute raw SQL",
		Description: "Executes a SQL statement and returns columns and rows as JSON.",
		Tags:        []string{"query"},
	}, func(ctx context.Context, input *QueryExecuteInput) (*QueryExecuteOutput, error) {
		cols, rows, err := client.QueryRaw(ctx, input.Body.SQL)
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			if qerr := queryError(err); qerr != nil {
				return nil, qerr
			}
			if cerr := connectivityError(err); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("execute query: %w", err)
		}
		out := &QueryExecuteOutput{}
		out.Body.Columns = cols
		if rows != nil {
			out.Body.Rows = rows
		} else {
			out.Body.Rows = [][]any{}
		}
		return out, nil
	})
}
