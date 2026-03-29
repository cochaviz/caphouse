package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
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

// QueryGenerateInput is the request body for POST /v1/query/generate.
type QueryGenerateInput struct {
	Body struct {
		Prompt  string `json:"prompt"           required:"true" doc:"Natural-language description of the query to generate."`
		BaseSQL string `json:"base_sql,omitempty"               doc:"The SQL query that would be generated without any filter — provides structural context for the AI."`
	}
}

// QueryGenerateOutput is the response for POST /v1/query/generate.
type QueryGenerateOutput struct {
	Body struct {
		SQL string `json:"sql" doc:"Generated ClickHouse SQL ready to execute."`
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

// buildSchemaPrompt builds a system prompt that describes the ClickHouse schema
// and the expected query pattern, so the model can generate valid SQL.
func buildSchemaPrompt(schema []caphouse.TableSchema) string {
	var sb strings.Builder
	sb.WriteString(`You are a ClickHouse SQL expert for a network packet capture database.

## Schema

The database stores packet captures. Each packet has a row in pcap_packets and optional rows in per-protocol component tables joined by (session_id, packet_id).

`)
	for _, t := range schema {
		colStrs := make([]string, len(t.Columns))
		for i, c := range t.Columns {
			colStrs[i] = c.Name + " " + c.Type
		}
		fmt.Fprintf(&sb, "**%s** (alias `%s`): %s\n", t.Label, t.Name, strings.Join(colStrs, ", "))
	}

	sb.WriteString(`
## Rules

- Output **only** valid ClickHouse SQL — no explanation, no markdown fences.
- Use the two-phase pattern above.
- Default LIMIT 1000 unless the user specifies otherwise.
- ts is Unix nanoseconds (Int64); use toDateTime64(ts / 1e9, 9) to display as timestamps.
- MAC addresses (ethernet_src, ethernet_dst) are stored as hex strings, e.g. 'aabbccddeeff'.
- IPv4 addresses are dotted-decimal strings, e.g. '192.168.1.1'.
- Component tables are named pcap_<name> (e.g. pcap_ipv4, pcap_tcp, pcap_udp, pcap_dns).
- Add inline SQL comments (--) to explain non-obvious filters, joins, and expressions.
`)

	return sb.String()
}

// callAnthropic sends a single-turn message to the Anthropic Messages API
// and returns the text of the first content block.
func callAnthropic(ctx context.Context, apiKey, system, userMsg string) (string, error) {
	type message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	reqBody, err := json.Marshal(map[string]any{
		"model":      "claude-haiku-4-5-20251001",
		"max_tokens": 2048,
		"system":     system,
		"messages":   []message{{Role: "user", Content: userMsg}},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read anthropic response: %w", err)
	}

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("parse anthropic response: %w", err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("anthropic error: %s", parsed.Error.Message)
	}
	if len(parsed.Content) == 0 {
		return "", fmt.Errorf("empty response from anthropic")
	}
	text := parsed.Content[0].Text

	// Strip markdown code fences if the model wrapped the SQL in them.
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "```") {
		lines := strings.SplitN(text, "\n", 2)
		if len(lines) == 2 {
			text = lines[1]
		}
		if idx := strings.LastIndex(text, "```"); idx >= 0 {
			text = text[:idx]
		}
		text = strings.TrimSpace(text)
	}
	return text, nil
}

func registerQueryHandlers(api huma.API, client *caphouse.Client, anthropicKey string) {
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

	// POST /v1/query/generate
	huma.Register(api, huma.Operation{
		OperationID: "query-generate",
		Method:      http.MethodPost,
		Path:        "/v1/query/generate",
		Summary:     "Generate SQL with AI",
		Description: "Uses an AI model to generate ClickHouse SQL from a natural-language prompt. Requires ANTHROPIC_API_KEY to be configured.",
		Tags:        []string{"query"},
	}, func(ctx context.Context, input *QueryGenerateInput) (*QueryGenerateOutput, error) {
		if anthropicKey == "" {
			return nil, huma.NewError(http.StatusNotImplemented, "AI generation is not configured (missing ANTHROPIC_API_KEY)")
		}
		system := buildSchemaPrompt(client.DisplaySchema())
		userMsg := input.Body.Prompt
		if input.Body.BaseSQL != "" {
			userMsg = "Base query (without filters, for structural reference):\n" + input.Body.BaseSQL + "\n\nRequest: " + input.Body.Prompt
		}
		sql, err := callAnthropic(ctx, anthropicKey, system, userMsg)
		if err != nil {
			if cerr := clientGone(ctx, err); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("generate SQL: %w", err)
		}
		out := &QueryGenerateOutput{}
		out.Body.SQL = sql
		return out, nil
	})
}
