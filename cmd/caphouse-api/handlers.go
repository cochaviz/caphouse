package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"caphouse"
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
// (i.e. the HTTP client disconnected before the response was sent).
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

// timeRangeNs returns fromNs and toNs for a From/To pair.
// Returns 0, 0 when either is zero (unset).
func timeRangeNs(from, to time.Time) (fromNs, toNs int64) {
	if from.IsZero() || to.IsZero() {
		return 0, 0
	}
	return from.UnixNano(), to.UnixNano()
}

// parseSessionIDs parses a slice of decimal uint64 session ID strings,
// returning nil when the input is empty.
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

func registerAllHandlers(api huma.API, client *caphouse.Client, anthropicKey string) {
	registerSearchHandlers(api, client)
	registerExportHandlers(api, client)
	registerStreamsHandlers(api, client)
	registerQueryHandlers(api, client, anthropicKey)
}
