//go:build integration

package caphouse

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	tccontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

var integrationClient *Client

func TestMain(m *testing.M) {
	ctx := context.Background()

	// CLICKHOUSE_DB tells the ClickHouse image to create the database on startup.
	ctr, err := clickhouse.Run(ctx, "clickhouse/clickhouse-server:25.3",
		tccontainers.WithEnv(map[string]string{
			"CLICKHOUSE_USER":     "default",
			"CLICKHOUSE_PASSWORD": "default",
			"CLICKHOUSE_DB":       "caphouse_e2e",
		}),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start clickhouse container: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = ctr.Terminate(ctx) }()

	dsn, err := ctr.ConnectionString(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get connection string: %v\n", err)
		os.Exit(1)
	}

	integrationClient, err = New(ctx, Config{
		DSN:      dsn,
		Database: "caphouse_e2e",
		// Large batch size so tests control flushing explicitly.
		BatchSize: 50000,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create client: %v\n", err)
		os.Exit(1)
	}
	defer integrationClient.Close()

	if err := integrationClient.InitSchema(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "init schema: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// TestE2ERoundtrip ingests every PCAP/PCAPng file in testdata/ via
// IngestPCAPStream and verifies byte-exact export for both formats.
func TestE2ERoundtrip(t *testing.T) {
	ctx := context.Background()
	paths, err := filepath.Glob("testdata/*.pcap")
	if err != nil {
		t.Fatalf("glob testdata: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no pcap files found in testdata/")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			pcapData, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			captureID, err := integrationClient.IngestPCAPStream(ctx, bytes.NewReader(pcapData), uuid.New(), "test", 0, nil)
			if err != nil {
				t.Fatalf("IngestPCAPStream: %v", err)
			}

			got, err := integrationClient.ExportCaptureBytes(ctx, captureID)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			if !bytes.Equal(got, pcapData) {
				t.Fatalf("exported pcap does not match original (got %d bytes, want %d)", len(got), len(pcapData))
			}
		})
	}
}

