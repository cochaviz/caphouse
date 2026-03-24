//go:build e2e

package caphouse

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	tccontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

var integrationClient *Client

func init() {
	var ctr *clickhouse.ClickHouseContainer
	testSetups = append(testSetups, testSetup{
		setup: func(ctx context.Context) error {
			var err error
			ctr, err = clickhouse.Run(ctx, "clickhouse/clickhouse-server:25.3",
				tccontainers.WithEnv(map[string]string{
					"CLICKHOUSE_USER":     "default",
					"CLICKHOUSE_PASSWORD": "default",
					"CLICKHOUSE_DB":       "caphouse_e2e",
				}),
			)
			if err != nil {
				return fmt.Errorf("start clickhouse container: %w", err)
			}
			dsn, err := ctr.ConnectionString(ctx)
			if err != nil {
				return fmt.Errorf("get connection string: %w", err)
			}
			integrationClient, err = New(ctx, Config{
				DSN:       dsn,
				Database:  "caphouse_e2e",
				BatchSize: 50000,
			})
			if err != nil {
				return fmt.Errorf("create client: %w", err)
			}
			if err := integrationClient.InitSchema(ctx); err != nil {
				return fmt.Errorf("init schema: %w", err)
			}
			return nil
		},
		teardown: func() {
			_ = integrationClient.Close()
			_ = ctr.Terminate(context.Background())
		},
	})
}

// TestE2ERoundtrip ingests every classic PCAP file in testdata/ via
// IngestPCAPStream and verifies byte-exact export. PCAPng files are covered
// separately by TestE2EPcapNgCompat (pcapng_e2e_test.go).
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

			h := sha256.New()
			fmt.Fprintf(h, "%s\x00", filepath.Base(path))
			h.Write(pcapData)
			sessionID := binary.BigEndian.Uint64(h.Sum(nil)[0:8])
			if _, err := integrationClient.IngestPCAPStream(ctx, bytes.NewReader(pcapData), sessionID, "test", nil); err != nil {
				t.Fatalf("IngestPCAPStream: %v", err)
			}

			got, err := integrationClient.ExportCaptureBytes(ctx, sessionID)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			if !bytes.Equal(got, pcapData) {
				t.Fatalf("exported pcap does not match original (got %d bytes, want %d)", len(got), len(pcapData))
			}
		})
	}
}

