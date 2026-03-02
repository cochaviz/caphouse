//go:build integration

package caphouse

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
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

// TestE2ERoundtrip verifies the core library contract: ingest a PCAP through
// the raw API (CreateCapture → IngestPacket → Flush) and export byte-for-byte.
// Runs once per PCAP file found in testdata/.
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

			meta, err := ParseGlobalHeader(pcapData[:24])
			if err != nil {
				t.Fatalf("parse global header: %v", err)
			}
			meta.CaptureID = uuid.New()
			meta.SensorID = "test"
			meta.CreatedAt = time.Now()
			meta.GlobalHeaderRaw = pcapData[:24]

			captureID, err := integrationClient.CreateCapture(ctx, meta)
			if err != nil {
				t.Fatalf("create capture: %v", err)
			}

			reader, err := pcapgo.NewReader(bytes.NewReader(pcapData))
			if err != nil {
				t.Fatalf("pcapgo reader: %v", err)
			}
			var seq uint64
			for {
				frame, ci, err := reader.ReadPacketData()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("read packet: %v", err)
				}
				if err := integrationClient.IngestPacket(ctx, meta.LinkType, Packet{
					CaptureID: captureID,
					PacketID:  seq,
					Timestamp: ci.Timestamp,
					InclLen:   uint32(ci.CaptureLength),
					OrigLen:   uint32(ci.Length),
					Frame:     frame,
				}); err != nil {
					t.Fatalf("ingest packet %d: %v", seq, err)
				}
				seq++
			}
			if err := integrationClient.Flush(ctx); err != nil {
				t.Fatalf("flush: %v", err)
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
