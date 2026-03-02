//go:build compression

package caphouse

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	tccontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

var compressionClient *Client

func TestMain(m *testing.M) {
	ctx := context.Background()

	ctr, err := clickhouse.Run(ctx, "clickhouse/clickhouse-server:25.3",
		tccontainers.WithEnv(map[string]string{
			"CLICKHOUSE_USER":     "default",
			"CLICKHOUSE_PASSWORD": "default",
			"CLICKHOUSE_DB":       "caphouse_compression",
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

	compressionClient, err = New(ctx, Config{
		DSN:      dsn,
		Database: "caphouse_compression",
		BatchSize: 50000,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create client: %v\n", err)
		os.Exit(1)
	}
	defer compressionClient.Close()

	if err := compressionClient.InitSchema(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "init schema: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// storageSnapshot forces a merge and returns the total compressed and
// uncompressed byte counts for the caphouse_compression database.
func storageSnapshot(t *testing.T, ctx context.Context) (compressed, uncompressed uint64) {
	t.Helper()
	tables := []string{
		"pcap_captures", "pcap_packets", "pcap_ethernet", "pcap_dot1q",
		"pcap_linuxsll", "pcap_ipv4", "pcap_ipv4_options", "pcap_ipv6",
		"pcap_ipv6_ext", "pcap_raw_tail",
	}
	for _, tbl := range tables {
		if err := compressionClient.conn.Exec(ctx,
			fmt.Sprintf("OPTIMIZE TABLE `caphouse_compression`.`%s` FINAL", tbl),
		); err != nil {
			t.Fatalf("optimize %s: %v", tbl, err)
		}
	}
	rows, err := compressionClient.conn.Query(ctx, `
		SELECT ifNull(sum(data_compressed_bytes),  0),
		       ifNull(sum(data_uncompressed_bytes), 0)
		FROM   system.parts
		WHERE  database = 'caphouse_compression' AND active = 1`)
	if err != nil {
		t.Fatalf("query system.parts: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&compressed, &uncompressed); err != nil {
			t.Fatalf("scan system.parts: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate system.parts: %v", err)
	}
	return
}

func fmtBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ingestPCAP ingests pcapData into compressionClient under a fresh captureID.
func ingestPCAP(t *testing.T, ctx context.Context, pcapData []byte) {
	t.Helper()
	meta, err := ParseGlobalHeader(pcapData[:24])
	if err != nil {
		t.Fatalf("parse global header: %v", err)
	}
	meta.CaptureID = uuid.New()
	meta.SensorID = "test"
	meta.CreatedAt = time.Now()
	meta.GlobalHeaderRaw = pcapData[:24]

	captureID, err := compressionClient.CreateCapture(ctx, meta)
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
		if err := compressionClient.IngestPacket(ctx, meta.LinkType, Packet{
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
	if err := compressionClient.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// TestCompressionRatio ingests test.pcap and reports how much space the data
// occupies in ClickHouse relative to the original file. Sizes are derived from
// the delta between two system.parts snapshots so the result reflects only this
// ingest.
func TestCompressionRatio(t *testing.T) {
	ctx := context.Background()
	pcapData, err := os.ReadFile("testdata/test.pcap")
	if err != nil {
		t.Fatalf("read testdata/test.pcap: %v", err)
	}

	beforeC, beforeU := storageSnapshot(t, ctx)
	ingestPCAP(t, ctx, pcapData)
	afterC, afterU := storageSnapshot(t, ctx)

	deltaC := afterC - beforeC
	deltaU := afterU - beforeU
	fileSize := uint64(len(pcapData))

	t.Logf("PCAP file:                  %s", fmtBytes(fileSize))
	t.Logf("ClickHouse logical size:    %s  (%.2fx file)", fmtBytes(deltaU), float64(deltaU)/float64(fileSize))
	t.Logf("ClickHouse compressed size: %s  (%.2fx file)", fmtBytes(deltaC), float64(deltaC)/float64(fileSize))
	t.Logf("Internal compress ratio:    %.2fx  (logical → disk)", float64(deltaU)/float64(deltaC))
}
