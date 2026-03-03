//go:build compression

package caphouse

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	tccontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

var compressionClient *Client

// compressionCSV and parseCSV receive one row per PCAP file.
// They are opened in TestMain and flushed/closed before os.Exit.
var compressionCSV *csv.Writer
var parseCSV *csv.Writer

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

	dsn, err := ctr.ConnectionString(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get connection string: %v\n", err)
		os.Exit(1)
	}

	compressionClient, err = New(ctx, Config{
		DSN:       dsn,
		Database:  "caphouse_compression",
		BatchSize: 50000,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create client: %v\n", err)
		os.Exit(1)
	}

	if err := compressionClient.InitSchema(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "init schema: %v\n", err)
		os.Exit(1)
	}

	// Open CSV outputs. os.Exit skips deferred functions, so we capture the
	// exit code from m.Run() and flush/close everything before calling os.Exit.
	if err := os.MkdirAll("testresults", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create testresults dir: %v\n", err)
		os.Exit(1)
	}

	cFile, err := os.Create("testresults/compression_ratio.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create compression_ratio.csv: %v\n", err)
		os.Exit(1)
	}
	compressionCSV = csv.NewWriter(cFile)
	_ = compressionCSV.Write([]string{
		"file", "file_bytes",
		"ref_method", "ref_bytes",
		"ch_logical_bytes", "ch_compressed_bytes",
		"ch_vs_file_ratio", "internal_ratio", "vs_ref_ratio",
	})

	pFile, err := os.Create("testresults/parse_ratio.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create parse_ratio.csv: %v\n", err)
		os.Exit(1)
	}
	parseCSV = csv.NewWriter(pFile)
	_ = parseCSV.Write([]string{
		"file", "total_packets", "parsed_packets", "raw_fallback_packets",
		"parsed_pct", "raw_pct",
	})

	code := m.Run()

	compressionCSV.Flush()
	_ = cFile.Close()
	parseCSV.Flush()
	_ = pFile.Close()
	_ = compressionClient.Close()
	_ = ctr.Terminate(ctx)

	os.Exit(code)
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

// ingestPCAP ingests pcapData into compressionClient under a fresh captureID
// and returns that ID.
func ingestPCAP(t *testing.T, ctx context.Context, pcapData []byte) uuid.UUID {
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
	return captureID
}

// compressedSize returns the byte count after compressing data with xz -9
// (if xz is available) or gzip -9 as a fallback. The method name is also
// returned so the log line is self-describing.
func compressedSize(data []byte) (size uint64, method string) {
	cmd := exec.Command("xz", "--compress", "--stdout", "-9")
	cmd.Stdin = bytes.NewReader(data)
	if out, err := cmd.Output(); err == nil {
		return uint64(len(out)), "xz-9"
	}
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = w.Write(data)
	_ = w.Close()
	return uint64(buf.Len()), "gzip-9"
}

// TestCompressionRatio ingests each PCAP in testdata/ and reports how much
// space the data occupies in ClickHouse relative to the original file. Sizes
// are derived from the delta between two system.parts snapshots so the result
// reflects only that one ingest.
func TestCompressionRatio(t *testing.T) {
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

			beforeC, beforeU := storageSnapshot(t, ctx)
			ingestPCAP(t, ctx, pcapData)
			afterC, afterU := storageSnapshot(t, ctx)

			deltaC := afterC - beforeC
			deltaU := afterU - beforeU
			fileSize := uint64(len(pcapData))
			refSz, refMethod := compressedSize(pcapData)

			chVsFile := float64(deltaC) / float64(fileSize)
			internal := float64(deltaU) / float64(deltaC)
			vsRef := float64(deltaC) / float64(refSz)

			t.Logf("PCAP file:                  %s", fmtBytes(fileSize))
			t.Logf("%s compressed:       %s  (%.2fx file)", refMethod, fmtBytes(refSz), float64(refSz)/float64(fileSize))
			t.Logf("ClickHouse logical size:    %s  (%.2fx file)", fmtBytes(deltaU), float64(deltaU)/float64(fileSize))
			t.Logf("ClickHouse compressed size: %s  (%.2fx file)", fmtBytes(deltaC), chVsFile)
			t.Logf("Internal compress ratio:    %.2fx  (logical → disk)", internal)
			t.Logf("vs %s:              %.2fx", refMethod, vsRef)

			_ = compressionCSV.Write([]string{
				filepath.Base(path),
				fmt.Sprintf("%d", fileSize),
				refMethod,
				fmt.Sprintf("%d", refSz),
				fmt.Sprintf("%d", deltaU),
				fmt.Sprintf("%d", deltaC),
				fmt.Sprintf("%.4f", chVsFile),
				fmt.Sprintf("%.4f", internal),
				fmt.Sprintf("%.4f", vsRef),
			})
		})
	}
}

// TestParseRatio ingests each PCAP in testdata/ and reports what fraction of
// packets were fully parsed into component tables versus stored as raw frame
// fallback bytes in pcap_packets.frame_raw.
func TestParseRatio(t *testing.T) {
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
			captureID := ingestPCAP(t, ctx, pcapData)

			var total, rawCount uint64
			rows, err := compressionClient.conn.Query(ctx, `
				SELECT count(), countIf(length(frame_raw) > 0)
				FROM `+"`caphouse_compression`.`pcap_packets`"+` FINAL
				WHERE capture_id = ?`, captureID)
			if err != nil {
				t.Fatalf("query parse ratio: %v", err)
			}
			defer rows.Close()
			if rows.Next() {
				if err := rows.Scan(&total, &rawCount); err != nil {
					t.Fatalf("scan parse ratio: %v", err)
				}
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("iterate parse ratio: %v", err)
			}
			if total == 0 {
				t.Log("no packets found")
				return
			}
			parsed := total - rawCount
			parsedPct := 100 * float64(parsed) / float64(total)
			rawPct := 100 * float64(rawCount) / float64(total)

			t.Logf("Total packets: %d", total)
			t.Logf("Parsed:        %d  (%.1f%%)", parsed, parsedPct)
			t.Logf("Raw fallback:  %d  (%.1f%%)", rawCount, rawPct)

			_ = parseCSV.Write([]string{
				filepath.Base(path),
				fmt.Sprintf("%d", total),
				fmt.Sprintf("%d", parsed),
				fmt.Sprintf("%d", rawCount),
				fmt.Sprintf("%.2f", parsedPct),
				fmt.Sprintf("%.2f", rawPct),
			})
		})
	}
}
