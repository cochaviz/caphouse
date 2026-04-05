//go:build compression

package caphouse

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/google/gopacket/pcapgo"
	tccontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

var compressionClient *Client

// compressionCSV, tableCSV, and parseCSV receive one row per PCAP file (or
// per file+table for tableCSV). They are opened in TestMain and
// flushed/closed before os.Exit.
var compressionCSV *csv.Writer
var tableCSV *csv.Writer
var parseCSV *csv.Writer

// tables is the ordered list of caphouse schema tables.
var tables = []string{
	"pcap_captures", "pcap_packets", "pcap_ethernet", "pcap_dot1q",
	"pcap_linuxsll", "pcap_ipv4", "pcap_ipv6", "pcap_ipv6_ext",
	"pcap_tcp", "pcap_udp", "pcap_dns", "pcap_ntp",
}

// tableBytes holds the raw system.parts byte counts for one table.
type tableBytes struct {
	compressed   uint64
	uncompressed uint64
}

func init() {
	var ctr *clickhouse.ClickHouseContainer
	var cFile, tFile, pFile *os.File
	testSetups = append(testSetups, testSetup{
		setup: func(ctx context.Context) error {
			var err error
			ctr, err = clickhouse.Run(ctx, "clickhouse/clickhouse-server:25.3",
				tccontainers.WithEnv(map[string]string{
					"CLICKHOUSE_USER":     "default",
					"CLICKHOUSE_PASSWORD": "default",
					"CLICKHOUSE_DB":       "caphouse_compression",
				}),
			)
			if err != nil {
				return fmt.Errorf("start clickhouse container: %w", err)
			}
			dsn, err := ctr.ConnectionString(ctx)
			if err != nil {
				return fmt.Errorf("get connection string: %w", err)
			}
			compressionClient, err = New(ctx, Config{
				DSN:       dsn,
				Database:  "caphouse_compression",
				BatchSize: 50000,
			})
			if err != nil {
				return fmt.Errorf("create client: %w", err)
			}
			if err := compressionClient.InitSchema(ctx); err != nil {
				return fmt.Errorf("init schema: %w", err)
			}
			if err := os.MkdirAll("test_results", 0o755); err != nil {
				return fmt.Errorf("create test_results dir: %w", err)
			}
			cFile, err = os.Create("test_results/compression_ratio.csv")
			if err != nil {
				return fmt.Errorf("create compression_ratio.csv: %w", err)
			}
			compressionCSV = csv.NewWriter(cFile)
			_ = compressionCSV.Write([]string{
				"file", "file_bytes",
				"ref_method", "ref_bytes",
				"ch_logical_bytes", "ch_compressed_bytes",
				"ch_vs_file_ratio", "internal_ratio", "vs_ref_ratio",
			})
			tFile, err = os.Create("test_results/compression_by_table.csv")
			if err != nil {
				return fmt.Errorf("create compression_by_table.csv: %w", err)
			}
			tableCSV = csv.NewWriter(tFile)
			_ = tableCSV.Write([]string{
				"file", "table",
				"logical_bytes", "compressed_bytes",
				"compression_ratio",
				"pct_of_total_logical", "pct_of_total_compressed",
			})
			pFile, err = os.Create("test_results/parse_ratio.csv")
			if err != nil {
				return fmt.Errorf("create parse_ratio.csv: %w", err)
			}
			parseCSV = csv.NewWriter(pFile)
			_ = parseCSV.Write([]string{
				"file", "total_packets", "parsed_packets", "raw_fallback_packets",
				"parsed_pct", "raw_pct",
			})
			return nil
		},
		teardown: func() {
			compressionCSV.Flush()
			_ = cFile.Close()
			tableCSV.Flush()
			_ = tFile.Close()
			parseCSV.Flush()
			_ = pFile.Close()
			_ = compressionClient.Close()
			_ = ctr.Terminate(context.Background())
		},
	})
}

// storageSnapshot forces a merge and returns per-table byte counts alongside
// the aggregate compressed/uncompressed totals for the caphouse_compression
// database.
func storageSnapshot(t *testing.T, ctx context.Context) (byTable map[string]tableBytes, compressed, uncompressed uint64) {
	t.Helper()
	for _, tbl := range tables {
		if err := compressionClient.conn.Exec(ctx,
			fmt.Sprintf("OPTIMIZE TABLE `caphouse_compression`.`%s` FINAL", tbl),
		); err != nil {
			t.Fatalf("optimize %s: %v", tbl, err)
		}
	}
	rows, err := compressionClient.conn.Query(ctx, `
		SELECT table,
		       ifNull(sum(data_compressed_bytes),  0),
		       ifNull(sum(data_uncompressed_bytes), 0)
		FROM   system.parts
		WHERE  database = 'caphouse_compression' AND active = 1
		GROUP BY table`)
	if err != nil {
		t.Fatalf("query system.parts: %v", err)
	}
	defer rows.Close()
	byTable = make(map[string]tableBytes)
	for rows.Next() {
		var tbl string
		var c, u uint64
		if err := rows.Scan(&tbl, &c, &u); err != nil {
			t.Fatalf("scan system.parts: %v", err)
		}
		byTable[tbl] = tableBytes{compressed: c, uncompressed: u}
		compressed += c
		uncompressed += u
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

// ingestPCAP ingests pcapData into compressionClient and returns the session ID.
func ingestPCAP(t *testing.T, ctx context.Context, pcapData []byte) uint64 {
	t.Helper()
	meta, err := ParseGlobalHeader(pcapData[:24])
	if err != nil {
		t.Fatalf("parse global header: %v", err)
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00", "compression_test")
	h.Write(pcapData)
	sessionID := binary.BigEndian.Uint64(h.Sum(nil)[0:8])
	meta.SessionID = sessionID
	meta.Sensor = "test"
	meta.GlobalHeaderRaw = pcapData[:24]

	if _, err := compressionClient.CreateCapture(ctx, meta); err != nil {
		t.Fatalf("create capture: %v", err)
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("pcapgo reader: %v", err)
	}
	var seq uint32
	for {
		frame, ci, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read packet: %v", err)
		}
		if err := compressionClient.IngestPacket(ctx, meta.LinkType, Packet{
			SessionID: sessionID,
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
	return sessionID
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

// compressionMeasure holds the results of a single PCAP compression measurement.
type compressionMeasure struct {
	FileBytes       uint64
	RefBytes        uint64
	RefMethod       string
	LogicalBytes    uint64 // delta uncompressed bytes in ClickHouse
	CompressedBytes uint64 // delta compressed bytes in ClickHouse
	ByTableDelta    map[string]tableBytes
}

// ChVsFileRatio returns CompressedBytes / FileBytes: how many ClickHouse
// compressed bytes are written per raw PCAP byte.
func (m compressionMeasure) ChVsFileRatio() float64 {
	return float64(m.CompressedBytes) / float64(m.FileBytes)
}

// measureCompression ingests the PCAP at path into compressionClient and
// returns storage deltas measured from system.parts snapshots. It is shared
// between TestCompressionRatio and TestCompressionRegression.
func measureCompression(t *testing.T, ctx context.Context, path string) compressionMeasure {
	t.Helper()
	pcapData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	beforeByTable, beforeC, beforeU := storageSnapshot(t, ctx)
	ingestPCAP(t, ctx, pcapData)
	afterByTable, afterC, afterU := storageSnapshot(t, ctx)

	delta := make(map[string]tableBytes, len(tables))
	for _, tbl := range tables {
		delta[tbl] = tableBytes{
			compressed:   afterByTable[tbl].compressed - beforeByTable[tbl].compressed,
			uncompressed: afterByTable[tbl].uncompressed - beforeByTable[tbl].uncompressed,
		}
	}
	refSz, refMethod := compressedSize(pcapData)
	return compressionMeasure{
		FileBytes:       uint64(len(pcapData)),
		RefBytes:        refSz,
		RefMethod:       refMethod,
		LogicalBytes:    afterU - beforeU,
		CompressedBytes: afterC - beforeC,
		ByTableDelta:    delta,
	}
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
			m := measureCompression(t, ctx, path)

			chVsFile := m.ChVsFileRatio()
			internal := float64(m.LogicalBytes) / float64(m.CompressedBytes)
			vsRef := float64(m.CompressedBytes) / float64(m.RefBytes)

			t.Logf("PCAP file:                  %s", fmtBytes(m.FileBytes))
			t.Logf("%s compressed:       %s  (%.2fx file)", m.RefMethod, fmtBytes(m.RefBytes), float64(m.RefBytes)/float64(m.FileBytes))
			t.Logf("ClickHouse logical size:    %s  (%.2fx file)", fmtBytes(m.LogicalBytes), float64(m.LogicalBytes)/float64(m.FileBytes))
			t.Logf("ClickHouse compressed size: %s  (%.2fx file)", fmtBytes(m.CompressedBytes), chVsFile)
			t.Logf("Internal compress ratio:    %.2fx  (logical → disk)", internal)
			t.Logf("vs %s:              %.2fx", m.RefMethod, vsRef)

			t.Logf("%-22s  %10s  %10s  %8s  %8s  %8s",
				"Table", "Logical", "Compressed", "Ratio", "%Logical", "%Compr")
			for _, tbl := range tables {
				d := m.ByTableDelta[tbl]
				if d.uncompressed == 0 && d.compressed == 0 {
					continue
				}
				ratio := float64(d.uncompressed) / float64(d.compressed)
				pctU := 100 * float64(d.uncompressed) / float64(m.LogicalBytes)
				pctC := 100 * float64(d.compressed) / float64(m.CompressedBytes)
				t.Logf("  %-20s  %10s  %10s  %7.2fx  %7.1f%%  %7.1f%%",
					tbl, fmtBytes(d.uncompressed), fmtBytes(d.compressed), ratio, pctU, pctC)
				_ = tableCSV.Write([]string{
					filepath.Base(path), tbl,
					fmt.Sprintf("%d", d.uncompressed),
					fmt.Sprintf("%d", d.compressed),
					fmt.Sprintf("%.4f", ratio),
					fmt.Sprintf("%.4f", pctU),
					fmt.Sprintf("%.4f", pctC),
				})
			}

			_ = compressionCSV.Write([]string{
				filepath.Base(path),
				fmt.Sprintf("%d", m.FileBytes),
				m.RefMethod,
				fmt.Sprintf("%d", m.RefBytes),
				fmt.Sprintf("%d", m.LogicalBytes),
				fmt.Sprintf("%d", m.CompressedBytes),
				fmt.Sprintf("%.4f", chVsFile),
				fmt.Sprintf("%.4f", internal),
				fmt.Sprintf("%.4f", vsRef),
			})
		})
	}
}

// TestParseRatio ingests each PCAP in testdata/ and reports what fraction of
// packets were fully parsed into component tables versus stored as raw frame
// fallback bytes in pcap_packets.payload.
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
				SELECT count(), countIf(length(payload) > 0)
				FROM `+"`caphouse_compression`.`pcap_packets`"+` FINAL
				WHERE session_id = ?`, captureID)
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
