//go:build e2e

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"caphouse"

	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	tccontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

var cliClient *caphouse.Client

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

	cliClient, err = caphouse.New(ctx, caphouse.Config{
		DSN:       dsn,
		Database:  "caphouse_e2e",
		BatchSize: 50000,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create client: %v\n", err)
		os.Exit(1)
	}
	defer cliClient.Close()

	if err := cliClient.InitSchema(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "init schema: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// --- helpers -----------------------------------------------------------------

type parsedPkt struct {
	ts   time.Time
	data []byte
}

func parsePackets(t *testing.T, data []byte) []parsedPkt {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parsePackets: new reader: %v", err)
	}
	var pkts []parsedPkt
	for {
		frame, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("parsePackets: read: %v", err)
		}
		pkts = append(pkts, parsedPkt{ts: ci.Timestamp, data: frame})
	}
	return pkts
}

func compareParsed(t *testing.T, got, want []parsedPkt) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("packet count: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].data, want[i].data) {
			t.Fatalf("packet %d data mismatch", i)
		}
		gotUs := got[i].ts.Unix()*1_000_000 + int64(got[i].ts.Nanosecond()/1000)
		wantUs := want[i].ts.Unix()*1_000_000 + int64(want[i].ts.Nanosecond()/1000)
		if gotUs != wantUs {
			t.Fatalf("packet %d timestamp mismatch: got %v want %v", i, got[i].ts, want[i].ts)
		}
	}
}

// splitPCAP distributes packets round-robin across n PCAP files, each carrying
// the original global header.
func splitPCAP(t *testing.T, data []byte, n int) [][]byte {
	t.Helper()
	globalHdr := data[:24]
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("splitPCAP: reader: %v", err)
	}
	type raw struct {
		ts      time.Time
		inclLen uint32
		origLen uint32
		frame   []byte
	}
	var all []raw
	for {
		frame, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("splitPCAP: read: %v", err)
		}
		all = append(all, raw{ci.Timestamp, uint32(ci.CaptureLength), uint32(ci.Length), frame})
	}
	results := make([][]byte, n)
	for i := range n {
		var buf bytes.Buffer
		buf.Write(globalHdr)
		for j := i; j < len(all); j += n {
			p := all[j]
			var hdr [16]byte
			binary.LittleEndian.PutUint32(hdr[0:4], uint32(p.ts.Unix()))
			binary.LittleEndian.PutUint32(hdr[4:8], uint32(p.ts.Nanosecond()/1000))
			binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(p.frame)))
			binary.LittleEndian.PutUint32(hdr[12:16], p.origLen)
			buf.Write(hdr[:])
			buf.Write(p.frame)
		}
		results[i] = buf.Bytes()
	}
	return results
}

// ingestPCAPStream is a thin wrapper around the client method that threads an
// ingestProgress counter through the onPacket callback.
func ingestPCAPStream(ctx context.Context, client *caphouse.Client, r io.Reader, captureID uuid.UUID, sensor string, p *ingestProgress, base uint64) (uuid.UUID, error) {
	return client.IngestPCAPStream(ctx, r, captureID, sensor, base, func() { p.packets.Add(1) })
}

// ingestAll ingests pcapData under captureID using the real CLI ingestPCAPStream.
func ingestAll(ctx context.Context, t *testing.T, captureID uuid.UUID, pcapData []byte, filename string) {
	t.Helper()
	base := stablePacketIDBase(filename, pcapData)
	if _, err := ingestPCAPStream(ctx, cliClient, bytes.NewReader(pcapData), captureID, "test", &ingestProgress{}, base); err != nil {
		t.Fatalf("ingestAll %q: %v", filename, err)
	}
}

// crashAfter ingests the first n packets from pcapData without flushing,
// simulating a process crash before the batch is sent to ClickHouse.
func crashAfter(ctx context.Context, t *testing.T, captureID uuid.UUID, pcapData []byte, filename string, n int) {
	t.Helper()
	base := stablePacketIDBase(filename, pcapData)

	meta, err := caphouse.ParseGlobalHeader(pcapData[:24])
	if err != nil {
		t.Fatalf("crashAfter %q: parse header: %v", filename, err)
	}
	meta.CaptureID = captureID
	meta.SensorID = "test"
	meta.CreatedAt = parsePackets(t, pcapData)[0].ts // anchor to first packet, matching IngestPCAPStream
	meta.GlobalHeaderRaw = pcapData[:24]

	if _, err := cliClient.CreateCapture(ctx, meta); err != nil {
		t.Fatalf("crashAfter %q: create capture: %v", filename, err)
	}

	reader, err := pcapgo.NewReader(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("crashAfter %q: pcapgo reader: %v", filename, err)
	}
	var seq uint64
	for i := 0; i < n; i++ {
		frame, ci, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("crashAfter %q: read packet: %v", filename, err)
		}
		if err := cliClient.IngestPacket(ctx, meta.LinkType, caphouse.Packet{
			CaptureID: captureID,
			PacketID:  base | seq,
			Timestamp: ci.Timestamp,
			InclLen:   uint32(ci.CaptureLength),
			OrigLen:   uint32(ci.Length),
			Frame:     frame,
		}); err != nil {
			t.Fatalf("crashAfter %q: ingest packet %d: %v", filename, seq, err)
		}
		seq++
	}
	// Intentionally no Flush — simulates crash.
}

// pcapPaths returns all *.pcap files under testdata/ relative to this package.
func pcapPaths(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("../../testdata/*.pcap")
	if err != nil {
		t.Fatalf("glob testdata: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no pcap files found in testdata/")
	}
	return paths
}

// --- tests -------------------------------------------------------------------

// TestE2EDuplicateIngest ingests each PCAP twice and verifies deduplication.
func TestE2EDuplicateIngest(t *testing.T) {
	ctx := context.Background()
	for _, path := range pcapPaths(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			pcapData, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			name := filepath.Base(path)
			captureID := uuid.New()
			ingestAll(ctx, t, captureID, pcapData, name)
			ingestAll(ctx, t, captureID, pcapData, name)

			got, err := cliClient.ExportCaptureBytes(ctx, captureID)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			compareParsed(t, parsePackets(t, got), parsePackets(t, pcapData))
		})
	}
}

// TestE2EPartialCrashResume simulates dropping the unflushed batch on crash,
// then completing the ingest. Export must match the original.
func TestE2EPartialCrashResume(t *testing.T) {
	ctx := context.Background()
	for _, path := range pcapPaths(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			pcapData, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			name := filepath.Base(path)
			total := len(parsePackets(t, pcapData))
			if total < 2 {
				t.Skip("need at least 2 packets")
			}
			captureID := uuid.New()
			crashAfter(ctx, t, captureID, pcapData, name, total/2)
			ingestAll(ctx, t, captureID, pcapData, name)

			got, err := cliClient.ExportCaptureBytes(ctx, captureID)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			compareParsed(t, parsePackets(t, got), parsePackets(t, pcapData))
		})
	}
}

// TestE2EFlushBeforeCrash flushes the partial batch before the crash,
// then re-ingests everything. Export must match after deduplication.
func TestE2EFlushBeforeCrash(t *testing.T) {
	ctx := context.Background()
	for _, path := range pcapPaths(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			pcapData, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			name := filepath.Base(path)
			total := len(parsePackets(t, pcapData))
			if total < 2 {
				t.Skip("need at least 2 packets")
			}
			captureID := uuid.New()
			crashAfter(ctx, t, captureID, pcapData, name, total/2)
			if err := cliClient.Flush(ctx); err != nil {
				t.Fatalf("flush: %v", err)
			}
			ingestAll(ctx, t, captureID, pcapData, name)

			got, err := cliClient.ExportCaptureBytes(ctx, captureID)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			compareParsed(t, parsePackets(t, got), parsePackets(t, pcapData))
		})
	}
}

// TestE2EConcurrentRings splits each PCAP into 2 ring files and ingests them
// concurrently under the same captureID.
func TestE2EConcurrentRings(t *testing.T) {
	ctx := context.Background()
	for _, path := range pcapPaths(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			pcapData, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			rings := splitPCAP(t, pcapData, 2)
			captureID := uuid.New()

			// Pre-create the capture anchored to the globally-earliest packet
			// timestamp (packet 0, always in ring 0 after round-robin split).
			// Without this, whichever ring wins the CreateCapture race sets
			// CreatedAt, and any ring with an earlier first packet would have
			// those packets clamped to tsOffsetNs=0 and exported with the
			// wrong timestamp.
			anchorMeta, err := caphouse.ParseGlobalHeader(pcapData[:24])
			if err != nil {
				t.Fatalf("parse header: %v", err)
			}
			anchorMeta.CaptureID = captureID
			anchorMeta.SensorID = "test"
			anchorMeta.CreatedAt = parsePackets(t, pcapData)[0].ts
			if _, err := cliClient.CreateCapture(ctx, anchorMeta); err != nil {
				t.Fatalf("pre-create capture: %v", err)
			}

			var wg sync.WaitGroup
			for i, ring := range rings {
				wg.Add(1)
				ringData := ring
				ringName := fmt.Sprintf("ring%d.pcap", i)
				go func() {
					defer wg.Done()
					ingestAll(ctx, t, captureID, ringData, ringName)
				}()
			}
			wg.Wait()

			got, err := cliClient.ExportCaptureBytes(ctx, captureID)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			gotPkts := parsePackets(t, got)
			wantPkts := parsePackets(t, pcapData)
			if len(gotPkts) != len(wantPkts) {
				t.Fatalf("packet count: got %d want %d", len(gotPkts), len(wantPkts))
			}
			sortPkts := func(ps []parsedPkt) {
				sort.Slice(ps, func(i, j int) bool {
					if ti, tj := ps[i].ts.UnixNano(), ps[j].ts.UnixNano(); ti != tj {
						return ti < tj
					}
					return bytes.Compare(ps[i].data, ps[j].data) < 0
				})
			}
			sortPkts(gotPkts)
			sortPkts(wantPkts)
			compareParsed(t, gotPkts, wantPkts)
		})
	}
}

// TestE2EMonitorRings splits each PCAP into 3 ring files (replicating what
// caphouse-monitor does) and ingests each under the same captureID.
func TestE2EMonitorRings(t *testing.T) {
	ctx := context.Background()
	for _, path := range pcapPaths(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			pcapData, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			const nRings = 3
			rings := splitPCAP(t, pcapData, nRings)
			captureID := uuid.New()

			for i, ring := range rings {
				ingestAll(ctx, t, captureID, ring, fmt.Sprintf("ring%d.pcap", i))
			}

			got, err := cliClient.ExportCaptureBytes(ctx, captureID)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			gotPkts := parsePackets(t, got)
			wantPkts := parsePackets(t, pcapData)
			if len(gotPkts) != len(wantPkts) {
				t.Fatalf("packet count: got %d want %d", len(gotPkts), len(wantPkts))
			}
			sortPkts := func(ps []parsedPkt) {
				sort.Slice(ps, func(i, j int) bool {
					if ti, tj := ps[i].ts.UnixNano(), ps[j].ts.UnixNano(); ti != tj {
						return ti < tj
					}
					return bytes.Compare(ps[i].data, ps[j].data) < 0
				})
			}
			sortPkts(gotPkts)
			sortPkts(wantPkts)
			compareParsed(t, gotPkts, wantPkts)
		})
	}
}
