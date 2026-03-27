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

// ingestAll ingests pcapData as filename and returns the derived session ID.
func ingestAll(ctx context.Context, t *testing.T, pcapData []byte, filename string) uint64 {
	t.Helper()
	sessionID := stableSessionID(filename, pcapData)
	if _, err := cliClient.IngestPCAPStream(ctx, bytes.NewReader(pcapData), sessionID, "test", func() {}); err != nil {
		t.Fatalf("ingestAll %q: %v", filename, err)
	}
	return sessionID
}

// crashAfter ingests the first n packets from pcapData without flushing,
// simulating a process crash before the batch is sent to ClickHouse.
func crashAfter(ctx context.Context, t *testing.T, pcapData []byte, filename string, n int) uint64 {
	t.Helper()
	sessionID := stableSessionID(filename, pcapData)

	meta, err := caphouse.ParseGlobalHeader(pcapData[:24])
	if err != nil {
		t.Fatalf("crashAfter %q: parse header: %v", filename, err)
	}
	meta.SessionID = sessionID
	meta.SensorID = "test"
	meta.GlobalHeaderRaw = pcapData[:24]

	if _, err := cliClient.CreateCapture(ctx, meta); err != nil {
		t.Fatalf("crashAfter %q: create capture: %v", filename, err)
	}

	reader, err := pcapgo.NewReader(bytes.NewReader(pcapData))
	if err != nil {
		t.Fatalf("crashAfter %q: pcapgo reader: %v", filename, err)
	}
	var seq uint32
	for i := 0; i < n; i++ {
		frame, ci, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("crashAfter %q: read packet: %v", filename, err)
		}
		if err := cliClient.IngestPacket(ctx, meta.LinkType, caphouse.Packet{
			SessionID: sessionID,
			PacketID:  seq,
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
	return sessionID
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
			sessionID := ingestAll(ctx, t, pcapData, name)
			ingestAll(ctx, t, pcapData, name)

			rc, _, err := cliClient.Export(ctx, caphouse.ExportOpts{SessionID: &sessionID})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("export read: %v", err)
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
			crashAfter(ctx, t, pcapData, name, total/2)
			sessionID := ingestAll(ctx, t, pcapData, name)

			rc, _, err := cliClient.Export(ctx, caphouse.ExportOpts{SessionID: &sessionID})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("export read: %v", err)
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
			crashAfter(ctx, t, pcapData, name, total/2)
			if err := cliClient.Flush(ctx); err != nil {
				t.Fatalf("flush: %v", err)
			}
			sessionID := ingestAll(ctx, t, pcapData, name)

			rc, _, err := cliClient.Export(ctx, caphouse.ExportOpts{SessionID: &sessionID})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("export read: %v", err)
			}
			compareParsed(t, parsePackets(t, got), parsePackets(t, pcapData))
		})
	}
}

// TestE2EConcurrentRings splits each PCAP into 2 ring files and ingests them
// concurrently. Each ring is its own session; we export both and compare total.
func TestE2EConcurrentRings(t *testing.T) {
	ctx := context.Background()
	for _, path := range pcapPaths(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			pcapData, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			rings := splitPCAP(t, pcapData, 2)

			var mu sync.Mutex
			sessionIDs := make([]uint64, len(rings))
			var wg sync.WaitGroup
			for i, ring := range rings {
				wg.Add(1)
				i, ringData := i, ring
				ringName := fmt.Sprintf("ring%d.pcap", i)
				go func() {
					defer wg.Done()
					sid := ingestAll(ctx, t, ringData, ringName)
					mu.Lock()
					sessionIDs[i] = sid
					mu.Unlock()
				}()
			}
			wg.Wait()

			var gotPkts []parsedPkt
			for _, sid := range sessionIDs {
				rc, _, err := cliClient.Export(ctx, caphouse.ExportOpts{SessionID: &sid})
				if err != nil {
					t.Fatalf("export session %d: %v", sid, err)
				}
				data, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					t.Fatalf("export read session %d: %v", sid, err)
				}
				gotPkts = append(gotPkts, parsePackets(t, data)...)
			}
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
// caphouse-monitor does) and ingests each as its own session.
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

			var gotPkts []parsedPkt
			for i, ring := range rings {
				ringName := fmt.Sprintf("ring%d.pcap", i)
				sid := ingestAll(ctx, t, ring, ringName)
				rc, _, err := cliClient.Export(ctx, caphouse.ExportOpts{SessionID: &sid})
				if err != nil {
					t.Fatalf("export ring %d: %v", i, err)
				}
				data, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					t.Fatalf("export ring read %d: %v", i, err)
				}
				gotPkts = append(gotPkts, parsePackets(t, data)...)
			}
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
