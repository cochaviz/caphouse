//go:build e2e

package caphouse

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
)

func TestStorageUsageBytesIgnoresUnmanagedTables(t *testing.T) {
	ctx := context.Background()
	dbName := retentionTestDBName(t)
	client := newRetentionTestClient(t, ctx, dbName, 0)
	defer closeRetentionTestClient(t, ctx, client)

	usage, err := client.storageUsageBytes(ctx)
	if err != nil {
		t.Fatalf("storageUsageBytes: %v", err)
	}
	if usage != 0 {
		t.Fatalf("initial usage: got %d want 0", usage)
	}

	table := client.tableRef("unmanaged_payloads")
	if err := client.conn.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (payload String) ENGINE = MergeTree ORDER BY tuple()", table)); err != nil {
		t.Fatalf("create unmanaged table: %v", err)
	}
	payload := make([]byte, 32<<10)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := client.conn.Exec(ctx, fmt.Sprintf("INSERT INTO %s (payload) VALUES (?)", table), string(payload)); err != nil {
		t.Fatalf("insert unmanaged payload: %v", err)
	}

	var unmanagedBytes uint64
	if err := client.conn.QueryRow(ctx, `
		SELECT toUInt64(ifNull(sum(data_compressed_bytes), 0))
		FROM system.parts
		WHERE database = ? AND table = 'unmanaged_payloads' AND active = 1`,
		dbName,
	).Scan(&unmanagedBytes); err != nil {
		t.Fatalf("query unmanaged table bytes: %v", err)
	}
	if unmanagedBytes == 0 {
		t.Fatal("expected unmanaged table to occupy disk bytes")
	}

	usage, err = client.storageUsageBytes(ctx)
	if err != nil {
		t.Fatalf("storageUsageBytes after unmanaged insert: %v", err)
	}
	if usage != 0 {
		t.Fatalf("managed usage should ignore unmanaged tables: got %d want 0", usage)
	}
}

func TestRetentionPrunesOldestCapture(t *testing.T) {
	ctx := context.Background()
	dbName := retentionTestDBName(t)

	firstClient := newRetentionTestClient(t, ctx, dbName, 0)
	defer closeRetentionTestClient(t, ctx, firstClient)

	// Use timestamps on different days so the two sessions land in different
	// partitions; the pruner must drop the old partition without touching the new one.
	oldSession := retentionSessionID("old", dbName)
	oldPCAP := buildHTTPPCAP(t, time.Unix(1_700_000_000, 0), "old.example", 8<<10) // 2023-11-14
	if _, err := firstClient.IngestPCAPStream(ctx, bytes.NewReader(oldPCAP), oldSession, "test", nil); err != nil {
		t.Fatalf("ingest old capture: %v", err)
	}
	insertSyntheticHTTPStreamRows(t, ctx, firstClient, oldSession, "old.example")

	oldCounts := sessionRowCounts(t, ctx, firstClient, oldSession)
	if oldCounts["stream_captures"] == 0 || oldCounts["stream_http"] == 0 {
		t.Fatalf("expected old capture to populate stream tables, got %+v", oldCounts)
	}
	oldUsage, err := firstClient.storageUsageBytes(ctx)
	if err != nil {
		t.Fatalf("measure old usage: %v", err)
	}

	secondClient := newRetentionTestClient(t, ctx, dbName, oldUsage-1)
	defer closeRetentionTestClient(t, ctx, secondClient)

	newSession := retentionSessionID("new", dbName)
	newPCAP := buildHTTPPCAP(t, time.Unix(1_700_200_000, 0), "new.example", 8<<10) // 2023-11-17 (different day)
	if _, err := secondClient.IngestPCAPStream(ctx, bytes.NewReader(newPCAP), newSession, "test", nil); err != nil {
		t.Fatalf("ingest new capture: %v", err)
	}

	// Lightweight deletes reclaim space lazily (background merge), so we
	// verify row-level deletion rather than physical byte counts.
	if got := sessionRowCounts(t, ctx, secondClient, oldSession); totalRows(got) != 0 {
		t.Fatalf("expected old session to be deleted, got counts %+v", got)
	}
	newCounts := sessionRowCounts(t, ctx, secondClient, newSession)
	for _, table := range []string{"pcap_captures", "pcap_packets", "pcap_ethernet", "pcap_ipv4", "pcap_tcp"} {
		if newCounts[table] == 0 {
			t.Fatalf("expected new session rows in %s, got counts %+v", table, newCounts)
		}
	}
}

func TestRetentionNoPruneWhenUnderCap(t *testing.T) {
	ctx := context.Background()
	dbName := retentionTestDBName(t)
	client := newRetentionTestClient(t, ctx, dbName, 1<<30)
	defer closeRetentionTestClient(t, ctx, client)

	sessionID := retentionSessionID("single", dbName)
	pcapData := buildHTTPPCAP(t, time.Unix(1_700_010_000, 0), "single.example", 4<<10)
	if _, err := client.IngestPCAPStream(ctx, bytes.NewReader(pcapData), sessionID, "test", nil); err != nil {
		t.Fatalf("ingest capture: %v", err)
	}

	counts := sessionRowCounts(t, ctx, client, sessionID)
	for _, table := range []string{"pcap_captures", "pcap_packets", "pcap_ethernet", "pcap_ipv4", "pcap_tcp"} {
		if counts[table] == 0 {
			t.Fatalf("expected session rows in %s, got %+v", table, counts)
		}
	}
}

func TestRetentionKeepsOversizedNewestCapture(t *testing.T) {
	ctx := context.Background()
	dbName := retentionTestDBName(t)
	client := newRetentionTestClient(t, ctx, dbName, 1)
	defer closeRetentionTestClient(t, ctx, client)

	sessionID := retentionSessionID("oversized", dbName)
	pcapData := buildHTTPPCAP(t, time.Unix(1_700_020_000, 0), "oversized.example", 16<<10)
	if _, err := client.IngestPCAPStream(ctx, bytes.NewReader(pcapData), sessionID, "test", nil); err != nil {
		t.Fatalf("ingest oversized capture: %v", err)
	}

	counts := sessionRowCounts(t, ctx, client, sessionID)
	if totalRows(counts) == 0 {
		t.Fatalf("expected oversized newest capture to be retained, got %+v", counts)
	}

	usage, err := client.storageUsageBytes(ctx)
	if err != nil {
		t.Fatalf("measure oversized usage: %v", err)
	}
	if usage <= client.cfg.MaxStorageBytes {
		t.Fatalf("expected usage to remain above cap for oversized newest capture: used=%d cap=%d", usage, client.cfg.MaxStorageBytes)
	}
}

func TestRetentionPrunesBeforeAppend(t *testing.T) {
	ctx := context.Background()
	dbName := retentionTestDBName(t)

	// Ingest two sessions on different days so they land in different partitions.
	baseClient := newRetentionTestClient(t, ctx, dbName, 0)
	defer closeRetentionTestClient(t, ctx, baseClient)

	olderSession := retentionSessionID("older", dbName)
	olderPCAP := buildHTTPPCAP(t, time.Unix(1_700_030_000, 0), "older.example", 8<<10) // older day
	if _, err := baseClient.IngestPCAPStream(ctx, bytes.NewReader(olderPCAP), olderSession, "test", nil); err != nil {
		t.Fatalf("ingest older capture: %v", err)
	}

	newerSession := retentionSessionID("newer", dbName)
	newerPCAP := buildHTTPPCAP(t, time.Unix(1_700_200_000, 0), "newer.example", 8<<10) // newer day
	if _, err := baseClient.IngestPCAPStream(ctx, bytes.NewReader(newerPCAP), newerSession, "test", nil); err != nil {
		t.Fatalf("ingest newer capture: %v", err)
	}

	usage, err := baseClient.storageUsageBytes(ctx)
	if err != nil {
		t.Fatalf("measure usage: %v", err)
	}

	// Create a client with a cap already exceeded — pruning fires before the next ingest.
	appendClient := newRetentionTestClient(t, ctx, dbName, usage-1)
	defer closeRetentionTestClient(t, ctx, appendClient)

	appendFrame := buildTCPFrame(t,
		net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		net.IP{192, 0, 2, 1},
		net.IP{198, 51, 100, 1},
		12345, 80,
		false, true, true,
		1001, 2001,
		[]byte("GET /append HTTP/1.1\r\nHost: newer.example\r\n\r\n"),
	)
	if err := appendClient.IngestPacket(ctx, uint32(layers.LinkTypeEthernet), Packet{
		SessionID: newerSession,
		PacketID:  99,
		Timestamp: time.Unix(1_700_200_010, 0),
		InclLen:   uint32(len(appendFrame)),
		OrigLen:   uint32(len(appendFrame)),
		Frame:     appendFrame,
	}); err != nil {
		t.Fatalf("append packet: %v", err)
	}
	if err := appendClient.Flush(ctx); err != nil {
		t.Fatalf("flush append: %v", err)
	}
	if err := appendClient.FinalizeStreams(ctx); err != nil {
		t.Fatalf("finalize append streams: %v", err)
	}

	// The older session (in the older partition) should have been pruned before
	// the append was written; the newer session must be intact.
	if got := sessionRowCounts(t, ctx, appendClient, olderSession); totalRows(got) != 0 {
		t.Fatalf("expected older session to be pruned, got %+v", got)
	}
	newerCounts := sessionRowCounts(t, ctx, appendClient, newerSession)
	if totalRows(newerCounts) == 0 {
		t.Fatalf("expected newer session to be intact after pruning, got %+v", newerCounts)
	}
}

func newRetentionTestClient(t *testing.T, ctx context.Context, dbName string, maxStorageBytes uint64) *Client {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := integrationClient.conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", quoteIdent(dbName))); err != nil {
		t.Fatalf("create database %s: %v", dbName, err)
	}
	client, err := New(ctx, Config{
		DSN:             integrationClient.cfg.DSN,
		Database:        dbName,
		BatchSize:       50_000,
		MaxStorageBytes: maxStorageBytes,
		Logger:          logger,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.InitSchema(ctx); err != nil {
		client.Close()
		t.Fatalf("init schema: %v", err)
	}
	return client
}

func closeRetentionTestClient(t *testing.T, ctx context.Context, client *Client) {
	t.Helper()
	if client == nil {
		return
	}
	dbName := client.cfg.Database
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	adminClient, err := New(ctx, Config{
		DSN:      integrationClient.cfg.DSN,
		Database: integrationClient.cfg.Database,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new admin client: %v", err)
	}
	defer adminClient.Close()
	if err := adminClient.conn.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s", quoteIdent(dbName))); err != nil {
		t.Fatalf("drop database %s: %v", dbName, err)
	}
}

func retentionTestDBName(t *testing.T) string {
	t.Helper()
	name := strings.ToLower(t.Name())
	name = strings.NewReplacer("/", "_", "-", "_").Replace(name)
	return fmt.Sprintf("retention_%s", name)
}

func retentionSessionID(prefix, dbName string) uint64 {
	sum := sha256.Sum256([]byte(prefix + ":" + dbName))
	return uint64(sum[0])<<56 | uint64(sum[1])<<48 | uint64(sum[2])<<40 | uint64(sum[3])<<32 |
		uint64(sum[4])<<24 | uint64(sum[5])<<16 | uint64(sum[6])<<8 | uint64(sum[7])
}

func sessionRowCounts(t *testing.T, ctx context.Context, client *Client, sessionID uint64) map[string]uint64 {
	t.Helper()
	out := make(map[string]uint64, len(client.managedTableNames()))
	for _, table := range client.managedTableNames() {
		var count uint64
		query := fmt.Sprintf("SELECT toUInt64(count()) FROM %s WHERE session_id = ?", client.tableRef(table))
		if err := client.conn.QueryRow(ctx, query, sessionID).Scan(&count); err != nil {
			t.Fatalf("count rows for %s: %v", table, err)
		}
		out[table] = count
	}
	return out
}

func totalRows(counts map[string]uint64) uint64 {
	var total uint64
	for _, count := range counts {
		total += count
	}
	return total
}

func insertSyntheticHTTPStreamRows(t *testing.T, ctx context.Context, client *Client, sessionID uint64, host string) {
	t.Helper()

	streamID := uuid.New()
	if err := client.conn.Exec(ctx, fmt.Sprintf(
		"INSERT INTO %s (session_id, stream_id, l7_proto, proto, src_ip, dst_ip, src_port, dst_port, is_complete, first_packet_id, last_packet_id, packet_count, byte_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		client.streamCapturesTable(),
	),
		sessionID, streamID, "HTTP", uint8(6),
		"::ffff:192.0.2.1", "::ffff:198.51.100.1",
		uint16(12345), uint16(80),
		true, uint32(0), uint32(2),
		uint64(3), uint64(8192),
	); err != nil {
		t.Fatalf("insert stream_captures row: %v", err)
	}

	if err := client.conn.Exec(ctx, fmt.Sprintf(
		"INSERT INTO %s (session_id, stream_id, method, host, path) VALUES (?, ?, ?, ?, ?)",
		client.streamHTTPTable(),
	),
		sessionID, streamID, "GET", host, "/",
	); err != nil {
		t.Fatalf("insert stream_http row: %v", err)
	}
}

func buildHTTPPCAP(t *testing.T, start time.Time, host string, padSize int) []byte {
	t.Helper()
	payload := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host))
	if padSize > 0 {
		padding := make([]byte, padSize)
		for i := range padding {
			padding[i] = byte('a' + (i % 26))
		}
		payload = append(payload, padding...)
	}

	frames := []struct {
		ts    time.Time
		frame []byte
	}{
		{
			ts: start,
			frame: buildTCPFrame(t,
				net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
				net.IP{192, 0, 2, 1},
				net.IP{198, 51, 100, 1},
				12345, 80,
				true, false, false,
				1000, 0,
				nil,
			),
		},
		{
			ts: start.Add(time.Millisecond),
			frame: buildTCPFrame(t,
				net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
				net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				net.IP{198, 51, 100, 1},
				net.IP{192, 0, 2, 1},
				80, 12345,
				true, true, false,
				2000, 1001,
				nil,
			),
		},
		{
			ts: start.Add(2 * time.Millisecond),
			frame: buildTCPFrame(t,
				net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
				net.IP{192, 0, 2, 1},
				net.IP{198, 51, 100, 1},
				12345, 80,
				false, true, true,
				1001, 2001,
				payload,
			),
		},
	}

	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	for _, frame := range frames {
		ci := gopacket.CaptureInfo{
			Timestamp:     frame.ts,
			CaptureLength: len(frame.frame),
			Length:        len(frame.frame),
		}
		if err := writer.WritePacket(ci, frame.frame); err != nil {
			t.Fatalf("write pcap packet: %v", err)
		}
	}
	return buf.Bytes()
}

func buildTCPFrame(
	t *testing.T,
	srcMAC net.HardwareAddr,
	dstMAC net.HardwareAddr,
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	syn bool,
	ackFlag bool,
	psh bool,
	seq uint32,
	ack uint32,
	payload []byte,
) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		SYN:     syn,
		ACK:     ackFlag,
		PSH:     psh,
		Window:  64240,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set checksum network layer: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	layersToSerialize := []gopacket.SerializableLayer{eth, ip4, tcp}
	if len(payload) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(payload))
	}
	if err := gopacket.SerializeLayers(buf, serializeOpts, layersToSerialize...); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}
