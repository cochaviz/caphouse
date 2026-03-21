// Package caphouse stores and queries classic PCAP captures in ClickHouse.
//
// # Architecture
//
// Instead of storing raw frames as opaque blobs, caphouse decomposes each
// packet into its protocol layers and writes each layer to a dedicated
// ClickHouse table. This gives ClickHouse homogeneous columns — narrow integer
// and fixed-byte fields — that compress and scan far more efficiently than raw
// frame data, while still allowing lossless PCAP reconstruction on export.
//
// The storage model has three tiers:
//
//   - pcap_captures — one row per capture session (link type, snaplen,
//     creation time, codec version).
//   - pcap_packets — one row per packet (timestamp offset from capture start,
//     lengths, component bitmask, raw tail bytes for unrecognised payload).
//   - pcap_<protocol> — one row per packet per layer (e.g. pcap_ethernet,
//     pcap_ipv4, pcap_tcp). Each table is managed by a [components.Component].
//
// Stream-level data (TCP sessions, HTTP reconstructions) is stored separately
// in stream_captures and stream_http.
//
// # Typical usage
//
// Create a client, initialise the schema once, then ingest and export:
//
//	c, err := caphouse.New(ctx, caphouse.Config{
//	    DSN: "clickhouse://user:pass@localhost:9000/default",
//	})
//	if err != nil { ... }
//	defer c.Close()
//
//	if err := c.InitSchema(ctx); err != nil { ... }
//
//	// Ingest a PCAP or PCAPng file
//	f, _ := os.Open("capture.pcap")
//	captureID, err := c.IngestPCAPStream(ctx, f, uuid.Nil, "sensor1", 0, nil)
//
//	// Export the capture back as a PCAP stream
//	rc, err := c.ExportCapture(ctx, captureID)
//	defer rc.Close()
//	io.Copy(out, rc)
//
//	// Filter and export
//	q, _ := query.ParseQuery("host 10.0.0.1 and port 443")
//	rc, total, err := c.ExportCaptureFiltered(ctx, captureID, q, nil)
//
//	// Merge all captures within a time window
//	q, _ := query.ParseQuery("time 2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z")
//	rc, total, err := c.ExportAllCapturesFiltered(ctx, q, nil)
//
// # Ingest pipeline
//
// [Client.IngestPCAPStream] is the primary ingest entry point. It:
//  1. Sniffs the first four bytes to detect classic PCAP vs PCAPng.
//  2. Calls [Client.CreateCapture] to register the capture (idempotent).
//  3. Reads packets in a loop, calling [Client.IngestPacket] for each one.
//  4. Flushes the batch buffer and finalises TCP streams via [Client.FinalizeStreams].
//
// Packets are buffered and sent to ClickHouse in batches (default 1 000
// packets or 1 s, whichever comes first). Failed batches are retried with
// exponential backoff up to five attempts before the error is returned.
//
// Packet timestamps are stored as nanosecond offsets from the capture's
// CreatedAt time (derived from the first packet) rather than as absolute
// timestamps. This keeps the ts column small and ensures offsets are always
// non-negative for archived captures.
//
// # Query and export pipeline
//
// Filter expressions follow a tcpdump-style syntax parsed by [query.ParseQuery].
// The resulting [query.Query] is compiled into a ClickHouse subquery by each node in
// the AST and executed via INTERSECT / UNION DISTINCT / EXCEPT set operations.
// [Client.GenerateSQL] and [Client.GenerateSQLForCaptures] render the same
// query as a human-readable SELECT for inspection or further customisation.
//
// Export methods reconstruct the original frame bytes from the stored columns
// and stream them as a valid classic PCAP. The reconstruction path is the
// inverse of ingest: each [components.Component] serialises its fields back
// into a gopacket SerializableLayer, which is then serialised to bytes.
//
// # Schema management
//
// Call [Client.InitSchema] once before the first ingest. It creates the
// database and all tables (captures, packets, every registered component table,
// and stream tables) using CREATE TABLE IF NOT EXISTS, so it is safe to call
// on every startup. See schema.go for the table layout and codec conventions.
//
// For the full public API see https://pkg.go.dev/github.com/cochaviz/caphouse.
package caphouse
