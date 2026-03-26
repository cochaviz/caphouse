// Package components defines the protocol-layer decomposition at the heart of
// caphouse's columnar storage model.
//
// # Overview
//
// Instead of storing raw packet frames as opaque blobs, caphouse parses each
// frame into its constituent protocol layers and stores each layer in its own
// ClickHouse table. This makes packet data queryable at the column level while
// still allowing lossless PCAP reconstruction via [ReconstructFrame].
//
// The central abstraction is the [Component] interface, which every protocol
// layer must implement. A Component knows how to:
//
//   - Encode a gopacket layer into ClickHouse-ready fields (INSERT path).
//   - Reconstruct its bytes into a gopacket SerializableLayer (export path).
//   - Describe its ClickHouse schema, column list, and scan order.
//
// The [PacketNucleus] struct is the primary row in pcap_packets. It holds
// per-packet metadata (timestamps, lengths, component bitmask) shared by all
// layer components. Each component receives a copy of the nucleus via
// [LayerDecoder.ApplyNucleus] so it can store the (capture_id, packet_id) key.
//
// # Component kinds and order
//
// Each component has a numeric kind constant (ComponentEthernet, ComponentIPv4,
// etc.) and an order constant (OrderL2Base, OrderL3Base, …) that determines
// decode order. The bitmask in PacketNucleus.Components records which kinds
// are present for a given packet. Use [ComponentHas] to test the mask.
//
// Some orders are repeatable (e.g. OrderL2Tag for 802.1Q stacking,
// OrderL3Ext for IPv6 extension headers); see [OrderRepeatable].
//
// # Registries
//
// [ComponentFactories] maps each kind constant to a zero-value constructor.
// It is the authoritative list of all registered components and is used
// throughout caphouse to build schema, drive batch inserts, and generate SQL.
//
// [LayerEncoders] maps gopacket LayerType values to the Component that handles
// encoding for that layer. It is used during ingest to select the right encoder
// for each layer returned by gopacket.
//
// # Creating a new component
//
// To add support for a new protocol layer:
//
//  1. Define a struct with exported fields tagged with `ch:"column_name"`.
//     Embed CaptureID, PacketID, and CodecVersion as the first three fields —
//     these are required by the schema conventions:
//
//     type MyComponent struct {
//     CaptureID    uuid.UUID `ch:"capture_id"`
//     PacketID     uint64    `ch:"packet_id"`
//     CodecVersion uint16    `ch:"codec_version"`
//     // ... protocol fields
//     }
//
//  2. Implement the [Component] interface. The ClickHouse column/value methods
//     can delegate to [GetClickhouseColumnsFrom] and [GetClickhouseValuesFrom],
//     which use struct field tags via reflection:
//
//     func (c *MyComponent) ClickhouseColumns() ([]string, error) {
//     return GetClickhouseColumnsFrom(c)
//     }
//     func (c *MyComponent) ClickhouseValues() ([]any, error) {
//     return GetClickhouseValuesFrom(c)
//     }
//
//  3. Write the ClickHouse schema as an embedded SQL file
//     (e.g. my_schema.sql) and expose it via Schema():
//
//     //go:embed my_schema.sql
//     var mySchemaSQL string
//
//     func (c *MyComponent) Schema(table string) string {
//     return applySchema(mySchemaSQL, table)
//     }
//
//  4. Register the component in [ComponentFactories] and [LayerEncoders]:
//
//     // In types.go, add a kind constant:
//     ComponentMyProto uint = iota
//
//     // In registry.go, add to LayerEncoders:
//     layers.LayerTypeXxx: &MyComponent{},
//
//     // In types.go, add to ComponentFactories:
//     ComponentMyProto: func() Component { return &MyComponent{} },
//
// The new component will be automatically picked up by schema initialisation,
// batch ingest, SQL generation, and packet reconstruction.
//
// # Compression
//
// Splitting frames into narrow, homogeneous columns is what makes ClickHouse
// compression effective: each column contains values of the same type and
// similar range, so delta-encoding and LZ4/ZSTD can compress them far more
// aggressively than a raw frame blob. When designing a new component, prefer
// narrow integer fields and avoid storing redundant data that is already
// present in another component (e.g. do not re-store the Ethernet type in an
// IPv4 component).
//
// Compression ratios per table and column can be measured with the
// `compression` build tag:
//
//	go test -v -tags compression ./...
//
// See the "Working with Compression" section of the development docs for the
// ClickHouse query used to inspect per-column ratios and a worked example for
// the pcap_ethernet table.
package components
