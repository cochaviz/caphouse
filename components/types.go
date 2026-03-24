package components

import (
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
)

const (
	CodecVersionV1 uint16 = 1
	CodecProfileV1        = "nested-v1"
)

const (
	ComponentRawFrame uint = iota
	ComponentEthernet
	ComponentDot1Q
	ComponentLinuxSLL
	ComponentIPv4
	ComponentIPv6
	ComponentIPv6Ext
	ComponentHash
	ComponentTruncated
	ComponentTCP
	ComponentUDP
	ComponentDNS
	ComponentNTP
	ComponentARP
)

const (
	OrderL2Base uint = iota
	OrderL2Tag
	OrderL3Base
	OrderL3Ext
	OrderL4Base
	OrderL7Base
)

var KnownComponentKinds = []uint{
	ComponentEthernet,
	ComponentDot1Q,
	ComponentLinuxSLL,
	ComponentIPv4,
	ComponentIPv6,
	ComponentIPv6Ext,
	ComponentTCP,
	ComponentUDP,
	ComponentDNS,
	ComponentNTP,
	ComponentARP,
}

var OrderRepeatable = map[uint]bool{
	OrderL2Tag: true,
	OrderL3Ext: true,
}

// PacketNucleus represents the primary row in pcap_packets, holding per-packet metadata and the component bitmask.
type PacketNucleus struct {
	SessionID uint64
	PacketID  uint32
	Timestamp time.Time
	InclLen   uint32
	OrigLen   uint32

	Components *big.Int
	TailOffset uint16

	FrameRaw  []byte
	FrameHash []byte
}

func (PacketNucleus) Table() string {
	return "pcap_packets"
}

func (p PacketNucleus) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(p)
}

func (p PacketNucleus) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(p)
}

// LayerDecoder defines the reconstruct contract for decoded layers.
type LayerDecoder interface {
	Kind() uint
	Order() uint
	Index() uint16
	SetIndex(uint16)
	HeaderLen() int
	ApplyNucleus(PacketNucleus)
	Reconstruct(*DecodeContext) error
}

// DecodeContext carries shared state while reconstructing a frame.
type DecodeContext struct {
	Nucleus PacketNucleus
	Layers  []gopacket.SerializableLayer
	Offset  int
}

// ClickhouseMapper covers generic ClickHouse INSERT and SELECT column concerns
// for any type that is stored in ClickHouse.
type ClickhouseMapper interface {
	Table() string
	ClickhouseColumns() ([]string, error)
	ClickhouseValues() ([]any, error)
	// DataColumns returns SELECT column expressions derived from the struct's
	// ch: tags, always excluding capture_id and codec_version.
	//
	// When tableAlias is empty, plain column names are returned (packet_id
	// included) — suitable for ScanRow SELECT queries.
	//
	// When tableAlias is non-empty, packet_id is also excluded and each
	// column is expressed as "alias.col AS alias_col" (or "alias.col AS col"
	// when the column name already begins with alias+"_"). The result is
	// suitable for use in a multi-component SELECT with LEFT JOINs.
	DataColumns(tableAlias string) ([]string, error)
}

// LayerEncoder defines the encoding contract for a gopacket layer.
type LayerEncoder interface {
	Encode(gopacket.Layer) ([]Component, error)
}

// Component is the full interface for a registered component: it can encode a
// gopacket layer and be decoded/stored in ClickHouse.
type Component interface {
	ClickhouseMapper
	LayerDecoder
	LayerEncoder
	// Component-specific ClickHouse methods for schema management and export.
	Schema(table string) string
	Indexes(table string) []string
	FetchOrderBy() string
	ScanRow(sessionID uint64, rows chdriver.Rows) (uint32, error)
}

func NewComponentMask(bits ...uint) *big.Int {
	mask := new(big.Int)
	for _, bit := range bits {
		mask.SetBit(mask, int(bit), 1)
	}
	return mask
}

func ComponentHas(mask *big.Int, bit uint) bool {
	if mask == nil {
		return false
	}
	return mask.Bit(int(bit)) == 1
}

func GetClickhouseColumnsFrom(v any) ([]string, error) {
	t := reflect.TypeOf(v)
	if t == nil {
		return nil, fmt.Errorf("nil value")
	}

	// allow pointer-to-struct
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct or *struct, got %s", t.Kind())
	}

	cols := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		// skip unexported fields
		if f.PkgPath != "" {
			continue
		}

		tag := f.Tag.Get("ch")
		if tag == "-" {
			continue
		}

		// support options like `ch:"val_1,omitempty"` if you want
		name := strings.Split(tag, ",")[0]
		if name == "" {
			// fallback: use field name (or convert Val1 -> val1, etc.)
			name = f.Name
		}

		cols = append(cols, name)
	}

	return cols, nil
}

// ComponentFactories maps component kind constants to zero-value constructors.
var ComponentFactories = map[uint]func() Component{
	ComponentEthernet: func() Component { return &EthernetComponent{} },
	ComponentDot1Q:    func() Component { return &Dot1QComponent{} },
	ComponentLinuxSLL: func() Component { return &LinuxSLLComponent{} },
	ComponentIPv4:     func() Component { return &IPv4Component{} },
	ComponentIPv6:     func() Component { return &IPv6Component{} },
	ComponentIPv6Ext:  func() Component { return &IPv6ExtComponent{} },
	ComponentTCP:      func() Component { return &TCPComponent{} },
	ComponentUDP:      func() Component { return &UDPComponent{} },
	ComponentDNS:      func() Component { return &DNSComponent{} },
	ComponentNTP:      func() Component { return &NTPComponent{} },
	ComponentARP:      func() Component { return &ARPComponent{} },
}

// GetDataColumnsFrom derives SELECT column expressions from a struct's ch: tags.
// capture_id and codec_version are always excluded.
//
// When tableAlias is empty, plain column names are returned (packet_id included),
// suitable for ScanRow queries.
//
// When tableAlias is non-empty, packet_id is also excluded and each column is
// expressed as "alias.col AS alias_col". If the column name already begins with
// alias+"_" the output alias is kept as the column name itself (avoiding double
// prefixes like arp_arp_op).
func GetDataColumnsFrom(v any, tableAlias string) ([]string, error) {
	all, err := GetClickhouseColumnsFrom(v)
	if err != nil {
		return nil, err
	}
	withAlias := tableAlias != ""
	alwaysExclude := map[string]bool{"session_id": true, "codec_version": true, "ts": true}

	cols := make([]string, 0, len(all))
	for _, col := range all {
		if alwaysExclude[col] {
			continue
		}
		if withAlias && col == "packet_id" {
			continue
		}
		if withAlias {
			prefix := tableAlias + "_"
			qualified := tableAlias + "." + col
			if strings.HasPrefix(col, prefix) {
				// e.g. arp_op with alias arp → arp.arp_op AS arp_op
				cols = append(cols, fmt.Sprintf("%s AS %s", qualified, col))
			} else {
				// e.g. src with alias ipv4 → ipv4.src AS ipv4_src
				cols = append(cols, fmt.Sprintf("%s AS %s_%s", qualified, tableAlias, col))
			}
		} else {
			cols = append(cols, col)
		}
	}
	return cols, nil
}

func GetClickhouseValuesFrom(v any) ([]any, error) {
	rv := reflect.ValueOf(v)
	rt := reflect.TypeOf(v)
	if rt == nil {
		return nil, fmt.Errorf("nil value")
	}

	// allow pointer-to-struct
	if rt.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil, fmt.Errorf("nil value")
		}
		rv = rv.Elem()
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct or *struct, got %s", rt.Kind())
	}

	vals := make([]any, 0, rv.NumField())

	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)

		// skip unexported fields
		if sf.PkgPath != "" {
			continue
		}

		tag := sf.Tag.Get("ch")
		if tag == "-" {
			continue
		}

		val := rv.Field(i)

		// If it’s a pointer field, Append usually wants nil or the value; keep as-is.
		// For non-pointer fields, Interface() is fine.
		vals = append(vals, val.Interface())
	}

	return vals, nil
}
