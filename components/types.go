package components

import (
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
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
	ComponentIPv4Options
	ComponentIPv6
	ComponentIPv6Ext
	ComponentRawTail
	ComponentHash
	ComponentTruncated
)

const (
	OrderL2Base uint = iota
	OrderL2Tag
	OrderL3Base
	OrderL3Options
	OrderL3Ext
	OrderTail
)

var KnownComponentKinds = []uint{
	ComponentEthernet,
	ComponentDot1Q,
	ComponentLinuxSLL,
	ComponentIPv4,
	ComponentIPv4Options,
	ComponentIPv6,
	ComponentIPv6Ext,
	ComponentRawTail,
}

var OrderRepeatable = map[uint]bool{
	OrderL2Tag: true,
	OrderL3Ext: true,
}

// PacketNucleus represents the primary row in pcap_packets, holding per-packet metadata and the component bitmask.
type PacketNucleus struct {
	CaptureID uuid.UUID
	PacketID  uint64
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

// ClickhouseMapper provides table/column mapping for ClickHouse inserts.
type ClickhouseMapper interface {
	Table() string
	ClickhouseColumns() ([]string, error)
	ClickhouseValues() ([]any, error)
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

// ClickhouseMappedDecoder provides both ClickHouse mapping and layer decode behavior.
type ClickhouseMappedDecoder interface {
	ClickhouseMapper
	LayerDecoder
}

// DecodeContext carries shared state while reconstructing a frame.
type DecodeContext struct {
	Nucleus  PacketNucleus
	Layers   []gopacket.SerializableLayer
	Offset   int
	LastIPv4 *layers.IPv4
}

// LayerEncoder defines the encoding contract for a gopacket layer.
type LayerEncoder interface {
	LayerType() gopacket.LayerType
	Encode(gopacket.Layer) ([]ClickhouseMappedDecoder, error)
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
