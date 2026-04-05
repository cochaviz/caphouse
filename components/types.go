package components

import (
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/google/gopacket"
)

const (
	CodecVersionV1 uint16 = 1
	CodecProfileV1        = "nested-v1"
)

const (
	OrderL2Base uint = iota
	OrderL2Tag
	OrderL3Base
	OrderL3Ext
	OrderL4Base
	OrderL7Base
)

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

	Payload []byte
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
	LayerSize() int
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

// ComponentTable returns the ClickHouse table name for c ("pcap_" + c.Name()).
func ComponentTable(c Component) string { return "pcap_" + c.Name() }

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
	// Name returns the short component alias (e.g. "ethernet", "ipv4").
	// The ClickHouse table name is "pcap_" + Name().
	Name() string
	Schema(table string) string
	FetchOrderBy() string
}

// RepeatableExporter is implemented by components that can appear multiple
// times per packet (Dot1Q, IPv6Ext). Their wide-JOIN scan targets are
// []T slices produced by groupArray CTEs, so they cannot be derived from
// the scalar ch-tagged struct fields via NewScanBuf.
type RepeatableExporter interface {
	// ExportScanTargets returns slice pointers that receive groupArray results.
	ExportScanTargets() []any
	// ExportExpand expands the scanned arrays into one Component per entry.
	ExportExpand(sessionID uint64, packetID uint32) []Component
}

// ScanBuf holds Scan() pointers and a post-scan type-conversion function.
// Targets must be passed to rows.Scan; call Apply after a successful scan
// to convert string intermediates into the struct's typed fields.
type ScanBuf struct {
	Targets []any
	Apply   func()
}

// scanMetaFields are excluded when withMeta is false.
var scanMetaFields = map[string]bool{
	"session_id": true, "packet_id": true, "codec_version": true,
}

// NewScanBuf returns a ScanBuf for the ch-tagged fields of v (must be a
// non-nil pointer to a struct). If withMeta is false, the fields
// "session_id", "packet_id", and "codec_version" are omitted.
//
// Fields whose Go type cannot be scanned directly from ClickHouse are given
// string intermediates; Apply converts them after Scan:
//   - []byte     → scan as *string, apply: []byte(*s)
//   - netip.Addr → scan as *string, apply: netip.ParseAddr(*s)
//   - [N]byte    → scan as *string, apply: copy into array
//
// net.IP and all other types are scanned directly.
func NewScanBuf(v any, withMeta bool) (*ScanBuf, error) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return nil, fmt.Errorf("NewScanBuf: expected non-nil pointer, got %T", v)
	}
	rv = rv.Elem()
	rt := rv.Type()
	if rt.Kind() != reflect.Struct {
		return nil, fmt.Errorf("NewScanBuf: expected pointer to struct, got %T", v)
	}

	var targets []any
	var appliers []func()

	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		if sf.PkgPath != "" {
			continue // unexported
		}
		tag := sf.Tag.Get("ch")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = sf.Name
		}
		if !withMeta && scanMetaFields[name] {
			continue
		}

		fv := rv.Field(i)

		switch fv.Interface().(type) {
		case net.IP:
			// net.IP scans directly; ClickHouse IPv4/IPv6 columns return net.IP.
			targets = append(targets, fv.Addr().Interface())
		case netip.Addr:
			s := new(string)
			targets = append(targets, s)
			fvCopy := fv
			appliers = append(appliers, func() {
				addr, _ := netip.ParseAddr(*s)
				fvCopy.Set(reflect.ValueOf(addr))
			})
		case []byte:
			s := new(string)
			targets = append(targets, s)
			fvCopy := fv
			appliers = append(appliers, func() {
				fvCopy.Set(reflect.ValueOf([]byte(*s)))
			})
		default:
			if sf.Type.Kind() == reflect.Array && sf.Type.Elem().Kind() == reflect.Uint8 {
				// [N]byte (e.g. [6]byte MAC addresses)
				s := new(string)
				targets = append(targets, s)
				fvCopy := fv
				appliers = append(appliers, func() {
					src := []byte(*s)
					for j, n := 0, fvCopy.Len(); j < n && j < len(src); j++ {
						fvCopy.Index(j).SetUint(uint64(src[j]))
					}
				})
			} else {
				targets = append(targets, fv.Addr().Interface())
			}
		}
	}

	applyFn := func() {
		for _, f := range appliers {
			f()
		}
	}
	return &ScanBuf{Targets: targets, Apply: applyFn}, nil
}

// ExpandOne copies v, sets SessionID and PacketID, and returns it as a
// single-element Component slice. Used by non-repeatable components after
// a NewScanBuf scan so that the scanner can be reused for the next row.
func ExpandOne(v Component, sessionID uint64, packetID uint32) []Component {
	rv := reflect.ValueOf(v).Elem()
	cp := reflect.New(rv.Type())
	cp.Elem().Set(rv)
	cp.Elem().FieldByName("SessionID").SetUint(sessionID)
	cp.Elem().FieldByName("PacketID").SetUint(uint64(packetID))
	return []Component{cp.Interface().(Component)}
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
	alwaysExclude := map[string]bool{"session_id": true, "codec_version": true}

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

		fv := rv.Field(i)

		switch v := fv.Interface().(type) {
		case net.IP:
			vals = append(vals, v) // net.IP accepted directly by driver
		case netip.Addr:
			vals = append(vals, v.Unmap().String())
		case []byte:
			vals = append(vals, string(v))
		default:
			if sf.Type.Kind() == reflect.Array && sf.Type.Elem().Kind() == reflect.Uint8 {
				// [N]byte → string (e.g. [6]byte MAC)
				b := make([]byte, sf.Type.Len())
				for j := range b {
					b[j] = byte(fv.Index(j).Uint())
				}
				vals = append(vals, string(b))
			} else {
				vals = append(vals, fv.Interface())
			}
		}
	}

	return vals, nil
}
