package components

import (
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/netip"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed ipv4_schema.sql
var ipv4SchemaSQL string

// IPv4Component stores parsed IPv4 fields, including any option bytes.
type IPv4Component struct {
	SessionID uint64 `ch:"session_id"`
	Ts        int64  `ch:"ts"`
	PacketID  uint32 `ch:"packet_id"`

	CodecVersion uint16 `ch:"codec_version"`

	Protocol uint8 `ch:"protocol"`

	SrcIP4 netip.Addr `ch:"src"`
	DstIP4 netip.Addr `ch:"dst"`

	IPv4IHL         uint8  `ch:"ihl"`
	IPv4TOS         uint8  `ch:"tos"`
	IPv4TotalLen    uint16 `ch:"total_len"`
	IPv4ID          uint16 `ch:"id"`
	IPv4Flags       uint8  `ch:"flags"`
	IPv4FragOffset  uint16 `ch:"frag_offset"`
	IPv4TTL         uint8  `ch:"ttl"`
	IPv4HdrChecksum uint16 `ch:"hdr_checksum"`

	OptionsRaw []byte `ch:"options_raw"`
}

func (c *IPv4Component) Kind() uint           { return ComponentIPv4 }
func (c *IPv4Component) Table() string        { return "pcap_ipv4" }
func (c *IPv4Component) Order() uint          { return OrderL3Base }
func (c *IPv4Component) Index() uint16        { return 0 }
func (c *IPv4Component) SetIndex(_ uint16)    {}
func (c *IPv4Component) HeaderLen() int       { return 20 + len(c.OptionsRaw) }
func (c *IPv4Component) FetchOrderBy() string { return "packet_id" }

func (c *IPv4Component) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

// ClickhouseValues overrides reflection to convert netip.Addr to strings.
func (c *IPv4Component) ClickhouseValues() ([]any, error) {
	return []any{
		c.SessionID, c.Ts, c.PacketID, c.CodecVersion,
		c.Protocol, ipv4String(c.SrcIP4), ipv4String(c.DstIP4),
		c.IPv4IHL, c.IPv4TOS, c.IPv4TotalLen, c.IPv4ID,
		c.IPv4Flags, c.IPv4FragOffset, c.IPv4TTL, c.IPv4HdrChecksum,
		string(c.OptionsRaw),
	}, nil
}

func (c *IPv4Component) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.Ts = nucleus.Timestamp.UnixNano()
	c.PacketID = nucleus.PacketID
}

func (c *IPv4Component) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("ipv4 component missing")
	}
	layer := &layers.IPv4{
		Version:    4,
		IHL:        c.IPv4IHL,
		TOS:        c.IPv4TOS,
		Length:     c.IPv4TotalLen,
		Id:         c.IPv4ID,
		Flags:      layers.IPv4Flag(c.IPv4Flags),
		FragOffset: c.IPv4FragOffset,
		TTL:        c.IPv4TTL,
		Protocol:   layers.IPProtocol(c.Protocol),
		Checksum:   c.IPv4HdrChecksum,
		SrcIP:      net.IP(c.SrcIP4.AsSlice()),
		DstIP:      net.IP(c.DstIP4.AsSlice()),
	}
	if len(c.OptionsRaw) > 0 {
		if len(c.OptionsRaw)%4 != 0 {
			return errors.New("ipv4 options length not multiple of 4")
		}
		opts, err := parseIPv4Options(c.OptionsRaw)
		if err != nil {
			return err
		}
		expectedIHL := uint8(5 + len(c.OptionsRaw)/4)
		if layer.IHL == 0 {
			layer.IHL = expectedIHL
		} else if layer.IHL != expectedIHL {
			return errors.New("ipv4 ihl/options length mismatch")
		}
		layer.Options = opts
	}
	ctx.Layers = append(ctx.Layers, layer)
	ctx.Offset += 20 + len(c.OptionsRaw)
	return nil
}

func (c *IPv4Component) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *IPv4Component) ScanRow(sessionID uint64, rows chdriver.Rows) (uint32, error) {
	var src, dst, optRaw string
	c.SessionID = sessionID
	err := rows.Scan(
		&c.PacketID, &c.Protocol,
		&src, &dst,
		&c.IPv4IHL, &c.IPv4TOS, &c.IPv4TotalLen, &c.IPv4ID,
		&c.IPv4Flags, &c.IPv4FragOffset, &c.IPv4TTL, &c.IPv4HdrChecksum,
		&optRaw,
	)
	c.SrcIP4, _ = netip.ParseAddr(src)
	c.DstIP4, _ = netip.ParseAddr(dst)
	c.OptionsRaw = []byte(optRaw)
	return c.PacketID, err
}

func (c *IPv4Component) Encode(layer gopacket.Layer) ([]Component, error) {
	ip4, ok := layer.(*layers.IPv4)
	if !ok {
		return nil, errors.New("unsupported ipv4 layer")
	}
	contents := ip4.LayerContents()
	if len(contents) < 20 {
		return nil, ErrShortFrame
	}
	headerLen := int(ip4.IHL) * 4
	if ip4.IHL == 0 {
		headerLen = len(contents)
	}
	if headerLen < 20 || headerLen > len(contents) {
		return nil, fmt.Errorf("invalid ipv4 header length %d", headerLen)
	}
	src, ok := netip.AddrFromSlice(ip4.SrcIP)
	if !ok {
		src = netip.Addr{}
	}
	dst, ok := netip.AddrFromSlice(ip4.DstIP)
	if !ok {
		dst = netip.Addr{}
	}
	comp := &IPv4Component{
		CodecVersion:    CodecVersionV1,
		Protocol:        uint8(ip4.Protocol),
		SrcIP4:          src,
		DstIP4:          dst,
		IPv4IHL:         ip4.IHL,
		IPv4TOS:         ip4.TOS,
		IPv4TotalLen:    ip4.Length,
		IPv4ID:          ip4.Id,
		IPv4Flags:       uint8(ip4.Flags),
		IPv4FragOffset:  ip4.FragOffset,
		IPv4TTL:         ip4.TTL,
		IPv4HdrChecksum: ip4.Checksum,
	}
	if optionsLen := headerLen - 20; optionsLen > 0 {
		comp.OptionsRaw = copyBytes(contents[20:headerLen])
	}
	return []Component{comp}, nil
}

func (c *IPv4Component) Schema(table string) string { return applySchema(ipv4SchemaSQL, table) }
func (c *IPv4Component) Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_dst (dst) TYPE bloom_filter GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_proto (protocol) TYPE set(256) GRANULARITY 4", table),
	}
}

func parseIPv4Options(raw []byte) ([]layers.IPv4Option, error) {
	opts := make([]layers.IPv4Option, 0)
	for i := 0; i < len(raw); {
		optType := raw[i]
		switch optType {
		case 0:
			opts = append(opts, layers.IPv4Option{OptionType: 0, OptionLength: 1})
			i++
		case 1:
			opts = append(opts, layers.IPv4Option{OptionType: 1, OptionLength: 1})
			i++
		default:
			if i+1 >= len(raw) {
				return nil, errors.New("ipv4 option missing length")
			}
			optLen := int(raw[i+1])
			if optLen < 2 {
				return nil, errors.New("ipv4 option length too short")
			}
			if i+optLen > len(raw) {
				return nil, errors.New("ipv4 option overruns buffer")
			}
			optData := make([]byte, optLen-2)
			copy(optData, raw[i+2:i+optLen])
			opts = append(opts, layers.IPv4Option{
				OptionType:   optType,
				OptionLength: uint8(optLen),
				OptionData:   optData,
			})
			i += optLen
		}
	}
	return opts, nil
}
