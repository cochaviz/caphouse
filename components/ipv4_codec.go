package components

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ipv4LayerEncoder struct{}

func (ipv4LayerEncoder) LayerType() gopacket.LayerType {
	return layers.LayerTypeIPv4
}

func (ipv4LayerEncoder) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
	ip4, ok := layer.(*layers.IPv4)
	if !ok {
		return nil, errors.New("unsupported ipv4 layer")
	}
	return encodeIPv4Layer(ip4)
}

func encodeIPv4Layer(ip4 *layers.IPv4) ([]ClickhouseMappedDecoder, error) {
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
	optionsLen := headerLen - 20
	src, ok := netip.AddrFromSlice(ip4.SrcIP)
	if !ok {
		src = netip.Addr{}
	}
	dst, ok := netip.AddrFromSlice(ip4.DstIP)
	if !ok {
		dst = netip.Addr{}
	}
	component := &IPv4Component{
		CodecVersion:    CodecVersionV1,
		ParsedOK:        1,
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
	components := []ClickhouseMappedDecoder{component}
	if optionsLen > 0 {
		components = append(components, newIPv4OptionsComponent(contents[20:headerLen]))
	}
	return components, nil
}
