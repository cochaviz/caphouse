package components

import (
	"errors"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ipv6LayerEncoder struct{}

func (ipv6LayerEncoder) LayerType() gopacket.LayerType {
	return layers.LayerTypeIPv6
}

func (ipv6LayerEncoder) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
	ip6, ok := layer.(*layers.IPv6)
	if !ok {
		return nil, errors.New("unsupported ipv6 layer")
	}
	return encodeIPv6Layer(ip6)
}

func encodeIPv6Layer(ip6 *layers.IPv6) ([]ClickhouseMappedDecoder, error) {
	contents := ip6.LayerContents()
	if len(contents) < 40 {
		return nil, ErrShortFrame
	}
	src, ok := netip.AddrFromSlice(ip6.SrcIP)
	if !ok {
		src = netip.Addr{}
	}
	dst, ok := netip.AddrFromSlice(ip6.DstIP)
	if !ok {
		dst = netip.Addr{}
	}
	component := &IPv6Component{
		CodecVersion:     CodecVersionV1,
		ParsedOK:         1,
		Protocol:         uint8(ip6.NextHeader),
		SrcIP6:           src,
		DstIP6:           dst,
		IPv6PayloadLen:   ip6.Length,
		IPv6HopLimit:     ip6.HopLimit,
		IPv6FlowLabel:    ip6.FlowLabel,
		IPv6TrafficClass: ip6.TrafficClass,
	}
	return []ClickhouseMappedDecoder{component}, nil
}
