package components

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ipv6ExtLayerEncoder struct{}

func (ipv6ExtLayerEncoder) LayerType() gopacket.LayerType {
	return layers.LayerTypeIPv6HopByHop
}

func (ipv6ExtLayerEncoder) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
	contents := layer.LayerContents()
	if len(contents) == 0 {
		return nil, ErrShortFrame
	}
	component := &IPv6ExtComponent{
		CodecVersion: CodecVersionV1,
		ExtType:      uint16(layer.LayerType()),
		ExtRaw:       copyBytes(contents),
	}
	return []ClickhouseMappedDecoder{component}, nil
}
