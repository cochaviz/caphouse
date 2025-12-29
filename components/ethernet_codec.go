package components

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ethernetLayerEncoder struct{}

func (ethernetLayerEncoder) LayerType() gopacket.LayerType {
	return layers.LayerTypeEthernet
}

func (ethernetLayerEncoder) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
	eth, ok := layer.(*layers.Ethernet)
	if !ok {
		return nil, errors.New("unsupported ethernet layer")
	}
	contents := eth.LayerContents()
	if len(contents) < 14 {
		return nil, ErrShortFrame
	}
	if len(eth.SrcMAC) != 6 || len(eth.DstMAC) != 6 {
		return nil, errors.New("invalid ethernet mac length")
	}
	component := &EthernetComponent{
		CodecVersion: CodecVersionV1,
		SrcMAC:       copyBytes(eth.SrcMAC),
		DstMAC:       copyBytes(eth.DstMAC),
		EtherType:    uint16(eth.EthernetType),
		Length:       eth.Length,
	}
	return []ClickhouseMappedDecoder{component}, nil
}
