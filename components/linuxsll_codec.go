package components

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type linuxSLLLayerEncoder struct{}

func (linuxSLLLayerEncoder) LayerType() gopacket.LayerType {
	return layers.LayerTypeLinuxSLL
}

func (linuxSLLLayerEncoder) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
	sll, ok := layer.(*layers.LinuxSLL)
	if !ok {
		return nil, errors.New("unsupported linux sll layer")
	}
	contents := sll.LayerContents()
	if len(contents) == 0 {
		return nil, ErrShortFrame
	}
	component := &LinuxSLLComponent{
		CodecVersion: CodecVersionV1,
		L2Len:        uint16(len(contents)),
		L2HdrRaw:     copyBytes(contents),
	}
	return []ClickhouseMappedDecoder{component}, nil
}
