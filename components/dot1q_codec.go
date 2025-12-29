package components

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type dot1QLayerEncoder struct{}

func (dot1QLayerEncoder) LayerType() gopacket.LayerType {
	return layers.LayerTypeDot1Q
}

func (dot1QLayerEncoder) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
	tag, ok := layer.(*layers.Dot1Q)
	if !ok {
		return nil, errors.New("unsupported dot1q layer")
	}
	contents := tag.LayerContents()
	if len(contents) < 4 {
		return nil, ErrShortFrame
	}
	component := &Dot1QComponent{
		CodecVersion: CodecVersionV1,
		Priority:     tag.Priority,
		DropEligible: boolToUint8(tag.DropEligible),
		VLANID:       tag.VLANIdentifier,
		EtherType:    uint16(tag.Type),
	}
	return []ClickhouseMappedDecoder{component}, nil
}
