package components

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerEncoders = map[gopacket.LayerType]LayerEncoder{
	layers.LayerTypeEthernet:        ethernetLayerEncoder{},
	layers.LayerTypeDot1Q:           dot1QLayerEncoder{},
	layers.LayerTypeLinuxSLL:        linuxSLLLayerEncoder{},
	layers.LayerTypeIPv4:            ipv4LayerEncoder{},
	layers.LayerTypeIPv6:            ipv6LayerEncoder{},
	layers.LayerTypeIPv6HopByHop:    ipv6ExtLayerEncoder{},
	layers.LayerTypeIPv6Routing:     ipv6ExtLayerEncoder{},
	layers.LayerTypeIPv6Fragment:    ipv6ExtLayerEncoder{},
	layers.LayerTypeIPv6Destination: ipv6ExtLayerEncoder{},
}

func LayerSupported(layerType gopacket.LayerType) bool {
	_, ok := LayerEncoders[layerType]
	return ok
}
