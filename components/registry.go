package components

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerEncoders = map[gopacket.LayerType]LayerEncoder{
	layers.LayerTypeEthernet:        &EthernetComponent{},
	layers.LayerTypeDot1Q:           &Dot1QComponent{},
	layers.LayerTypeLinuxSLL:        &LinuxSLLComponent{},
	layers.LayerTypeIPv4:            &IPv4Component{},
	layers.LayerTypeIPv6:            &IPv6Component{},
	layers.LayerTypeIPv6HopByHop:    &IPv6ExtComponent{},
	layers.LayerTypeIPv6Routing:     &IPv6ExtComponent{},
	layers.LayerTypeIPv6Fragment:    &IPv6ExtComponent{},
	layers.LayerTypeIPv6Destination: &IPv6ExtComponent{},
}

func LayerSupported(layerType gopacket.LayerType) bool {
	_, ok := LayerEncoders[layerType]
	return ok
}
