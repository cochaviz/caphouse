package components

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	ComponentRawFrame uint = iota
	ComponentEthernet
	ComponentDot1Q
	ComponentLinuxSLL
	ComponentIPv4
	ComponentIPv6
	ComponentIPv6Ext
	ComponentHash
	ComponentTruncated
	ComponentTCP
	ComponentUDP
	ComponentDNS
	ComponentNTP
	ComponentARP
	ComponentICMPv4
	ComponentICMPv6
	ComponentGRE
)

var KnownComponentKinds = []uint{
	ComponentEthernet,
	ComponentDot1Q,
	ComponentLinuxSLL,
	ComponentIPv4,
	ComponentIPv6,
	ComponentIPv6Ext,
	ComponentTCP,
	ComponentUDP,
	ComponentDNS,
	ComponentNTP,
	ComponentARP,
	ComponentICMPv4,
	ComponentICMPv6,
	ComponentGRE,
}

var LayerEncoders = map[gopacket.LayerType]Component{
	layers.LayerTypeEthernet:        &EthernetComponent{},
	layers.LayerTypeDot1Q:           &Dot1QComponent{},
	layers.LayerTypeLinuxSLL:        &LinuxSLLComponent{},
	layers.LayerTypeIPv4:            &IPv4Component{},
	layers.LayerTypeIPv6:            &IPv6Component{},
	layers.LayerTypeIPv6HopByHop:    &IPv6ExtComponent{},
	layers.LayerTypeIPv6Routing:     &IPv6ExtComponent{},
	layers.LayerTypeIPv6Fragment:    &IPv6ExtComponent{},
	layers.LayerTypeIPv6Destination: &IPv6ExtComponent{},
	layers.LayerTypeTCP:             &TCPComponent{},
	layers.LayerTypeUDP:             &UDPComponent{},
	layers.LayerTypeDNS:             &DNSComponent{},
	layers.LayerTypeNTP:             &NTPComponent{},
	layers.LayerTypeARP:             &ARPComponent{},
	layers.LayerTypeICMPv4:          &ICMPv4Component{},
	layers.LayerTypeICMPv6:          &ICMPv6Component{},
	layers.LayerTypeGRE:             &GREComponent{},
}

func LayerSupported(layerType gopacket.LayerType) bool {
	_, ok := LayerEncoders[layerType]
	return ok
}

// ComponentFactories maps component kind constants to zero-value constructors.
var ComponentFactories = map[uint]func() Component{
	ComponentEthernet: func() Component { return &EthernetComponent{} },
	ComponentDot1Q:    func() Component { return &Dot1QComponent{} },
	ComponentLinuxSLL: func() Component { return &LinuxSLLComponent{} },
	ComponentIPv4:     func() Component { return &IPv4Component{} },
	ComponentIPv6:     func() Component { return &IPv6Component{} },
	ComponentIPv6Ext:  func() Component { return &IPv6ExtComponent{} },
	ComponentTCP:      func() Component { return &TCPComponent{} },
	ComponentUDP:      func() Component { return &UDPComponent{} },
	ComponentDNS:      func() Component { return &DNSComponent{} },
	ComponentNTP:      func() Component { return &NTPComponent{} },
	ComponentARP:      func() Component { return &ARPComponent{} },
	ComponentICMPv4:   func() Component { return &ICMPv4Component{} },
	ComponentICMPv6:   func() Component { return &ICMPv6Component{} },
	ComponentGRE:      func() Component { return &GREComponent{} },
}
