package components

import (
	_ "embed"
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed arp_schema.sql
var arpSchemaSQL string

// ARPComponent stores parsed ARP header fields.
type ARPComponent struct {
	SessionID    uint64 `ch:"session_id"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`
	LayerIndex   uint16 `ch:"layer_index"`

	// HwType    [4]byte
	// AddrType  [4]byte
	ArpOp     uint16  `ch:"arp_op"`
	SenderMAC [6]byte `ch:"sender_mac"`
	SenderIP  net.IP  `ch:"sender_ip"`
	TargetMAC [6]byte `ch:"target_mac"`
	TargetIP  net.IP  `ch:"target_ip"`
}

func (c *ARPComponent) Kind() uint           { return ComponentARP }
func (c *ARPComponent) Name() string         { return "arp" }
func (c *ARPComponent) Order() uint          { return OrderL4Base }
func (c *ARPComponent) Index() uint16        { return c.LayerIndex }
func (c *ARPComponent) SetIndex(i uint16)    { c.LayerIndex = i }
func (c *ARPComponent) LayerSize() int       { return 28 }
func (c *ARPComponent) FetchOrderBy() string { return "packet_id" }

func (c *ARPComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *ARPComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *ARPComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.PacketID = nucleus.PacketID
}

func (c *ARPComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("arp component missing")
	}

	layer := &layers.ARP{
		// TODO Actually interpret these two fields from data
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         c.ArpOp,
		SourceHwAddress:   c.SenderMAC[:],
		DstHwAddress:      c.TargetMAC[:],
		SourceProtAddress: c.SenderIP,
		DstProtAddress:    c.TargetIP,
	}

	ctx.Layers = append(ctx.Layers, layer)
	ctx.Offset += 28
	return nil
}

func (c *ARPComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *ARPComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	arp, ok := layer.(*layers.ARP)
	if !ok {
		return nil, errors.New("unsupported arp layer")
	}
	if len(arp.LayerContents()) < 28 {
		return nil, ErrShortFrame
	}
	comp := &ARPComponent{
		CodecVersion: CodecVersionV1,
		ArpOp:        arp.Operation,
	}
	if len(arp.SourceHwAddress) == 6 {
		copy(comp.SenderMAC[:], arp.SourceHwAddress)
	}
	if len(arp.DstHwAddress) == 6 {
		copy(comp.TargetMAC[:], arp.DstHwAddress)
	}
	comp.SenderIP = net.IP(arp.SourceProtAddress).To4()
	comp.TargetIP = net.IP(arp.DstProtAddress).To4()
	return []Component{comp}, nil
}

func (c *ARPComponent) Schema(table string) string { return applySchema(arpSchemaSQL, table) }
