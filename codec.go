package caphouse

import (
	"errors"
	"fmt"
	"sort"

	"caphouse/components"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// EncodePacket parses a packet frame into codec components.
func EncodePacket(linkType uint32, p Packet) CodecPacket {
	frame := copyBytes(p.Frame)
	mask := components.NewComponentMask()
	if p.OrigLen > p.InclLen {
		mask.SetBit(mask, int(components.ComponentTruncated), 1)
	}

	nucleus := components.PacketNucleus{
		CaptureID:  p.CaptureID,
		PacketID:   p.PacketID,
		Timestamp:  p.Timestamp,
		InclLen:    p.InclLen,
		OrigLen:    p.OrigLen,
		Components: mask,
	}
	if !linkTypeSupported(linkType) {
		return rawFrameFallback(nucleus, frame)
	}

	packet := gopacket.NewPacket(frame, layers.LinkType(linkType), gopacket.NoCopy)
	layerList := packet.Layers()
	if len(layerList) == 0 {
		return rawFrameFallback(nucleus, frame)
	}

	componentList := []components.Component{}
	orderCounts := map[uint]uint16{}

	for _, layer := range layerList {
		encoder, ok := components.LayerEncoders[layer.LayerType()]
		if !ok {
			continue
		}
		layerComponents, err := encoder.Encode(layer)
		if err != nil {
			// Skip layers that cannot be encoded (e.g. gopacket returns a
			// zero-content layer for a truncated L4 header). The post-loop
			// validation catches missing L2/L3 and triggers rawFrameFallback.
			continue
		}
		for _, component := range layerComponents {
			if component == nil {
				continue
			}
			order := component.Order()
			count := orderCounts[order]
			if !components.OrderRepeatable[order] && count > 0 {
				return rawFrameFallback(nucleus, frame)
			}
			component.SetIndex(count)
			component.ApplyNucleus(nucleus)
			orderCounts[order] = count + 1
			componentList = append(componentList, component)
		}
	}

	if requiresL2(linkType) && orderCounts[components.OrderL2Base] == 0 {
		return rawFrameFallback(nucleus, frame)
	}
	if orderCounts[components.OrderL2Tag] > 0 && orderCounts[components.OrderL2Base] == 0 {
		return rawFrameFallback(nucleus, frame)
	}
	if orderCounts[components.OrderL3Ext] > 0 && orderCounts[components.OrderL3Base] == 0 {
		return rawFrameFallback(nucleus, frame)
	}
	if orderCounts[components.OrderL4Base] > 0 && orderCounts[components.OrderL3Base] == 0 {
		return rawFrameFallback(nucleus, frame)
	}

	tailOffset := 0
	for _, component := range componentList {
		tailOffset += component.HeaderLen()
		if tailOffset > len(frame) || tailOffset > maxTailOffset {
			return rawFrameFallback(nucleus, frame)
		}
	}

	if tailOffset > len(frame) || tailOffset > maxTailOffset {
		return rawFrameFallback(nucleus, frame)
	}
	nucleus.TailOffset = uint16(tailOffset)
	nucleus.FrameRaw = copyBytes(frame[tailOffset:])

	for _, component := range componentList {
		if component == nil {
			continue
		}
		nucleus.Components.SetBit(nucleus.Components, int(component.Kind()), 1)
	}

	return CodecPacket{
		Nucleus:    nucleus,
		Components: componentList,
	}
}

// ReconstructFrame rebuilds packet bytes using component presence and tail_offset.
func ReconstructFrame(nucleus components.PacketNucleus, comps []components.Component) ([]byte, error) {
	if components.ComponentHas(nucleus.Components, components.ComponentRawFrame) {
		if len(nucleus.FrameRaw) == 0 {
			return nil, errors.New("raw frame bit set but frame_raw empty")
		}
		return copyBytes(nucleus.FrameRaw), nil
	}

	kindCounts := map[uint]int{}
	orderCounts := map[uint]int{}
	for _, component := range comps {
		if component == nil {
			continue
		}
		kind := component.Kind()
		kindCounts[kind]++
		orderCounts[component.Order()]++
		if !components.ComponentHas(nucleus.Components, kind) {
			return nil, fmt.Errorf("component kind %d present without bit set", kind)
		}
	}

	for _, kind := range components.KnownComponentKinds {
		if components.ComponentHas(nucleus.Components, kind) && kindCounts[kind] == 0 {
			return nil, fmt.Errorf("missing component kind %d", kind)
		}
	}
	for order, count := range orderCounts {
		if !components.OrderRepeatable[order] && count > 1 {
			return nil, fmt.Errorf("duplicate component order %d", order)
		}
	}

	sorted := make([]components.Component, 0, len(comps))
	for _, component := range comps {
		if component != nil {
			sorted = append(sorted, component)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		a := sorted[i]
		b := sorted[j]
		if a.Order() != b.Order() {
			return a.Order() < b.Order()
		}
		if a.Index() != b.Index() {
			return a.Index() < b.Index()
		}
		return a.Kind() < b.Kind()
	})

	ctx := components.DecodeContext{
		Nucleus: nucleus,
	}

	for _, component := range sorted {
		if err := component.Reconstruct(&ctx); err != nil {
			return nil, err
		}
	}

	if nucleus.TailOffset > 0 && int(nucleus.TailOffset) != ctx.Offset {
		return nil, fmt.Errorf("tail_offset mismatch: %d != %d", nucleus.TailOffset, ctx.Offset)
	}
	if len(nucleus.FrameRaw) > 0 {
		ctx.Layers = append(ctx.Layers, gopacket.Payload(nucleus.FrameRaw))
	}

	if len(ctx.Layers) == 0 {
		return nil, errors.New("no layers reconstructed")
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	if err := gopacket.SerializeLayers(buf, opts, ctx.Layers...); err != nil {
		return nil, err
	}
	serialized := buf.Bytes()
	if nucleus.InclLen > 0 && len(serialized) > int(nucleus.InclLen) {
		serialized = serialized[:nucleus.InclLen]
	}
	return copyBytes(serialized), nil
}

func rawFrameFallback(nucleus components.PacketNucleus, frame []byte) CodecPacket {
	mask := components.NewComponentMask(components.ComponentRawFrame)
	if components.ComponentHas(nucleus.Components, components.ComponentTruncated) {
		mask.SetBit(mask, int(components.ComponentTruncated), 1)
	}
	if components.ComponentHas(nucleus.Components, components.ComponentHash) {
		mask.SetBit(mask, int(components.ComponentHash), 1)
	}
	nucleus.Components = mask
	nucleus.FrameRaw = frame
	nucleus.TailOffset = 0
	return CodecPacket{Nucleus: nucleus}
}

const maxTailOffset = 1<<16 - 1

func linkTypeSupported(linkType uint32) bool {
	if linkType > maxUint8 {
		return false
	}
	switch layers.LinkType(linkType) {
	case layers.LinkTypeEthernet, layers.LinkTypeLinuxSLL, layers.LinkTypeRaw, layers.LinkTypeIPv4, layers.LinkTypeIPv6:
		return true
	default:
		return false
	}
}

func requiresL2(linkType uint32) bool {
	switch layers.LinkType(linkType) {
	case layers.LinkTypeEthernet, layers.LinkTypeLinuxSLL:
		return true
	default:
		return false
	}
}

const maxUint8 = 1<<8 - 1

func copyBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
