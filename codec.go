package caphouse

import (
	"errors"
	"fmt"
	"sort"

	"caphouse/components"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// encodePacket parses a raw frame into a codecPacket whose Components slice
// holds one entry per recognised protocol layer. Layers that cannot be decoded
// fall back to storing the full raw frame in the nucleus instead.
func encodePacket(linkType uint32, p Packet) codecPacket {
	frame := copyBytes(p.Frame)
	mask := components.NewComponentMask()
	if p.OrigLen > p.InclLen {
		mask.SetBit(mask, int(components.ComponentTruncated), 1)
	}

	nucleus := components.PacketNucleus{
		SessionID:  p.SessionID,
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

	for count, layer := range layerList {
		encoder, ok := components.LayerEncoders[layer.LayerType()]
		if !ok {
			break
		}
		layerComponents, err := encoder.Encode(layer)
		if err != nil {
			continue
		}
		for _, component := range layerComponents {
			if component == nil {
				continue
			}
			component.SetIndex(uint16(count))
			component.ApplyNucleus(nucleus)
			componentList = append(componentList, component)
		}
	}

	tailOffset := 0
	for _, component := range componentList {
		tailOffset += component.LayerSize()
	}

	if tailOffset > min(len(frame), maxTailOffset) {
		return rawFrameFallback(nucleus, frame)
	}
	nucleus.TailOffset = uint16(tailOffset)
	nucleus.Payload = copyBytes(frame[tailOffset:])

	for _, component := range componentList {
		if component == nil {
			continue
		}
		nucleus.Components.SetBit(nucleus.Components, int(component.Kind()), 1)
	}

	return codecPacket{
		Nucleus:    nucleus,
		Components: componentList,
	}
}

// reconstructFrame rebuilds the original frame bytes from a stored nucleus and
// its protocol-layer components. If the raw-frame bit is set in the nucleus,
// the stored frame bytes are returned directly without consulting comps.
// Returns an error if a component's kind bit is not set in the nucleus mask.
func reconstructFrame(nucleus components.PacketNucleus, comps []components.Component) ([]byte, error) {
	if components.ComponentHas(nucleus.Components, components.ComponentRawFrame) {
		if len(nucleus.Payload) == 0 {
			return nil, errors.New("raw frame bit set but payload empty")
		}
		return copyBytes(nucleus.Payload), nil
	}

	kindCounts := map[uint]int{}
	for _, component := range comps {
		if component == nil {
			continue
		}
		kind := component.Kind()
		kindCounts[kind]++
		if !components.ComponentHas(nucleus.Components, kind) {
			return nil, fmt.Errorf("component kind %d present without bit set", kind)
		}
	}

	for _, kind := range components.KnownComponentKinds {
		if components.ComponentHas(nucleus.Components, kind) && kindCounts[kind] == 0 {
			return nil, fmt.Errorf("missing component kind %d", kind)
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
		return a.Index() < b.Index()
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
	if len(nucleus.Payload) > 0 {
		ctx.Layers = append(ctx.Layers, gopacket.Payload(nucleus.Payload))
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

func rawFrameFallback(nucleus components.PacketNucleus, frame []byte) codecPacket {
	mask := components.NewComponentMask(components.ComponentRawFrame)
	if components.ComponentHas(nucleus.Components, components.ComponentTruncated) {
		mask.SetBit(mask, int(components.ComponentTruncated), 1)
	}
	if components.ComponentHas(nucleus.Components, components.ComponentHash) {
		mask.SetBit(mask, int(components.ComponentHash), 1)
	}
	nucleus.Components = mask
	nucleus.Payload = frame
	nucleus.TailOffset = 0
	return codecPacket{Nucleus: nucleus}
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
