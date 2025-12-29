package components

import "errors"

type RawTailCodec struct{}

const maxTailOffset = 1<<16 - 1

func (RawTailCodec) Encode(nucleus *PacketNucleus, frame []byte, tailOffset int) (*RawTailComponent, error) {
	if nucleus == nil {
		return nil, errors.New("missing nucleus")
	}
	if tailOffset < 0 || tailOffset > len(frame) || tailOffset > maxTailOffset {
		return nil, ErrTailOffset
	}
	nucleus.TailOffset = uint16(tailOffset)
	return &RawTailComponent{
		CaptureID:  nucleus.CaptureID,
		PacketID:   nucleus.PacketID,
		TailOffset: uint16(tailOffset),
		Bytes:      copyBytes(frame[tailOffset:]),
	}, nil
}

var (
	ErrTailOffset = errors.New("tail offset out of range")
)
