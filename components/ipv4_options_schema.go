package components

import (
	"errors"
	"fmt"

	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

// IPv4OptionsComponent stores raw IPv4 options bytes.
type IPv4OptionsComponent struct {
	CaptureID    uuid.UUID
	PacketID     uint64
	CodecVersion uint16
	OptionsRaw   []byte
}

func (c *IPv4OptionsComponent) Kind() uint {
	return ComponentIPv4Options
}

func (c *IPv4OptionsComponent) Table() string {
	return "pcap_ipv4_options"
}

func (c *IPv4OptionsComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *IPv4OptionsComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *IPv4OptionsComponent) Order() uint {
	return OrderL3Options
}

func (c *IPv4OptionsComponent) Index() uint16 {
	return 0
}

func (c *IPv4OptionsComponent) SetIndex(_ uint16) {}

func (c *IPv4OptionsComponent) HeaderLen() int {
	return len(c.OptionsRaw)
}

func (c *IPv4OptionsComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
}

func (c *IPv4OptionsComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("ipv4 options component missing")
	}
	if len(c.OptionsRaw) == 0 {
		return nil
	}
	if ctx.LastIPv4 == nil {
		return errors.New("ipv4 options without ipv4 header")
	}
	if len(c.OptionsRaw)%4 != 0 {
		return errors.New("ipv4 options length not multiple of 4")
	}
	opts, err := parseIPv4Options(c.OptionsRaw)
	if err != nil {
		return err
	}
	expectedIHL := uint8(5 + len(c.OptionsRaw)/4)
	if ctx.LastIPv4.IHL == 0 {
		ctx.LastIPv4.IHL = expectedIHL
	} else if ctx.LastIPv4.IHL != expectedIHL {
		return errors.New("ipv4 ihl/options length mismatch")
	}
	ctx.LastIPv4.Options = opts
	ctx.Offset += len(c.OptionsRaw)
	return nil
}

func parseIPv4Options(raw []byte) ([]layers.IPv4Option, error) {
	opts := make([]layers.IPv4Option, 0)
	for i := 0; i < len(raw); {
		optType := raw[i]
		switch optType {
		case 0:
			opts = append(opts, layers.IPv4Option{
				OptionType:   0,
				OptionLength: 1,
			})
			i++
		case 1:
			opts = append(opts, layers.IPv4Option{
				OptionType:   1,
				OptionLength: 1,
			})
			i++
		default:
			if i+1 >= len(raw) {
				return nil, errors.New("ipv4 option missing length")
			}
			optLen := int(raw[i+1])
			if optLen < 2 {
				return nil, errors.New("ipv4 option length too short")
			}
			if i+optLen > len(raw) {
				return nil, errors.New("ipv4 option overruns buffer")
			}
			optData := make([]byte, optLen-2)
			copy(optData, raw[i+2:i+optLen])
			opts = append(opts, layers.IPv4Option{
				OptionType:   optType,
				OptionLength: uint8(optLen),
				OptionData:   optData,
			})
			i += optLen
		}
	}
	return opts, nil
}

func IPv4OptionsSchema(table string) string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s
(
  capture_id UUID,
  packet_id UInt64,

  codec_version UInt16,

  options_raw String CODEC(ZSTD)
)
ENGINE = MergeTree
ORDER BY (capture_id, packet_id)`, table)
}
