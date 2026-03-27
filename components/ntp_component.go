package components

import (
	_ "embed"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:embed ntp_schema.sql
var ntpSchemaSQL string

// NTPComponent stores parsed NTP header fields.
// ntp_raw holds the full wire bytes for lossless reconstruction.
type NTPComponent struct {
	SessionID    uint64 `ch:"session_id"`
	Ts           int64  `ch:"ts"`
	PacketID     uint32 `ch:"packet_id"`
	CodecVersion uint16 `ch:"codec_version"`

	LeapIndicator  uint8  `ch:"leap_indicator"`
	Version        uint8  `ch:"version"`
	Mode           uint8  `ch:"mode"`
	Stratum        uint8  `ch:"stratum"`
	Poll           int8   `ch:"poll"`
	Precision      int8   `ch:"precision"`
	RootDelay      uint32 `ch:"root_delay"`
	RootDispersion uint32 `ch:"root_dispersion"`
	ReferenceID    uint32 `ch:"reference_id"`

	ReferenceTS uint64 `ch:"reference_ts"`
	OriginTS    uint64 `ch:"origin_ts"`
	ReceiveTS   uint64 `ch:"receive_ts"`
	TransmitTS  uint64 `ch:"transmit_ts"`

	NTPRaw []byte `ch:"ntp_raw"`
}

func (c *NTPComponent) Kind() uint   { return ComponentNTP }
func (c *NTPComponent) Name() string { return "ntp" }
func (c *NTPComponent) Order() uint          { return OrderL7Base }
func (c *NTPComponent) Index() uint16        { return 0 }
func (c *NTPComponent) SetIndex(_ uint16)    {}
func (c *NTPComponent) HeaderLen() int       { return len(c.NTPRaw) }
func (c *NTPComponent) FetchOrderBy() string { return "packet_id" }

func (c *NTPComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *NTPComponent) ClickhouseValues() ([]any, error) {
	return GetClickhouseValuesFrom(c)
}

func (c *NTPComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.SessionID = nucleus.SessionID
	c.Ts = nucleus.Timestamp.UnixNano()
	c.PacketID = nucleus.PacketID
}

func (c *NTPComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("ntp component missing")
	}
	ctx.Layers = append(ctx.Layers, gopacket.Payload(c.NTPRaw))
	ctx.Offset += len(c.NTPRaw)
	return nil
}

func (c *NTPComponent) DataColumns(tableAlias string) ([]string, error) {
	return GetDataColumnsFrom(c, tableAlias)
}

func (c *NTPComponent) Encode(layer gopacket.Layer) ([]Component, error) {
	ntp, ok := layer.(*layers.NTP)
	if !ok {
		return nil, errors.New("unsupported ntp layer")
	}
	contents := ntp.LayerContents()
	if len(contents) < 48 {
		return nil, ErrShortFrame
	}

	return []Component{&NTPComponent{
		CodecVersion:   CodecVersionV1,
		LeapIndicator:  uint8(ntp.LeapIndicator),
		Version:        uint8(ntp.Version),
		Mode:           uint8(ntp.Mode),
		Stratum:        uint8(ntp.Stratum),
		Poll:           int8(ntp.Poll),
		Precision:      int8(ntp.Precision),
		RootDelay:      uint32(ntp.RootDelay),
		RootDispersion: uint32(ntp.RootDispersion),
		ReferenceID:    uint32(ntp.ReferenceID),
		ReferenceTS:    uint64(ntp.ReferenceTimestamp),
		OriginTS:       uint64(ntp.OriginTimestamp),
		ReceiveTS:      uint64(ntp.ReceiveTimestamp),
		TransmitTS:     uint64(ntp.TransmitTimestamp),
		NTPRaw:         copyBytes(contents),
	}}, nil
}

func (c *NTPComponent) Schema(table string) string { return applySchema(ntpSchemaSQL, table) }
func (c *NTPComponent) Indexes(_ string) []string  { return nil }
