package components

import (
	_ "embed"
	"errors"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

//go:embed ntp_schema.sql
var ntpSchemaSQL string

// NTPComponent stores parsed NTP header fields.
// ntp_raw holds the full wire bytes for lossless reconstruction.
type NTPComponent struct {
	CaptureID    uuid.UUID `ch:"capture_id"`
	PacketID     uint64    `ch:"packet_id"`
	CodecVersion uint16    `ch:"codec_version"`

	LeapIndicator  uint8 `ch:"leap_indicator"`
	Version        uint8 `ch:"version"`
	Mode           uint8 `ch:"mode"`
	Stratum        uint8 `ch:"stratum"`
	Poll           int8  `ch:"poll"`
	Precision      int8  `ch:"precision"`
	RootDelay      uint32 `ch:"root_delay"`
	RootDispersion uint32 `ch:"root_dispersion"`
	ReferenceID    uint32 `ch:"reference_id"`

	ReferenceTS uint64 `ch:"reference_ts"`
	OriginTS    uint64 `ch:"origin_ts"`
	ReceiveTS   uint64 `ch:"receive_ts"`
	TransmitTS  uint64 `ch:"transmit_ts"`

	NTPRaw []byte `ch:"ntp_raw"`
}

func (c *NTPComponent) Kind() uint           { return ComponentNTP }
func (c *NTPComponent) Table() string        { return "pcap_ntp" }
func (c *NTPComponent) Order() uint          { return OrderL7Base }
func (c *NTPComponent) Index() uint16        { return 0 }
func (c *NTPComponent) SetIndex(_ uint16)    {}
func (c *NTPComponent) HeaderLen() int       { return len(c.NTPRaw) }
func (c *NTPComponent) FetchOrderBy() string { return "packet_id" }

func (c *NTPComponent) ClickhouseColumns() ([]string, error) {
	return GetClickhouseColumnsFrom(c)
}

func (c *NTPComponent) ClickhouseValues() ([]any, error) {
	return []any{
		c.CaptureID, c.PacketID, c.CodecVersion,
		c.LeapIndicator, c.Version, c.Mode, c.Stratum, c.Poll, c.Precision,
		c.RootDelay, c.RootDispersion, c.ReferenceID,
		c.ReferenceTS, c.OriginTS, c.ReceiveTS, c.TransmitTS,
		string(c.NTPRaw),
	}, nil
}

func (c *NTPComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
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

func (c *NTPComponent) ScanColumns() []string {
	return []string{
		"packet_id",
		"leap_indicator", "version", "mode", "stratum", "poll", "precision",
		"root_delay", "root_dispersion", "reference_id",
		"reference_ts", "origin_ts", "receive_ts", "transmit_ts",
		"ntp_raw",
	}
}

func (c *NTPComponent) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	var raw string
	c.CaptureID = captureID
	err := rows.Scan(
		&c.PacketID,
		&c.LeapIndicator, &c.Version, &c.Mode, &c.Stratum, &c.Poll, &c.Precision,
		&c.RootDelay, &c.RootDispersion, &c.ReferenceID,
		&c.ReferenceTS, &c.OriginTS, &c.ReceiveTS, &c.TransmitTS,
		&raw,
	)
	c.NTPRaw = []byte(raw)
	return c.PacketID, err
}

func (c *NTPComponent) Encode(layer gopacket.Layer) ([]ClickhouseMappedDecoder, error) {
	ntp, ok := layer.(*layers.NTP)
	if !ok {
		return nil, errors.New("unsupported ntp layer")
	}
	contents := ntp.LayerContents()
	if len(contents) < 48 {
		return nil, ErrShortFrame
	}

	return []ClickhouseMappedDecoder{&NTPComponent{
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

func NTPSchema(table string) string {
	return applySchema(ntpSchemaSQL, table)
}
