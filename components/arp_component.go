package components

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

//go:embed arp_schema.sql
var arpSchemaSQL string

// ARPComponent stores parsed ARP header fields.
type ARPComponent struct {
	CaptureID    uuid.UUID `ch:"capture_id"`
	PacketID     uint64    `ch:"packet_id"`
	CodecVersion uint16    `ch:"codec_version"`

	ArpOp     uint16   `ch:"arp_op"`
	SenderMAC [6]byte  `ch:"sender_mac"`
	SenderIP  net.IP   `ch:"sender_ip"`
	TargetMAC [6]byte  `ch:"target_mac"`
	TargetIP  net.IP   `ch:"target_ip"`
}

func (c *ARPComponent) Kind() uint           { return ComponentARP }
func (c *ARPComponent) Table() string        { return "pcap_arp" }
func (c *ARPComponent) Order() uint          { return OrderL4Base }
func (c *ARPComponent) Index() uint16        { return 0 }
func (c *ARPComponent) SetIndex(_ uint16)    {}
func (c *ARPComponent) HeaderLen() int       { return 28 }
func (c *ARPComponent) FetchOrderBy() string { return "packet_id" }

func (c *ARPComponent) ClickhouseColumns() ([]string, error) {
	return []string{
		"capture_id", "packet_id", "codec_version",
		"arp_op", "sender_mac", "sender_ip", "target_mac", "target_ip",
	}, nil
}

func (c *ARPComponent) ClickhouseValues() ([]any, error) {
	return []any{
		c.CaptureID, c.PacketID, c.CodecVersion,
		c.ArpOp, string(c.SenderMAC[:]), c.SenderIP, string(c.TargetMAC[:]), c.TargetIP,
	}, nil
}

func (c *ARPComponent) ApplyNucleus(nucleus PacketNucleus) {
	c.CaptureID = nucleus.CaptureID
	c.PacketID = nucleus.PacketID
}

func (c *ARPComponent) Reconstruct(ctx *DecodeContext) error {
	if c == nil {
		return errors.New("arp component missing")
	}
	// Standard Ethernet/IPv4 ARP: 28 bytes
	// HTYPE(2) PTYPE(2) HLEN(1) PLEN(1) OPER(2) SHA(6) SPA(4) THA(6) TPA(4)
	var hdr [28]byte
	binary.BigEndian.PutUint16(hdr[0:2], 1)    // HTYPE: Ethernet
	binary.BigEndian.PutUint16(hdr[2:4], 0x0800) // PTYPE: IPv4
	hdr[4] = 6                                  // HLEN: 6
	hdr[5] = 4                                  // PLEN: 4
	binary.BigEndian.PutUint16(hdr[6:8], c.ArpOp)
	copy(hdr[8:14], c.SenderMAC[:])
	ip4 := c.SenderIP.To4()
	if ip4 != nil {
		copy(hdr[14:18], ip4)
	}
	copy(hdr[18:24], c.TargetMAC[:])
	ip4 = c.TargetIP.To4()
	if ip4 != nil {
		copy(hdr[24:28], ip4)
	}
	ctx.Layers = append(ctx.Layers, gopacket.Payload(hdr[:]))
	ctx.Offset += 28
	return nil
}

func (c *ARPComponent) ScanColumns() []string {
	return []string{"packet_id", "arp_op", "sender_mac", "sender_ip", "target_mac", "target_ip"}
}

func (c *ARPComponent) ScanRow(captureID uuid.UUID, rows chdriver.Rows) (uint64, error) {
	c.CaptureID = captureID
	var senderMAC, targetMAC string
	var senderIP, targetIP net.IP
	err := rows.Scan(&c.PacketID, &c.ArpOp, &senderMAC, &senderIP, &targetMAC, &targetIP)
	if err != nil {
		return 0, err
	}
	copy(c.SenderMAC[:], senderMAC)
	copy(c.TargetMAC[:], targetMAC)
	c.SenderIP = senderIP
	c.TargetIP = targetIP
	return c.PacketID, nil
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
func (c *ARPComponent) Indexes(table string) []string {
	return []string{
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_sender_ip (sender_ip) TYPE minmax GRANULARITY 4", table),
		fmt.Sprintf("ALTER TABLE %s ADD INDEX IF NOT EXISTS idx_target_ip (target_ip) TYPE minmax GRANULARITY 4", table),
	}
}
