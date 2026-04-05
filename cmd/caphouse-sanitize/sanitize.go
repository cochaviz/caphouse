package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// sanitize reads packets from r, rewrites public IP and MAC addresses using m,
// and writes the result to w.
func sanitize(r io.Reader, w io.Writer, m *mapper) error {
	pr, err := pcapgo.NewReader(r)
	if err != nil {
		return fmt.Errorf("open pcap reader: %w", err)
	}

	pw := pcapgo.NewWriter(w)
	if err := pw.WriteFileHeader(pr.Snaplen(), pr.LinkType()); err != nil {
		return fmt.Errorf("write pcap header: %w", err)
	}

	src := gopacket.NewPacketSource(pr, pr.LinkType())

	for {
		pkt, err := src.NextPacket()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read packet: %w", err)
		}

		// Work on a copy so we never alias gopacket's internal read buffer.
		raw := make([]byte, len(pkt.Data()))
		copy(raw, pkt.Data())

		rewritePacket(pkt, raw, m)

		ci := pkt.Metadata().CaptureInfo
		ci.CaptureLength = len(raw)
		ci.Length = len(raw)
		if err := pw.WritePacket(ci, raw); err != nil {
			return fmt.Errorf("write packet: %w", err)
		}
	}
	return nil
}

// rewritePacket modifies raw (a copy of the packet bytes) in-place, replacing
// public IP and MAC addresses using m, then recomputing affected checksums.
//
// gopacket layer fields (SrcIP, DstMAC, etc.) are slices into pkt's internal
// read buffer — NOT into raw. We therefore compute the byte offset of each
// field within pkt.Data() and apply the same offset into raw.
func rewritePacket(pkt gopacket.Packet, raw []byte, m *mapper) {
	base := pkt.Data()

	if eth, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		rewriteAtOffset(raw, base, eth.SrcMAC, m.mac(eth.SrcMAC))
		rewriteAtOffset(raw, base, eth.DstMAC, m.mac(eth.DstMAC))
	}

	if ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		rewriteAtOffset(raw, base, ip4.SrcIP.To4(), m.ipv4(ip4.SrcIP))
		rewriteAtOffset(raw, base, ip4.DstIP.To4(), m.ipv4(ip4.DstIP))
		recomputeIPv4Checksum(raw, base, ip4)
		if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
			recomputeTCPChecksum(raw, base, ip4, tcp)
		}
		if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
			recomputeUDPChecksum(raw, base, ip4, udp)
		}
	}

	if ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		rewriteAtOffset(raw, base, ip6.SrcIP, m.ipv6(ip6.SrcIP))
		rewriteAtOffset(raw, base, ip6.DstIP, m.ipv6(ip6.DstIP))
		if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
			recomputeTCPv6Checksum(raw, base, ip6, tcp)
		}
		if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
			recomputeUDPv6Checksum(raw, base, ip6, udp)
		}
	}
}

// rewriteAtOffset finds the byte offset of src within base and writes dst
// into raw at the same offset.
func rewriteAtOffset(raw, base, src, dst []byte) {
	if len(src) == 0 || len(dst) == 0 {
		return
	}
	off := offsetOf(base, src)
	if off < 0 || off+len(dst) > len(raw) {
		return
	}
	copy(raw[off:], dst)
}

// offsetOf returns the byte offset of sub within base, relying on the fact
// that sub is a sub-slice of base (same backing array). Returns -1 if not found.
func offsetOf(base, sub []byte) int {
	if len(sub) > len(base) {
		return -1
	}
	for i := 0; i <= len(base)-len(sub); i++ {
		if &base[i] == &sub[0] {
			return i
		}
	}
	return -1
}

// --- Checksum helpers --------------------------------------------------------

func ipv4HeaderAt(raw, base []byte, ip4 *layers.IPv4) []byte {
	off := offsetOf(base, ip4.Contents)
	if off < 0 || off+len(ip4.Contents) > len(raw) {
		return nil
	}
	return raw[off : off+len(ip4.Contents)]
}

func recomputeIPv4Checksum(raw, base []byte, ip4 *layers.IPv4) {
	hdr := ipv4HeaderAt(raw, base, ip4)
	if len(hdr) < 20 {
		return
	}
	hdr[10] = 0
	hdr[11] = 0
	binary.BigEndian.PutUint16(hdr[10:12], internetChecksum(hdr))
}

func transportAt(raw, base, contents []byte) []byte {
	off := offsetOf(base, contents)
	if off < 0 {
		return nil
	}
	return raw[off:]
}

func recomputeTCPChecksum(raw, base []byte, ip4 *layers.IPv4, tcp *layers.TCP) {
	seg := transportAt(raw, base, tcp.Contents)
	if len(seg) < 20 {
		return
	}
	srcOff := offsetOf(base, ip4.SrcIP.To4())
	dstOff := offsetOf(base, ip4.DstIP.To4())
	if srcOff < 0 || dstOff < 0 {
		return
	}
	seg[16] = 0
	seg[17] = 0
	binary.BigEndian.PutUint16(seg[16:18], tcpUDPChecksum(raw[srcOff:srcOff+4], raw[dstOff:dstOff+4], 6, seg))
}

func recomputeUDPChecksum(raw, base []byte, ip4 *layers.IPv4, udp *layers.UDP) {
	seg := transportAt(raw, base, udp.Contents)
	if len(seg) < 8 {
		return
	}
	srcOff := offsetOf(base, ip4.SrcIP.To4())
	dstOff := offsetOf(base, ip4.DstIP.To4())
	if srcOff < 0 || dstOff < 0 {
		return
	}
	seg[6] = 0
	seg[7] = 0
	ck := tcpUDPChecksum(raw[srcOff:srcOff+4], raw[dstOff:dstOff+4], 17, seg)
	if ck == 0 {
		ck = 0xffff
	}
	binary.BigEndian.PutUint16(seg[6:8], ck)
}

func recomputeTCPv6Checksum(raw, base []byte, ip6 *layers.IPv6, tcp *layers.TCP) {
	seg := transportAt(raw, base, tcp.Contents)
	if len(seg) < 20 {
		return
	}
	srcOff := offsetOf(base, ip6.SrcIP)
	dstOff := offsetOf(base, ip6.DstIP)
	if srcOff < 0 || dstOff < 0 {
		return
	}
	seg[16] = 0
	seg[17] = 0
	binary.BigEndian.PutUint16(seg[16:18], tcpUDPChecksum(raw[srcOff:srcOff+16], raw[dstOff:dstOff+16], 6, seg))
}

func recomputeUDPv6Checksum(raw, base []byte, ip6 *layers.IPv6, udp *layers.UDP) {
	seg := transportAt(raw, base, udp.Contents)
	if len(seg) < 8 {
		return
	}
	srcOff := offsetOf(base, ip6.SrcIP)
	dstOff := offsetOf(base, ip6.DstIP)
	if srcOff < 0 || dstOff < 0 {
		return
	}
	seg[6] = 0
	seg[7] = 0
	ck := tcpUDPChecksum(raw[srcOff:srcOff+16], raw[dstOff:dstOff+16], 17, seg)
	if ck == 0 {
		ck = 0xffff
	}
	binary.BigEndian.PutUint16(seg[6:8], ck)
}

// internetChecksum computes the RFC 1071 one's-complement checksum.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpUDPChecksum computes the TCP/UDP checksum over a pseudo-header plus the
// segment. proto is 6 (TCP) or 17 (UDP). src/dst are 4- or 16-byte IP addrs.
func tcpUDPChecksum(src, dst []byte, proto byte, seg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 != 0 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src)
	add(dst)
	segLen := uint16(len(seg))
	pseudo := [4]byte{0, proto, byte(segLen >> 8), byte(segLen)}
	add(pseudo[:])
	add(seg)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// --- Address mapper ----------------------------------------------------------

// mapper holds the HMAC key and per-type caches so each distinct address maps
// to exactly one pseudonym. A single mapper should be reused across all files
// in a batch so the same address maps to the same pseudonym everywhere.
type mapper struct {
	key     []byte
	ipv4Map map[[4]byte][4]byte
	ipv6Map map[[16]byte][16]byte
	macMap  map[[6]byte][6]byte
}

func newMapper(seed []byte) *mapper {
	return &mapper{
		key:     seed,
		ipv4Map: make(map[[4]byte][4]byte),
		ipv6Map: make(map[[16]byte][16]byte),
		macMap:  make(map[[6]byte][6]byte),
	}
}

func (m *mapper) digest(domain byte, addr []byte) []byte {
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte{domain})
	h.Write(addr)
	return h.Sum(nil)
}

// isPublicIP reports whether ip is a globally routable unicast address.
// Private (RFC 1918 / RFC 4193), loopback, link-local, multicast, and
// unspecified addresses are considered non-public and left unchanged.
func isPublicIP(ip net.IP) bool {
	return !ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}

// ipv4 returns a deterministic pseudonym for src if it is a public address,
// preserving the first octet. Non-public addresses are returned unchanged.
func (m *mapper) ipv4(src net.IP) net.IP {
	src4 := src.To4()
	if src4 == nil {
		return src
	}
	if !isPublicIP(src4) {
		return src4
	}
	var key [4]byte
	copy(key[:], src4)
	if cached, ok := m.ipv4Map[key]; ok {
		out := make(net.IP, 4)
		copy(out, cached[:])
		return out
	}
	d := m.digest(0x04, src4)
	var out [4]byte
	out[0] = src4[0]
	out[1] = d[0]
	out[2] = d[1]
	out[3] = d[2]
	switch out[3] {
	case 0:
		out[3] = 1
	case 255:
		out[3] = 254
	}
	m.ipv4Map[key] = out
	result := make(net.IP, 4)
	copy(result, out[:])
	return result
}

// ipv6 returns a deterministic pseudonym for src if it is a public address,
// preserving the first 2 bytes. Non-public addresses are returned unchanged.
func (m *mapper) ipv6(src net.IP) net.IP {
	src16 := src.To16()
	if src16 == nil {
		return src
	}
	if !isPublicIP(src16) {
		return src16
	}
	var key [16]byte
	copy(key[:], src16)
	if cached, ok := m.ipv6Map[key]; ok {
		out := make(net.IP, 16)
		copy(out, cached[:])
		return out
	}
	d := m.digest(0x06, src16)
	var out [16]byte
	out[0] = src16[0]
	out[1] = src16[1]
	copy(out[2:], d[:14])
	m.ipv6Map[key] = out
	result := make(net.IP, 16)
	copy(result, out[:])
	return result
}

// mac returns a deterministic pseudonym for src. Multicast (LSB of first
// octet set), broadcast, and zero MACs are returned unchanged. All other
// unicast MACs are replaced with locally-administered unicast MACs (0x02:...).
func (m *mapper) mac(src net.HardwareAddr) net.HardwareAddr {
	if len(src) != 6 {
		return src
	}
	if src[0]&0x01 != 0 {
		return src
	}
	allSame := true
	b0 := src[0]
	for _, b := range src[1:] {
		if b != b0 {
			allSame = false
			break
		}
	}
	if allSame && (b0 == 0x00 || b0 == 0xff) {
		return src
	}
	var key [6]byte
	copy(key[:], src)
	if cached, ok := m.macMap[key]; ok {
		out := make(net.HardwareAddr, 6)
		copy(out, cached[:])
		return out
	}
	d := m.digest(0x0e, src)
	var out [6]byte
	out[0] = 0x02 // locally administered, unicast
	binary.BigEndian.PutUint32(out[1:5], binary.BigEndian.Uint32(d[:4]))
	out[5] = d[4]
	m.macMap[key] = out
	result := make(net.HardwareAddr, 6)
	copy(result, out[:])
	return result
}
