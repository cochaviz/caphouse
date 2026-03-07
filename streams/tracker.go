package streams

import (
	"net/netip"
	"sync"

	"caphouse/components"

	"github.com/google/uuid"
)

const maxPayloadBuf = 1024

// flowKey is the canonical (bidirectional) 5-tuple key for a TCP stream.
// lo/hi ordering ensures both directions map to the same key.
type flowKey struct {
	captureID uuid.UUID
	proto     uint8
	loIP      [16]byte
	hiIP      [16]byte
	loPort    uint16
	hiPort    uint16
}

func canonicalKey(captureID uuid.UUID, srcIP, dstIP netip.Addr, srcPort, dstPort uint16) flowKey {
	src16 := srcIP.As16()
	dst16 := dstIP.As16()

	var loIP, hiIP [16]byte
	var loPort, hiPort uint16

	// Canonical ordering: lower IP first; on tie, lower port first.
	cmp := compareBytes(src16[:], dst16[:])
	if cmp < 0 || (cmp == 0 && srcPort <= dstPort) {
		loIP, hiIP = src16, dst16
		loPort, hiPort = srcPort, dstPort
	} else {
		loIP, hiIP = dst16, src16
		loPort, hiPort = dstPort, srcPort
	}

	return flowKey{
		captureID: captureID,
		proto:     6, // TCP
		loIP:      loIP,
		hiIP:      hiIP,
		loPort:    loPort,
		hiPort:    hiPort,
	}
}

func compareBytes(a, b []byte) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// streamState tracks the evolving state of a single TCP stream.
type streamState struct {
	streamID   uuid.UUID
	synSrcIP   netip.Addr
	synDstIP   netip.Addr
	synSrcPort uint16
	synDstPort uint16

	hasSYN    bool
	hasSYNACK bool

	proto      Protocol // nil until identified
	session    Session  // non-nil only for SessionProtocol
	payloadBuf []byte   // nil after identification or abandon

	firstPacketID uint64
	lastPacketID  uint64
	packetCount   uint64
	byteCount     uint64
}

// Tracker observes encoded TCP packets and accumulates per-stream state.
type Tracker struct {
	mu    sync.Mutex
	flows map[flowKey]*streamState
}

// NewTracker creates a Tracker.
func NewTracker() *Tracker {
	return &Tracker{
		flows: make(map[flowKey]*streamState),
	}
}

// Observe processes one encoded packet. Only packets with the TCP component set
// are considered. Safe for concurrent use.
func (t *Tracker) Observe(nucleus components.PacketNucleus, comps []components.ClickhouseMappedDecoder) {
	if !components.ComponentHas(nucleus.Components, components.ComponentTCP) {
		return
	}

	var tcpComp *components.TCPComponent
	var ipv4Comp *components.IPv4Component
	var ipv6Comp *components.IPv6Component
	var rawTailComp *components.RawTailComponent

	for _, comp := range comps {
		switch c := comp.(type) {
		case *components.TCPComponent:
			tcpComp = c
		case *components.IPv4Component:
			ipv4Comp = c
		case *components.IPv6Component:
			ipv6Comp = c
		case *components.RawTailComponent:
			rawTailComp = c
		}
	}

	if tcpComp == nil {
		return
	}

	var srcIP, dstIP netip.Addr
	if ipv4Comp != nil {
		srcIP = ipv4Comp.SrcIP4.Unmap()
		dstIP = ipv4Comp.DstIP4.Unmap()
	} else if ipv6Comp != nil {
		srcIP = ipv6Comp.SrcIP6
		dstIP = ipv6Comp.DstIP6
	}

	if !srcIP.IsValid() || !dstIP.IsValid() {
		return
	}

	key := canonicalKey(nucleus.CaptureID, srcIP, dstIP, tcpComp.SrcPort, tcpComp.DstPort)

	t.mu.Lock()
	defer t.mu.Unlock()

	st, exists := t.flows[key]
	if !exists {
		// payloadBuf starts as an empty (non-nil) slice to signal "still accumulating".
		st = &streamState{
			streamID:      uuid.New(),
			firstPacketID: nucleus.PacketID,
			payloadBuf:    []byte{},
		}
		t.flows[key] = st
	}

	st.lastPacketID = nucleus.PacketID
	st.packetCount++
	if rawTailComp != nil {
		st.byteCount += uint64(len(rawTailComp.Bytes))
	}

	isSYN := tcpComp.Flags&components.TCPFlagSYN != 0
	isACK := tcpComp.Flags&components.TCPFlagACK != 0

	if isSYN && !isACK && !st.hasSYN {
		// First SYN: record stream direction from SYN sender.
		st.hasSYN = true
		st.synSrcIP = srcIP
		st.synDstIP = dstIP
		st.synSrcPort = tcpComp.SrcPort
		st.synDstPort = tcpComp.DstPort
	} else if isSYN && isACK && st.hasSYN {
		st.hasSYNACK = true
	}

	// Attempt L7 protocol detection.
	// payloadBuf == nil means detection has already concluded (matched or abandoned).
	if st.proto == nil && st.payloadBuf != nil && rawTailComp != nil && len(rawTailComp.Bytes) > 0 {
		st.payloadBuf = append(st.payloadBuf, rawTailComp.Bytes...)
		if proto := Detect(st.payloadBuf); proto != nil {
			st.proto = proto
			if sp, ok := proto.(SessionProtocol); ok {
				st.session = sp.NewSession(st.streamID, nucleus.CaptureID)
			}
			st.payloadBuf = nil
		} else if len(st.payloadBuf) >= maxPayloadBuf {
			st.payloadBuf = nil // give up
		}
	}

	if st.session != nil && rawTailComp != nil && len(rawTailComp.Bytes) > 0 {
		st.session.Feed(rawTailComp.Bytes)
	}
}

// StreamRecord is the exported view of a completed stream for insertion.
type StreamRecord struct {
	CaptureID uuid.UUID
	StreamID  uuid.UUID

	SynSrcIP   netip.Addr
	SynDstIP   netip.Addr
	SynSrcPort uint16
	SynDstPort uint16

	HasSYN    bool
	HasSYNACK bool

	Proto   Protocol
	Session Session

	FirstPacketID uint64
	LastPacketID  uint64
	PacketCount   uint64
	ByteCount     uint64
}

// QualifyingStreams drains the tracker and returns streams where both SYN and
// SYN-ACK were observed and L7 protocol was identified.
func (t *Tracker) QualifyingStreams() []*StreamRecord {
	t.mu.Lock()
	flows := t.flows
	t.flows = make(map[flowKey]*streamState)
	t.mu.Unlock()

	var out []*StreamRecord
	for key, st := range flows {
		if !st.hasSYN || !st.hasSYNACK || st.proto == nil {
			continue
		}
		out = append(out, &StreamRecord{
			CaptureID:     key.captureID,
			StreamID:      st.streamID,
			SynSrcIP:      st.synSrcIP,
			SynDstIP:      st.synDstIP,
			SynSrcPort:    st.synSrcPort,
			SynDstPort:    st.synDstPort,
			HasSYN:        st.hasSYN,
			HasSYNACK:     st.hasSYNACK,
			Proto:         st.proto,
			Session:       st.session,
			FirstPacketID: st.firstPacketID,
			LastPacketID:  st.lastPacketID,
			PacketCount:   st.packetCount,
			ByteCount:     st.byteCount,
		})
	}
	return out
}
