package caphouse

// pcapng.go is the single explicit entry point for pcapng awareness.
// Everything downstream (ingest batching, ClickHouse inserts, export) reuses
// the classical PCAP path unchanged.

import (
	"errors"
	"fmt"
	"io"

	"github.com/google/gopacket/pcapgo"
)

// ErrPcapNG is returned by ParseGlobalHeader when the stream is pcapng.
// Callers should pass the reader to ParseNgCaptureMeta for processing.
var ErrPcapNG = errors.New("pcapng format")

// ParseNgCaptureMeta opens a pcapng stream and returns a CaptureMeta
// populated from the SHB/IDB, along with an NgReader positioned at the first
// packet. All pcapng block metadata is discarded; packets flow through the
// classical PCAP ingest path.
func ParseNgCaptureMeta(r io.Reader) (CaptureMeta, *pcapgo.NgReader, error) {
	ngr, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return CaptureMeta{}, nil, fmt.Errorf("pcapng reader: %w", err)
	}
	meta := CaptureMeta{
		Endianness:     "le",
		TimeResolution: "us",
		LinkType:       uint32(ngr.LinkType()),
		Snaplen:        65535,
	}
	return meta, ngr, nil
}
