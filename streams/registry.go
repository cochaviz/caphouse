package streams

// Protocols is the ordered list of supported L7 protocols.
// Detection is first-match; order matters.
var Protocols = []Protocol{
	TLSProtocol{},
	SSHProtocol{},
	HTTPProtocol{},
}

// Detect returns the first protocol whose Detect method matches payload,
// or nil if no protocol matches.
func Detect(payload []byte) Protocol {
	for _, p := range Protocols {
		if p.Detect(payload) {
			return p
		}
	}
	return nil
}
