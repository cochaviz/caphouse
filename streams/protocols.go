package streams

// TLSProtocol detects TLS handshake records by their content-type (0x16)
// and legacy record-layer version byte (0x03).
type TLSProtocol struct{}

func (TLSProtocol) Name() string { return "TLS" }

func (TLSProtocol) Detect(payload []byte) bool {
	return len(payload) >= 3 && payload[0] == 0x16 && payload[1] == 0x03
}

// SSHProtocol detects SSH by its protocol banner prefix.
type SSHProtocol struct{}

func (SSHProtocol) Name() string { return "SSH" }

func (SSHProtocol) Detect(payload []byte) bool {
	return len(payload) >= 4 && string(payload[:4]) == "SSH-"
}
