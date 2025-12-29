package components

func newIPv4OptionsComponent(raw []byte) *IPv4OptionsComponent {
	return &IPv4OptionsComponent{
		CodecVersion: CodecVersionV1,
		OptionsRaw:   copyBytes(raw),
	}
}
