package caphouse

import (
	"strings"
	"testing"
)

// parseClause is a convenience wrapper that returns just the expanded clause.
func parseClause(t *testing.T, input string) string {
	t.Helper()
	f, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse(%q) unexpected error: %v", input, err)
	}
	return f.Clause
}

func TestParse_FieldAlias_Equal(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			"ipv4.addr = '1.1.1.1'",
			"(ipv4.src = '1.1.1.1' or ipv4.dst = '1.1.1.1')",
		},
		{
			"ipv6.addr = '::1'",
			"(ipv6.src = '::1' or ipv6.dst = '::1')",
		},
		{
			"tcp.port = 443",
			"(tcp.src = 443 or tcp.dst = 443)",
		},
		{
			"udp.port = 53",
			"(udp.src = 53 or udp.dst = 53)",
		},
		{
			"ethernet.mac = 'aa:bb:cc:dd:ee:ff'",
			"(ethernet.src = 'aa:bb:cc:dd:ee:ff' or ethernet.dst = 'aa:bb:cc:dd:ee:ff')",
		},
		{
			"arp.ip = '192.168.1.1'",
			"(arp.sender_ip = '192.168.1.1' or arp.target_ip = '192.168.1.1')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseClause(t, tt.input)
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestParse_FieldAlias_NotEqual(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			"ipv4.addr != '160.79.104.10'",
			"(ipv4.src != '160.79.104.10' and ipv4.dst != '160.79.104.10')",
		},
		{
			"ipv6.addr != '::1'",
			"(ipv6.src != '::1' and ipv6.dst != '::1')",
		},
		{
			"tcp.port != 80",
			"(tcp.src != 80 and tcp.dst != 80)",
		},
		{
			"udp.port != 53",
			"(udp.src != 53 and udp.dst != 53)",
		},
		{
			"ethernet.mac != 'aa:bb:cc:dd:ee:ff'",
			"(ethernet.src != 'aa:bb:cc:dd:ee:ff' and ethernet.dst != 'aa:bb:cc:dd:ee:ff')",
		},
		{
			"arp.ip != '10.0.0.1'",
			"(arp.sender_ip != '10.0.0.1' and arp.target_ip != '10.0.0.1')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseClause(t, tt.input)
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestParse_FieldAlias_Func(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			"startsWith(ipv4.addr, '127')",
			"(startsWith(ipv4.src, '127') or startsWith(ipv4.dst, '127'))",
		},
		{
			"endsWith(ipv4.addr, '.1')",
			"(endsWith(ipv4.src, '.1') or endsWith(ipv4.dst, '.1'))",
		},
		{
			"match(ipv4.addr, '^10\\.')",
			"(match(ipv4.src, '^10\\.') or match(ipv4.dst, '^10\\.'))",
		},
		{
			"startsWith(tcp.port, '80')",
			"(startsWith(tcp.src, '80') or startsWith(tcp.dst, '80'))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseClause(t, tt.input)
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestParse_FieldAlias_Between(t *testing.T) {
	got := parseClause(t, "tcp.port between 1024 and 65535")
	want := "(tcp.src between 1024 and 65535 or tcp.dst between 1024 and 65535)"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestParse_FieldAlias_In(t *testing.T) {
	got := parseClause(t, "tcp.port in (80, 443, 8080)")
	want := "(tcp.src in (80, 443, 8080) or tcp.dst in (80, 443, 8080))"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}


func TestParse_BareComponent(t *testing.T) {
	f, err := Parse("dns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Clause != "1 = 1" {
		t.Errorf("bare component clause: got %q, want %q", f.Clause, "1 = 1")
	}
	comps := f.Components()
	if len(comps) != 1 || comps[0] != "dns" {
		t.Errorf("components: got %v, want [dns]", comps)
	}
}

func TestParse_Components_Detected(t *testing.T) {
	f, err := Parse("ipv4.dst = '1.1.1.1' and tcp.dst = 443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	comps := f.Components()
	if len(comps) != 2 {
		t.Fatalf("want 2 components, got %v", comps)
	}
	if comps[0] != "ipv4" || comps[1] != "tcp" {
		t.Errorf("want [ipv4 tcp], got %v", comps)
	}
}

func TestParse_AliasComponents_Detected(t *testing.T) {
	// ipv4.addr alias must still register ipv4 as a required component.
	f, err := Parse("ipv4.addr != '10.0.0.1'")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	comps := f.Components()
	if len(comps) != 1 || comps[0] != "ipv4" {
		t.Errorf("want [ipv4], got %v", comps)
	}
}

func TestParse_UnknownComponent(t *testing.T) {
	// Unrecognised component names are not matched by the component regex, so
	// they pass through as-is with no error and no JOIN registered.
	f, err := Parse("bogus.field = 1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Clause != "bogus.field = 1" {
		t.Errorf("unexpected clause rewrite: %q", f.Clause)
	}
	if len(f.Components()) != 0 {
		t.Errorf("expected no components, got %v", f.Components())
	}
}

func TestParse_Empty(t *testing.T) {
	f, err := Parse("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Clause != "" {
		t.Errorf("empty filter: got %q, want empty string", f.Clause)
	}
	if len(f.Components()) != 0 {
		t.Errorf("empty filter: got components %v, want none", f.Components())
	}
}

func TestParse_CombinedAliasAndLiteral(t *testing.T) {
	got := parseClause(t, "ipv4.addr != '10.0.0.1' and tcp.dst = 443")
	if !strings.Contains(got, "ipv4.src != '10.0.0.1' and ipv4.dst != '10.0.0.1'") {
		t.Errorf("ipv4.addr != not expanded correctly in: %s", got)
	}
	if !strings.Contains(got, "tcp.dst = 443") {
		t.Errorf("literal tcp.dst missing in: %s", got)
	}
}
