package components

import (
	"net/netip"
	"strings"
)

func applySchema(sql, table string) string {
	return strings.ReplaceAll(sql, "{{ table }}", table)
}

func shortErr(msg string) string {
	if len(msg) <= 200 {
		return msg
	}
	return msg[:200]
}

func ipv4String(addr netip.Addr) string {
	if addr.IsValid() && addr.Is4() {
		return addr.String()
	}
	return "0.0.0.0"
}

func ipv6String(addr netip.Addr) string {
	if addr.IsValid() && addr.Is6() {
		return addr.String()
	}
	return "::"
}
