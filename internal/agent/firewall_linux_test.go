//go:build linux

package agent

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestNftScript(t *testing.T) {
	s := nftScript([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:1::/48")},
		[]netip.Addr{netip.MustParseAddr("203.0.113.5")})
	for _, must := range []string{"delete table inet httpowl", "th dport != { 80, 443 } accept", "ip saddr @allow4 accept", "192.0.2.0/24"} {
		if !strings.Contains(s, must) {
			t.Errorf("script lacks %q", must)
		}
	}
	if p := os.Getenv("NFT_SCRIPT_OUT"); p != "" {
		os.WriteFile(p, []byte(s), 0o644)
	}
}
