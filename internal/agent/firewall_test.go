package agent

import (
	"net/netip"
	"testing"
	"time"

	"github.com/NazifSelimi/httpowl-api/internal/wire"
)

func TestSafeBlocksNeverCoversAllowed(t *testing.T) {
	allow := []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("127.0.0.1")}
	got := safeBlocks([]string{
		"203.0.113.0/24",  // contains an allowed IP -> dropped
		"198.51.100.7",    // plain IP -> /32
		"10.0.0.0/8",      // private -> dropped
		"0.0.0.0/0",       // too broad -> dropped
		"2001:db8::/16",   // too broad -> dropped
		"192.0.2.0/24",    // ok
		"198.51.100.7/32", // duplicate
		"garbage",
	}, allow)
	want := []string{"192.0.2.0/24", "198.51.100.7/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestBotWatcher(t *testing.T) {
	b := newBotWatcher()
	b.see(wire.Request{IP: "192.0.2.1", UA: "AhrefsBot/7.0"})
	if len(b.activeIPs()) != 0 {
		t.Fatal("blocked without a pattern")
	}
	b.setPatterns([]string{"ahrefsbot"})
	b.see(wire.Request{IP: "192.0.2.1", UA: "Mozilla/5.0 (compatible; AhrefsBot/7.0)"})
	b.see(wire.Request{IP: "192.0.2.2", UA: "Mozilla/5.0 Chrome"})
	if ips := b.activeIPs(); len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Fatalf("got %v", ips)
	}
	b.ips["192.0.2.1"] = time.Now().Add(-time.Second)
	if len(b.activeIPs()) != 0 {
		t.Fatal("expired block kept")
	}
}
