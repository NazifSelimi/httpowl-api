package rules

import (
	"net/netip"
	"testing"
)

func TestNormalize(t *testing.T) {
	ok := map[[2]string]string{
		{KindIP, " 203.0.113.9 "}:      "203.0.113.9",
		{KindIP, "::ffff:203.0.113.9"}: "203.0.113.9",
		{KindCIDR, "203.0.113.77/24"}:  "203.0.113.0/24",
		{KindCountry, "cn"}:            "CN",
		{KindBot, "AhrefsBot"}:         "ahrefsbot",
	}
	for in, want := range ok {
		got, err := Normalize(in[0], in[1])
		if err != nil || got != want {
			t.Errorf("%v: %q %v", in, got, err)
		}
	}
	bad := [][2]string{
		{KindIP, "10.0.0.1"}, {KindIP, "127.0.0.1"}, {KindIP, "nope"},
		{KindCIDR, "0.0.0.0/0"}, {KindCIDR, "1.0.0.0/7"}, {KindCIDR, "192.168.0.0/16"}, {KindCIDR, "2001:db8::/16"},
		{KindCountry, "CHN"}, {KindBot, "mozilla"}, {KindBot, "ch"}, {KindBot, "Chrome/1"}, {"port", "22"},
	}
	for _, in := range bad {
		if _, err := Normalize(in[0], in[1]); err == nil {
			t.Errorf("%v accepted", in)
		}
	}
}

func TestCheckNeverBlocksYou(t *testing.T) {
	me := netip.MustParseAddr("198.51.100.20")
	ssh := netip.MustParseAddr("203.0.113.5")
	p := Protected{RequesterIP: me, IPs: []netip.Addr{ssh}, CountryOf: func(a netip.Addr) string {
		if a == me {
			return "MK"
		}
		return "US"
	}}
	refuse := [][2]string{
		{KindIP, "198.51.100.20"}, {KindCIDR, "198.51.100.0/24"}, {KindIP, "203.0.113.5"},
		{KindCIDR, "203.0.0.0/8"}, {KindCountry, "MK"}, {KindCountry, "US"},
	}
	for _, r := range refuse {
		if err := Check(r[0], r[1], p); err == nil {
			t.Errorf("%v allowed but blocks a protected IP", r)
		}
	}
	allow := [][2]string{{KindIP, "192.0.2.1"}, {KindCIDR, "192.0.2.0/24"}, {KindCountry, "CN"}, {KindBot, "ahrefsbot"}}
	for _, r := range allow {
		if err := Check(r[0], r[1], p); err != nil {
			t.Errorf("%v refused: %v", r, err)
		}
	}
	if err := Check(KindCountry, "CN", Protected{RequesterIP: me}); err == nil {
		t.Error("country rule without GeoIP allowed")
	}
}
