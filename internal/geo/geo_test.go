package geo

import (
	"net/netip"
	"os"
	"testing"
)

func TestLookup(t *testing.T) {
	p := "../../data/dbip-country-lite.mmdb"
	if _, err := os.Stat(p); err != nil {
		t.Skip("no GeoIP db in data/")
	}
	d := Open(p)
	if cc := d.Country(netip.MustParseAddr("8.8.8.8")); cc != "US" {
		t.Fatalf("8.8.8.8 -> %q", cc)
	}
	if cc := d.Country(netip.MustParseAddr("10.0.0.1")); cc != "" {
		t.Fatalf("private -> %q", cc)
	}
	if n := len(d.CountryCIDRs("MK")); n < 10 {
		t.Fatalf("MK ranges: %d", n)
	}
}
