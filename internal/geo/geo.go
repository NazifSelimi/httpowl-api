// Package geo maps IPs to countries with the free DB-IP "IP to Country Lite"
// database (CC BY 4.0, https://db-ip.com), and lists a country's IP ranges for blocking.
package geo

import (
	"log/slog"
	"net/netip"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

type DB struct {
	r     *maxminddb.Reader
	mu    sync.Mutex
	cidrs map[string][]string
}

// Open loads the mmdb file. An empty path or a missing file gives a DB that knows nothing.
func Open(path string) *DB {
	d := &DB{cidrs: map[string][]string{}}
	if path == "" {
		slog.Warn("GEOIP_PATH not set: countries will be empty")
		return d
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		slog.Warn("GeoIP database not loaded: countries will be empty", "err", err)
		return d
	}
	d.r = r
	return d
}

// Ready reports whether a database is loaded.
func (d *DB) Ready() bool { return d.r != nil }

// Country returns the ISO code (e.g. "DE") or "".
func (d *DB) Country(ip netip.Addr) string {
	if d.r == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return ""
	}
	var cc string
	if err := d.r.Lookup(ip).DecodePath(&cc, "country", "iso_code"); err != nil {
		return ""
	}
	return cc
}

// CountryCIDRs lists every IP range of a country (cached; first call walks the whole DB).
func (d *DB) CountryCIDRs(cc string) []string {
	if d.r == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.cidrs[cc]; ok {
		return c
	}
	var out []string
	for res := range d.r.Networks() {
		var got string
		if err := res.DecodePath(&got, "country", "iso_code"); err == nil && got == cc {
			out = append(out, res.Prefix().String())
		}
	}
	d.cidrs[cc] = out
	return out
}
