// Package rules: reversible block rules (IP, IP range, country, bot) and the
// safety checks that stop a user from locking themselves (or SSH) out.
package rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

const (
	KindIP      = "ip"
	KindCIDR    = "cidr"
	KindCountry = "country"
	KindBot     = "bot"
)

// Protected is everything a rule must never cover.
type Protected struct {
	RequesterIP netip.Addr   // whoever is clicking "block" right now
	IPs         []netip.Addr // server IPs, live SSH peers, team login IPs
	CountryOf   func(netip.Addr) string
}

// browserWords would match real visitors' browsers, so they can't be bot rules.
var browserWords = []string{"mozilla", "chrome", "safari", "applewebkit", "gecko", "firefox", "edge", "opera", "windows", "macintosh", "iphone", "android", "linux", "mobile"}

var botRe = regexp.MustCompile(`^[a-z0-9][a-z0-9 ._/+-]{2,49}$`)
var ccRe = regexp.MustCompile(`^[A-Z]{2}$`)

// Normalize validates a rule value and returns its canonical form.
func Normalize(kind, value string) (string, error) {
	value = strings.TrimSpace(value)
	switch kind {
	case KindIP:
		a, err := netip.ParseAddr(value)
		if err != nil {
			return "", fmt.Errorf("%q is not an IP address", value)
		}
		a = a.Unmap()
		if !public(a) {
			return "", fmt.Errorf("%s is a private/local address; blocking it would break your own network", a)
		}
		return a.String(), nil
	case KindCIDR:
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return "", fmt.Errorf("%q is not an IP range like 203.0.113.0/24", value)
		}
		p = p.Masked()
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 32) {
			return "", fmt.Errorf("range %s is too big (smallest allowed: /8 for IPv4, /32 for IPv6)", p)
		}
		if !public(p.Addr()) {
			return "", fmt.Errorf("%s is a private/local range", p)
		}
		return p.String(), nil
	case KindCountry:
		cc := strings.ToUpper(value)
		if !ccRe.MatchString(cc) {
			return "", fmt.Errorf("country must be a 2-letter code like CN")
		}
		return cc, nil
	case KindBot:
		v := strings.ToLower(value)
		if !botRe.MatchString(v) {
			return "", fmt.Errorf("bot name must be 3-50 letters/digits (part of its user agent, like ahrefsbot)")
		}
		for _, w := range browserWords {
			if strings.Contains(w, v) || strings.Contains(v, w) {
				return "", fmt.Errorf("%q would match normal browsers (%s); use the bot's own name", v, w)
			}
		}
		return v, nil
	}
	return "", fmt.Errorf("kind must be ip, cidr, country or bot")
}

// Check refuses a (normalized) rule that would block a protected address.
func Check(kind, value string, p Protected) error {
	all := p.IPs
	if p.RequesterIP.IsValid() {
		all = append([]netip.Addr{p.RequesterIP}, all...)
	}
	covers := func(a netip.Addr) bool { return false }
	switch kind {
	case KindIP:
		v := netip.MustParseAddr(value)
		covers = func(a netip.Addr) bool { return a == v }
	case KindCIDR:
		v := netip.MustParsePrefix(value)
		covers = v.Contains
	case KindCountry:
		if p.CountryOf == nil {
			return fmt.Errorf("country blocking is unavailable (no GeoIP database)")
		}
		covers = func(a netip.Addr) bool { return p.CountryOf(a) == value }
	case KindBot:
		return nil // bot rules only block IPs that send that bot's user agent; protected IPs are excluded by the agent
	}
	for i, a := range all {
		if !a.IsValid() || !covers(a.Unmap()) {
			continue
		}
		if i == 0 && p.RequesterIP.IsValid() {
			return fmt.Errorf("this would block you (your IP %s); refused", a)
		}
		return fmt.Errorf("this would block %s, which is your server, an open SSH session or a team member's login IP; refused", a)
	}
	return nil
}

func public(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}
