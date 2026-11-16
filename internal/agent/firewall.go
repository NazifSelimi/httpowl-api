package agent

import (
	"context"
	"crypto/sha256"

	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NazifSelimi/httpowl-api/internal/agent/sys"
	"github.com/NazifSelimi/httpowl-api/internal/wire"
)

// firewall applies the full desired state: drop web traffic (ports 80/443 only)
// from block prefixes, but always let allow IPs through. SSH is never touched.
type firewall interface {
	Name() string
	Apply(block []netip.Prefix, allow []netip.Addr) error
	Cleanup() error
}

type noFirewall struct{}

func (noFirewall) Name() string                             { return "off" }
func (noFirewall) Apply([]netip.Prefix, []netip.Addr) error { return nil }
func (noFirewall) Cleanup() error                           { return nil }

func newFirewall(mode string) firewall {
	if mode == "off" {
		return noFirewall{}
	}
	return detectFirewall()
}

// Cleanup removes everything HTTPowl added to the firewall.
func (a *Agent) Cleanup() error { return a.fw.Cleanup() }

const botBlockFor = 24 * time.Hour

type ruleState struct {
	mu       sync.Mutex
	rules    wire.Rules
	etag     string
	lastHash [32]byte
	applied  int64
}

// syncRules pulls rules (ETag-cached) and re-applies if the desired state changed.
func (a *Agent) syncRules(ctx context.Context) error {
	if _, ok := a.fw.(noFirewall); ok {
		return nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.Cfg.Server+"/api/agent/rules", nil)
	a.rs.mu.Lock()
	if a.rs.etag != "" {
		req.Header.Set("If-None-Match", a.rs.etag)
	}
	a.rs.mu.Unlock()
	var rules wire.Rules
	notModified := false
	err := a.doRaw(req, func(resp *http.Response) error {
		if resp.StatusCode == http.StatusNotModified {
			notModified = true
			return nil
		}
		a.rs.mu.Lock()
		a.rs.etag = resp.Header.Get("ETag")
		a.rs.mu.Unlock()
		return decodeJSON(resp, &rules)
	})
	if err != nil {
		return err
	}
	if !notModified {
		a.rs.mu.Lock()
		a.rs.rules = rules
		a.rs.mu.Unlock()
		a.botWatch.setPatterns(rules.BotPatterns)
	}
	return a.applyIfChanged()
}

// applyIfChanged computes block/allow sets and applies them when they differ from last time.
func (a *Agent) applyIfChanged() error {
	a.rs.mu.Lock()
	defer a.rs.mu.Unlock()
	allow := allowList(a.rs.rules.AllowIPs)
	block := safeBlocks(append(a.rs.rules.BlockCIDRs, a.botWatch.activeIPs()...), allow)
	h := hashState(block, allow)
	if h == a.rs.lastHash {
		return nil
	}
	if err := a.fw.Apply(block, allow); err != nil {
		return err
	}
	a.rs.lastHash = h
	a.rs.applied = int64(len(block))
	slog.Info("firewall updated", "blocked_ranges", len(block), "always_allowed", len(allow), "backend", a.fw.Name())
	return nil
}

// allowList = what the server says + this machine's IPs + live SSH peers + loopback.
func allowList(fromServer []string) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(s string) {
		if a, err := netip.ParseAddr(s); err == nil && !seen[a.Unmap()] {
			seen[a.Unmap()] = true
			out = append(out, a.Unmap())
		}
	}
	for _, s := range fromServer {
		add(s)
	}
	for _, s := range sys.ServerIPs() {
		add(s)
	}
	for _, s := range sys.SSHPeers() {
		add(s)
	}
	add("127.0.0.1")
	add("::1")
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// safeBlocks parses prefixes and drops anything unsafe: private ranges, too-broad
// ranges, and any range that contains an allowed IP (belt and braces with the allow set).
func safeBlocks(in []string, allow []netip.Addr) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, s := range in {
		var p netip.Prefix
		var err error
		if strings.Contains(s, "/") {
			p, err = netip.ParsePrefix(s)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(s); err == nil {
				p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
			}
		}
		if err != nil {
			continue
		}
		p = p.Masked()
		if p.Addr().Is4In6() {
			continue
		}
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 19) {
			continue
		}
		if a := p.Addr(); a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
			continue
		}
		bad := false
		for _, al := range allow {
			if p.Contains(al) {
				bad = true
				break
			}
		}
		if !bad && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out
}

func hashState(block []netip.Prefix, allow []netip.Addr) [32]byte {
	var b strings.Builder
	for _, p := range block {
		b.WriteString(p.String())
		b.WriteByte(',')
	}
	b.WriteByte('|')
	for _, a := range allow {
		b.WriteString(a.String())
		b.WriteByte(',')
	}
	return sha256.Sum256([]byte(b.String()))
}

// botWatcher blocks IPs that send a blocked bot's user agent, for 24h.
type botWatcher struct {
	mu       sync.Mutex
	patterns []string
	ips      map[string]time.Time
	dirty    bool
}

func newBotWatcher() *botWatcher { return &botWatcher{ips: map[string]time.Time{}} }

func (b *botWatcher) setPatterns(p []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.patterns = p
	if len(p) == 0 && len(b.ips) > 0 { // all bot rules removed: lift bot blocks
		b.ips = map[string]time.Time{}
		b.dirty = true
	}
}

func (b *botWatcher) see(r wire.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.patterns) == 0 || len(b.ips) >= 10000 {
		return
	}
	ua := strings.ToLower(r.UA)
	for _, p := range b.patterns {
		if strings.Contains(ua, p) {
			if _, ok := b.ips[r.IP]; !ok {
				b.dirty = true
			}
			b.ips[r.IP] = time.Now().Add(botBlockFor)
			return
		}
	}
}

func (b *botWatcher) activeIPs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	out := make([]string, 0, len(b.ips))
	for ip, exp := range b.ips {
		if now.After(exp) {
			delete(b.ips, ip)
			continue
		}
		out = append(out, ip)
	}
	b.dirty = false
	return out
}

func (b *botWatcher) takeDirty() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := b.dirty
	return d
}

// botLoop applies new bot blocks within ~5 seconds.
func (a *Agent) botLoop(ctx context.Context) error {
	if a.botWatch.takeDirty() {
		return a.applyIfChanged()
	}
	return nil
}

// FirewallName reports which backend will be used.
func (a *Agent) FirewallName() string { return a.fw.Name() }
