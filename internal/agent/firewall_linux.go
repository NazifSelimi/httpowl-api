//go:build linux

package agent

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

func detectFirewall() firewall {
	if p, err := exec.LookPath("nft"); err == nil {
		return &nftables{bin: p}
	}
	ipt, err1 := exec.LookPath("iptables")
	ips, err2 := exec.LookPath("ipset")
	if err1 == nil && err2 == nil {
		return &iptablesFW{iptables: ipt, ipset: ips}
	}
	return noFirewall{}
}

// nftables: one table "inet httpowl", replaced atomically on each apply.
// It only ever drops ports 80/443; its "accept" verdicts only skip our own drops
// (other tables such as ufw still run), so it can't open anything up.
type nftables struct{ bin string }

func (n *nftables) Name() string { return "nftables" }

func (n *nftables) Apply(block []netip.Prefix, allow []netip.Addr) error {
	return n.run(nftScript(block, allow))
}

// nftScript builds the full, atomic replacement of table inet httpowl.
func nftScript(block []netip.Prefix, allow []netip.Addr) string {
	var b4, b6 []string
	for _, p := range block {
		if p.Addr().Is4() {
			b4 = append(b4, p.String())
		} else {
			b6 = append(b6, p.String())
		}
	}
	var a4, a6 []string
	for _, a := range allow {
		if a.Is4() {
			a4 = append(a4, a.String())
		} else {
			a6 = append(a6, a.String())
		}
	}
	var s strings.Builder
	s.WriteString("table inet httpowl {}\ndelete table inet httpowl\ntable inet httpowl {\n")
	set := func(name, typ string, elems []string) {
		fmt.Fprintf(&s, "  set %s { type %s; flags interval; auto-merge;", name, typ)
		if len(elems) > 0 {
			s.WriteString(" elements = { " + strings.Join(elems, ", ") + " };")
		}
		s.WriteString(" }\n")
	}
	set("allow4", "ipv4_addr", a4)
	set("allow6", "ipv6_addr", a6)
	set("block4", "ipv4_addr", b4)
	set("block6", "ipv6_addr", b6)
	s.WriteString(`  chain input {
    type filter hook input priority filter - 5; policy accept;
    meta l4proto != { tcp, udp } accept
    th dport != { 80, 443 } accept
    ip saddr @allow4 accept
    ip6 saddr @allow6 accept
    ip saddr @block4 counter drop
    ip6 saddr @block6 counter drop
  }
}
`)
	return s.String()
}

func (n *nftables) Cleanup() error {
	return n.run("table inet httpowl {}\ndelete table inet httpowl\n")
}

func (n *nftables) run(script string) error {
	cmd := exec.Command(n.bin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, firstLine(errb.String()))
	}
	return nil
}

// iptablesFW: ipsets + one chain HTTPOWL jumped to from INPUT (ports 80/443 only).
type iptablesFW struct{ iptables, ipset string }

func (f *iptablesFW) Name() string { return "iptables" }

func (f *iptablesFW) Apply(block []netip.Prefix, allow []netip.Addr) error {
	var r strings.Builder
	for _, fam := range []struct{ suf, family string }{{"4", "inet"}, {"6", "inet6"}} {
		fmt.Fprintf(&r, "create httpowl-allow%s hash:net family %s -exist\n", fam.suf, fam.family)
		fmt.Fprintf(&r, "create httpowl-block%s hash:net family %s maxelem 1000000 -exist\n", fam.suf, fam.family)
		fmt.Fprintf(&r, "create httpowl-tmpa%s hash:net family %s -exist\nflush httpowl-tmpa%s\n", fam.suf, fam.family, fam.suf)
		fmt.Fprintf(&r, "create httpowl-tmpb%s hash:net family %s maxelem 1000000 -exist\nflush httpowl-tmpb%s\n", fam.suf, fam.family, fam.suf)
	}
	for _, a := range allow {
		suf := "4"
		if a.Is6() {
			suf = "6"
		}
		fmt.Fprintf(&r, "add httpowl-tmpa%s %s -exist\n", suf, a)
	}
	for _, p := range block {
		suf := "4"
		if p.Addr().Is6() {
			suf = "6"
		}
		fmt.Fprintf(&r, "add httpowl-tmpb%s %s -exist\n", suf, p)
	}
	for _, suf := range []string{"4", "6"} {
		fmt.Fprintf(&r, "swap httpowl-tmpa%s httpowl-allow%s\nswap httpowl-tmpb%s httpowl-block%s\ndestroy httpowl-tmpa%s\ndestroy httpowl-tmpb%s\n", suf, suf, suf, suf, suf, suf)
	}
	cmd := exec.Command(f.ipset, "restore")
	cmd.Stdin = strings.NewReader(r.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ipset: %v: %s", err, firstLine(string(out)))
	}
	for _, v := range []struct{ bin, suf string }{{f.iptables, "4"}, {"ip6tables", "6"}} {
		if v.suf == "6" {
			if _, err := exec.LookPath("ip6tables"); err != nil {
				continue
			}
		}
		ipt := func(args ...string) error { return exec.Command(v.bin, append([]string{"-w"}, args...)...).Run() }
		_ = ipt("-N", "HTTPOWL")
		if err := ipt("-F", "HTTPOWL"); err != nil {
			return fmt.Errorf("%s: cannot manage chain HTTPOWL", v.bin)
		}
		_ = ipt("-A", "HTTPOWL", "-m", "set", "--match-set", "httpowl-allow"+v.suf, "src", "-j", "RETURN")
		_ = ipt("-A", "HTTPOWL", "-m", "set", "--match-set", "httpowl-block"+v.suf, "src", "-j", "DROP")
		for _, proto := range []string{"tcp", "udp"} {
			jump := []string{"INPUT", "-p", proto, "-m", "multiport", "--dports", "80,443", "-j", "HTTPOWL"}
			if ipt(append([]string{"-C"}, jump...)...) != nil {
				if err := ipt(append([]string{"-I"}, jump...)...); err != nil {
					return fmt.Errorf("%s: cannot add jump to HTTPOWL", v.bin)
				}
			}
		}
	}
	return nil
}

func (f *iptablesFW) Cleanup() error {
	for _, bin := range []string{f.iptables, "ip6tables"} {
		for _, proto := range []string{"tcp", "udp"} {
			for exec.Command(bin, "-w", "-D", "INPUT", "-p", proto, "-m", "multiport", "--dports", "80,443", "-j", "HTTPOWL").Run() == nil {
			}
		}
		_ = exec.Command(bin, "-w", "-F", "HTTPOWL").Run()
		_ = exec.Command(bin, "-w", "-X", "HTTPOWL").Run()
	}
	for _, s := range []string{"allow4", "allow6", "block4", "block6"} {
		_ = exec.Command(f.ipset, "destroy", "httpowl-"+s).Run()
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}
