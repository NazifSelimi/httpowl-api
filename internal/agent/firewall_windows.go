//go:build windows

package agent

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

func detectFirewall() firewall {
	if _, err := exec.LookPath("netsh"); err == nil {
		return &windowsFW{}
	}
	return noFirewall{}
}

// windowsFW adds inbound block rules named "HTTPowl block N" for TCP 80/443.
// Windows block rules beat allow rules, so allowed IPs are removed from the
// block list before applying (safeBlocks already drops ranges containing them).
type windowsFW struct{}

func (w *windowsFW) Name() string { return "windows" }

func (w *windowsFW) Apply(block []netip.Prefix, allow []netip.Addr) error {
	_ = w.Cleanup()
	for i := 0; i < len(block); i += 200 {
		chunk := block[i:min(i+200, len(block))]
		ips := make([]string, len(chunk))
		for j, p := range chunk {
			ips[j] = p.String()
		}
		name := fmt.Sprintf("name=HTTPowl block %d", i/200+1)
		out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", name,
			"dir=in", "action=block", "protocol=TCP", "localport=80,443", "remoteip="+strings.Join(ips, ",")).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (w *windowsFW) Cleanup() error {
	out, _ := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all").Output()
	seen := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if i := strings.Index(l, "HTTPowl block "); i >= 0 && !seen[l[i:]] {
			seen[l[i:]] = true
			_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+l[i:]).Run()
		}
	}
	return nil
}
