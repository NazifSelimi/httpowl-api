// Package sys reports facts about this server that keep blocking safe:
// its own IPs and the IPs of open SSH sessions.
package sys

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// ServerIPs returns this machine's non-loopback interface addresses.
func ServerIPs() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
			out = append(out, p.Addr().String())
		}
	}
	return out
}

// SSHPorts reads Port lines from sshd_config (default 22).
func SSHPorts() []int {
	var ports []int
	for _, f := range []string{"/etc/ssh/sshd_config"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) == 2 && strings.EqualFold(fs[0], "Port") {
				if p, err := strconv.Atoi(fs[1]); err == nil {
					ports = append(ports, p)
				}
			}
		}
		fh.Close()
	}
	if len(ports) == 0 {
		ports = []int{22}
	}
	return ports
}

// SSHPeers returns remote IPs with an ESTABLISHED connection to an SSH port (Linux).
func SSHPeers() []string {
	ports := map[int]bool{}
	for _, p := range SSHPorts() {
		ports[p] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fs := strings.Fields(line)
			if len(fs) < 4 || fs[3] != "01" { // 01 = ESTABLISHED
				continue
			}
			_, lport, err1 := parseProcAddr(fs[1])
			raddr, _, err2 := parseProcAddr(fs[2])
			if err1 != nil || err2 != nil || !ports[lport] {
				continue
			}
			ip := raddr.Unmap().String()
			if !seen[ip] && !raddr.IsLoopback() {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	return out
}

// parseProcAddr decodes "0100007F:0016" (little-endian 32-bit words).
func parseProcAddr(s string) (netip.Addr, int, error) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("bad addr")
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("bad addr")
	}
	for i := 0; i < len(raw); i += 4 { // each 32-bit word is little-endian
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	a, _ := netip.AddrFromSlice(raw)
	return a, int(p), nil
}
