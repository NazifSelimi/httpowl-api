// Package wire holds the JSON shapes shared by the API and the agent.
// Keep identical to httpowl-agent/internal/wire (separate repository).
package wire

import "time"

// Request is one parsed access-log line.
type Request struct {
	TS         time.Time `json:"ts"`
	IP         string    `json:"ip"`
	Method     string    `json:"method"`
	Host       string    `json:"host,omitempty"`
	Path       string    `json:"path"`
	Query      string    `json:"query,omitempty"`
	Proto      string    `json:"proto,omitempty"`
	Status     int       `json:"status"`
	Bytes      int64     `json:"bytes"`
	DurationMS float64   `json:"duration_ms,omitempty"`
	UA         string    `json:"ua,omitempty"`
	Referer    string    `json:"referer,omitempty"`
}

// IngestBatch is the body of POST /api/ingest.
type IngestBatch struct {
	Requests []Request `json:"requests"`
}

// Heartbeat is the body of POST /api/agent/heartbeat.
type Heartbeat struct {
	Version      string   `json:"version"`
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	Servers      []string `json:"servers"`   // detected web servers
	LogPaths     []string `json:"log_paths"` // files being read
	Firewall     string   `json:"firewall"`  // nftables | iptables | windows | off
	ServerIPs    []string `json:"server_ips"`
	SSHPeers     []string `json:"ssh_peers"` // IPs with an open SSH session right now
	RulesApplied int64    `json:"rules_applied"`
	LastError    string   `json:"last_error,omitempty"`
	// False when recent log lines had no domain, so every visit lands on one site.
	// Fix: `sudo httpowl-agent setup-logs`. Nil until lines were read.
	LogsHaveDomain *bool `json:"logs_have_domain,omitempty"`
}

// Rules is the body of GET /api/agent/rules: the full desired block state.
type Rules struct {
	Version     int64    `json:"version"`
	BlockCIDRs  []string `json:"block_cidrs"`  // IPs as /32 or /128 too
	BotPatterns []string `json:"bot_patterns"` // lower-case UA substrings; agent blocks matching IPs for 24h
	AllowIPs    []string `json:"allow_ips"`    // never blocked (protected IPs)
}
