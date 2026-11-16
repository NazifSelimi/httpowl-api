// Package detect finds which web servers run here and where their access logs are.
package detect

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/NazifSelimi/httpowl-api/internal/agent/tail"
)

type Server struct {
	Name     string   `json:"name"`
	Patterns []string `json:"patterns"`
}

// Known log locations per server.
var known = []Server{
	{"nginx", []string{"/var/log/nginx/*access*.log", "/usr/local/nginx/logs/access.log"}},
	{"apache", []string{"/var/log/apache2/*access*.log", "/var/log/httpd/*access_log", "/var/log/httpd/*access*.log", "/usr/local/apache2/logs/access_log"}},
	{"litespeed", []string{"/usr/local/lsws/logs/access.log", "/usr/local/lsws/logs/*access*.log"}},
	{"caddy", []string{"/var/log/caddy/*.log"}},
	{"traefik", []string{"/var/log/traefik/access.log", "/var/log/traefik/*access*.log"}},
	{"iis", []string{`C:\inetpub\logs\LogFiles\W3SVC*\u_ex*.log`}},
}

// processNames maps running process names to servers (Linux /proc).
var processNames = map[string]string{
	"nginx": "nginx", "apache2": "apache", "httpd": "apache", "litespeed": "litespeed",
	"lshttpd": "litespeed", "openlitespeed": "litespeed", "caddy": "caddy", "traefik": "traefik",
}

// Detect returns servers that are running or have log files.
func Detect() []Server {
	running := runningServers()
	var out []Server
	for _, s := range known {
		if s.Name == "iis" && runtime.GOOS != "windows" {
			continue
		}
		if len(tail.Files(s.Patterns)) > 0 || running[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

// Patterns flattens the patterns of the given servers.
func Patterns(ss []Server) []string {
	var p []string
	for _, s := range ss {
		p = append(p, s.Patterns...)
	}
	return p
}

// Names lists server names.
func Names(ss []Server) []string {
	var n []string
	for _, s := range ss {
		n = append(n, s.Name)
	}
	return n
}

func runningServers() map[string]bool {
	found := map[string]bool{}
	dirs, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, d := range dirs {
		b, err := os.ReadFile(d)
		if err != nil {
			continue
		}
		if s, ok := processNames[strings.TrimSpace(string(b))]; ok {
			found[s] = true
		}
	}
	return found
}
