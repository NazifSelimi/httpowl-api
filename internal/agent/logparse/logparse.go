// Package logparse turns access-log lines from nginx, Apache, LiteSpeed,
// Traefik (CLF + JSON), Caddy (JSON) and IIS (W3C) into wire.Requests.
package logparse

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/NazifSelimi/httpowl-api/internal/wire"
)

var ErrSkip = errors.New("not a request line")

// Parser keeps per-file state (IIS #Fields header). Use one per file.
type Parser struct {
	iisFields []string
}

// Parse auto-detects the line format.
func (p *Parser) Parse(line string) (wire.Request, error) {
	line = strings.TrimRight(line, "\r\n")
	switch {
	case line == "":
		return wire.Request{}, ErrSkip
	case line[0] == '#':
		if f, ok := strings.CutPrefix(line, "#Fields:"); ok {
			p.iisFields = strings.Fields(f)
		}
		return wire.Request{}, ErrSkip
	case line[0] == '{':
		return parseJSON(line)
	case p.iisFields != nil:
		return p.parseIIS(line)
	}
	return parseCLF(line)
}

// combined / common log format, optionally with an Apache vhost prefix and trailing extras.
var clfRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?(.*)$`)
var trailingMS = regexp.MustCompile(`(\d+)ms\s*$`)
var trailingSec = regexp.MustCompile(`(?:rt=|request_time=|\s)(\d+\.\d{3})\b`)

func parseCLF(line string) (wire.Request, error) {
	var host string
	// Apache vhost_combined: "example.com:443 1.2.3.4 - - [...]"
	if sp := strings.IndexByte(line, ' '); sp > 0 {
		first := line[:sp]
		if i := strings.LastIndexByte(first, ':'); i > 0 && isDigits(first[i+1:]) {
			rest := line[sp+1:]
			if sp2 := strings.IndexByte(rest, ' '); sp2 > 0 && validIP(rest[:sp2]) && !validIP(first) {
				host, line = first[:i], rest
			}
		}
	}
	m := clfRe.FindStringSubmatch(line)
	if m == nil {
		return wire.Request{}, ErrSkip
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		return wire.Request{}, ErrSkip
	}
	r := wire.Request{TS: ts, IP: m[1], Host: host, UA: unescape(m[7]), Referer: dash(unescape(m[6]))}
	parts := strings.Fields(m[3])
	if len(parts) >= 2 {
		r.Method, r.Path = parts[0], parts[1]
		if len(parts) >= 3 {
			r.Proto = parts[2]
		}
	} else {
		r.Method, r.Path = "-", m[3] // garbage request line (scanners)
	}
	r.Status, _ = strconv.Atoi(m[4])
	r.Bytes, _ = strconv.ParseInt(m[5], 10, 64)
	if rest := m[8]; rest != "" {
		if mm := trailingMS.FindStringSubmatch(rest); mm != nil { // Traefik CLF
			v, _ := strconv.ParseFloat(mm[1], 64)
			r.DurationMS = v
		} else if mm := trailingSec.FindStringSubmatch(rest); mm != nil { // nginx $request_time
			v, _ := strconv.ParseFloat(mm[1], 64)
			r.DurationMS = v * 1000
		}
	}
	return finish(r)
}

func parseJSON(line string) (wire.Request, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return wire.Request{}, ErrSkip
	}
	if req, ok := m["request"].(map[string]any); ok { // Caddy
		r := wire.Request{
			IP:     str(req["client_ip"]),
			Method: str(req["method"]),
			Host:   str(req["host"]),
			Path:   str(req["uri"]),
			Proto:  str(req["proto"]),
			Status: int(num(m["status"])),
			Bytes:  int64(num(m["size"])),
		}
		if r.IP == "" {
			r.IP = str(req["remote_ip"])
		}
		if ts := num(m["ts"]); ts > 0 {
			r.TS = time.Unix(0, int64(ts*1e9))
		}
		r.DurationMS = num(m["duration"]) * 1000
		if h, ok := req["headers"].(map[string]any); ok {
			r.UA = first(h["User-Agent"])
			r.Referer = first(h["Referer"])
		}
		return finish(r)
	}
	if _, ok := m["ClientHost"]; ok { // Traefik JSON
		r := wire.Request{
			IP:         str(m["ClientHost"]),
			Method:     str(m["RequestMethod"]),
			Host:       str(m["RequestHost"]),
			Path:       str(m["RequestPath"]),
			Proto:      str(m["RequestProtocol"]),
			Status:     int(num(m["DownstreamStatus"])),
			Bytes:      int64(num(m["DownstreamContentSize"])),
			DurationMS: num(m["Duration"]) / 1e6,
			UA:         str(m["request_User-Agent"]),
			Referer:    str(m["request_Referer"]),
		}
		r.TS, _ = time.Parse(time.RFC3339Nano, str(m["StartUTC"]))
		return finish(r)
	}
	return wire.Request{}, ErrSkip
}

func (p *Parser) parseIIS(line string) (wire.Request, error) {
	vals := strings.Fields(line)
	if len(vals) != len(p.iisFields) {
		return wire.Request{}, ErrSkip
	}
	var r wire.Request
	var date, clock string
	for i, f := range p.iisFields {
		v := vals[i]
		if v == "-" {
			continue
		}
		switch f {
		case "date":
			date = v
		case "time":
			clock = v
		case "c-ip":
			r.IP = v
		case "cs-method":
			r.Method = v
		case "cs-uri-stem":
			r.Path = v
		case "cs-uri-query":
			r.Query = v
		case "cs-host":
			r.Host = v
		case "cs-version":
			r.Proto = v
		case "sc-status":
			r.Status, _ = strconv.Atoi(v)
		case "sc-bytes":
			r.Bytes, _ = strconv.ParseInt(v, 10, 64)
		case "time-taken":
			r.DurationMS, _ = strconv.ParseFloat(v, 64)
		case "cs(User-Agent)":
			r.UA = strings.ReplaceAll(v, "+", " ")
		case "cs(Referer)":
			r.Referer = v
		}
	}
	r.TS, _ = time.Parse("2006-01-02 15:04:05", date+" "+clock) // IIS logs are UTC
	return finish(r)
}

func finish(r wire.Request) (wire.Request, error) {
	if r.TS.IsZero() || r.Status < 100 || r.Status > 999 {
		return wire.Request{}, ErrSkip
	}
	if a, err := netip.ParseAddr(r.IP); err == nil {
		r.IP = a.Unmap().String()
	} else if ap, err := netip.ParseAddrPort(r.IP); err == nil {
		r.IP = ap.Addr().Unmap().String()
	} else {
		return wire.Request{}, ErrSkip
	}
	if r.Query == "" {
		if i := strings.IndexByte(r.Path, '?'); i >= 0 {
			r.Path, r.Query = r.Path[:i], r.Path[i+1:]
		}
	}
	r.Path = clip(r.Path, 1000)
	r.Query = clip(r.Query, 500)
	r.UA = clip(r.UA, 500)
	r.Referer = clip(r.Referer, 500)
	r.Method = clip(r.Method, 16)
	r.Host = clip(r.Host, 253)
	r.Proto = clip(r.Proto, 16)
	r.TS = r.TS.UTC()
	return r, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
func unescape(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(s)
}
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func validIP(s string) bool { _, err := netip.ParseAddr(s); return err == nil }
func str(v any) string      { s, _ := v.(string); return s }
func num(v any) float64     { f, _ := v.(float64); return f }
func first(v any) string {
	if a, ok := v.([]any); ok && len(a) > 0 {
		return str(a[0])
	}
	return ""
}
