// Package agent ties together tailing, parsing, shipping to the API,
// heartbeats and (feature 7) firewall rules.
package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/NazifSelimi/httpowl-api/internal/agent/detect"
	"github.com/NazifSelimi/httpowl-api/internal/agent/logparse"
	"github.com/NazifSelimi/httpowl-api/internal/agent/sys"
	"github.com/NazifSelimi/httpowl-api/internal/agent/tail"
	"github.com/NazifSelimi/httpowl-api/internal/wire"
)

// Config is /etc/httpowl/agent.json.
type Config struct {
	Server   string   `json:"server"`   // https://httpowl.net
	Token    string   `json:"token"`    // owl_...
	Logs     []string `json:"logs"`     // paths/globs; empty or ["auto"] = detect
	Firewall string   `json:"firewall"` // auto | off
	StateDir string   `json:"state_dir"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

const maxBuffered = 50000

type Agent struct {
	Cfg     Config
	Version string

	client   *http.Client
	servers  []detect.Server
	patterns []string

	mu        sync.Mutex
	lastError string
	fw        firewall
	botWatch  *botWatcher
	rs        ruleState
}

func New(cfg Config, version string) (*Agent, error) {
	cfg.Server = strings.TrimRight(cfg.Server, "/")
	if !strings.HasPrefix(cfg.Token, "owl_") {
		return nil, fmt.Errorf("token missing or wrong (it starts with owl_)")
	}
	if !strings.HasPrefix(cfg.Server, "https://") && !strings.HasPrefix(cfg.Server, "http://127.0.0.1") && !strings.HasPrefix(cfg.Server, "http://localhost") {
		return nil, fmt.Errorf("server must be https://")
	}
	a := &Agent{Cfg: cfg, Version: version, client: &http.Client{Timeout: 20 * time.Second}}
	a.servers = detect.Detect()
	if len(cfg.Logs) == 0 || (len(cfg.Logs) == 1 && cfg.Logs[0] == "auto") {
		a.patterns = detect.Patterns(a.servers)
	} else {
		a.patterns = cfg.Logs
	}
	a.fw = newFirewall(cfg.Firewall)
	a.botWatch = newBotWatcher()
	return a, nil
}

// LogFiles lists files currently matched.
func (a *Agent) LogFiles() []string { return tail.Files(a.patterns) }

// Servers lists detected web servers.
func (a *Agent) Servers() []string { return detect.Names(a.servers) }

func (a *Agent) Run(ctx context.Context) error {
	if len(a.patterns) == 0 {
		return fmt.Errorf("no web server logs found; set \"logs\" in the config")
	}
	slog.Info("httpowl agent starting", "version", a.Version, "servers", a.Servers(), "files", a.LogFiles(), "firewall", a.fw.Name())
	lines := make(chan tail.Line, 5000)
	t := &tail.Tailer{Patterns: a.patterns, Out: lines}
	if a.Cfg.StateDir != "" {
		_ = os.MkdirAll(a.Cfg.StateDir, 0o700)
		t.StatePath = filepath.Join(a.Cfg.StateDir, "offsets.json")
	}
	go t.Run(ctx)
	go a.loop(ctx, time.Minute, a.heartbeat)
	go a.loop(ctx, 30*time.Second, a.syncRules)
	go a.loop(ctx, 5*time.Second, a.botLoop)
	go a.loop(ctx, 10*time.Second, func(context.Context) error { t.Save(); return nil })
	a.ship(ctx, lines)
	return nil
}

func (a *Agent) loop(ctx context.Context, d time.Duration, fn func(context.Context) error) {
	for {
		if err := fn(ctx); err != nil {
			a.setErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
	}
}

func (a *Agent) setErr(err error) {
	slog.Warn("agent", "err", err)
	a.mu.Lock()
	a.lastError = err.Error()
	a.mu.Unlock()
}

// ship parses lines and sends batches of up to 1000 every 2 seconds.
func (a *Agent) ship(ctx context.Context, lines <-chan tail.Line) {
	parsers := map[string]*logparse.Parser{}
	var buf []wire.Request
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	backoff := time.Time{}
	flush := func() {
		if len(buf) == 0 || time.Now().Before(backoff) {
			return
		}
		for len(buf) > 0 {
			n := min(len(buf), 1000)
			if err := a.post(ctx, "/api/ingest", wire.IngestBatch{Requests: buf[:n]}, nil); err != nil {
				a.setErr(fmt.Errorf("send: %w", err))
				backoff = time.Now().Add(15 * time.Second)
				return
			}
			buf = buf[n:]
		}
		buf = nil
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case l := <-lines:
			p := parsers[l.File]
			if p == nil {
				p = &logparse.Parser{}
				parsers[l.File] = p
			}
			r, err := p.Parse(l.Text)
			if err != nil {
				continue
			}
			a.botWatch.see(r)
			buf = append(buf, r)
			if len(buf) > maxBuffered { // server unreachable for long: drop oldest
				buf = buf[len(buf)-maxBuffered:]
			}
			if len(buf) >= 1000 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (a *Agent) heartbeat(ctx context.Context) error {
	host, _ := os.Hostname()
	a.mu.Lock()
	lastErr := a.lastError
	a.mu.Unlock()
	hb := wire.Heartbeat{
		Version: a.Version, Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Servers: a.Servers(), LogPaths: a.LogFiles(), Firewall: a.fw.Name(),
		ServerIPs: sys.ServerIPs(), SSHPeers: sys.SSHPeers(), RulesApplied: a.appliedCount(), LastError: lastErr,
	}
	return a.post(ctx, "/api/agent/heartbeat", hb, nil)
}

func (a *Agent) post(ctx context.Context, path string, body any, out any) error {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if err := json.NewEncoder(zw).Encode(body); err != nil {
		return err
	}
	zw.Close()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, a.Cfg.Server+path, &gz)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	return a.do(req, out)
}

func (a *Agent) get(ctx context.Context, path string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.Cfg.Server+path, nil)
	return a.do(req, out)
}

func (a *Agent) do(req *http.Request, out any) error {
	return a.doRaw(req, func(resp *http.Response) error {
		if out != nil {
			return decodeJSON(resp, out)
		}
		return nil
	})
}

// doRaw sends an authenticated request; 2xx and 304 go to fn.
func (a *Agent) doRaw(req *http.Request, fn func(*http.Response) error) error {
	req.Header.Set("Authorization", "Bearer "+a.Cfg.Token)
	req.Header.Set("User-Agent", "httpowl-agent/"+a.Version)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotModified {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("%s %s: %d %s", req.Method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return fn(resp)
}

func decodeJSON(resp *http.Response, out any) error {
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

func (a *Agent) appliedCount() int64 {
	a.rs.mu.Lock()
	defer a.rs.mu.Unlock()
	return a.rs.applied
}
