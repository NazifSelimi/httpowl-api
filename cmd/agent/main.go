// Command httpowl-agent reads web server access logs and sends them to HTTPowl.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/NazifSelimi/httpowl-api/internal/agent"
)

var version = "dev"

type multi []string

func (m *multi) String() string     { return fmt.Sprint(*m) }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	cfgPath := flag.String("config", defaultConfig(), "config file")
	token := flag.String("token", "", "agent token (overrides config)")
	server := flag.String("server", "", "HTTPowl server URL (overrides config)")
	detectOnly := flag.Bool("detect", false, "show detected web servers and log files, then exit")
	cleanup := flag.Bool("cleanup", false, "remove every firewall block HTTPowl added, then exit")
	showVersion := flag.Bool("version", false, "print version")
	var logs multi
	flag.Var(&logs, "log", "access log path or glob (repeatable; overrides auto-detect)")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil && !os.IsNotExist(err) {
		fail(err)
	}
	if cfg.Server == "" {
		cfg.Server = "https://httpowl.net"
	}
	if *token != "" {
		cfg.Token = *token
	}
	if *server != "" {
		cfg.Server = *server
	}
	if len(logs) > 0 {
		cfg.Logs = logs
	}
	if cfg.Token == "" && (*detectOnly || *cleanup) {
		cfg.Token = "owl_detect"
	}
	a, err := agent.New(cfg, version)
	if err != nil {
		fail(err)
	}
	if *cleanup {
		if err := a.Cleanup(); err != nil {
			fail(err)
		}
		fmt.Println("HTTPowl firewall blocks removed")
		return
	}
	if *detectOnly {
		out, _ := json.MarshalIndent(map[string]any{"servers": a.Servers(), "log_files": a.LogFiles(), "firewall": a.FirewallName()}, "", "  ")
		fmt.Println(string(out))
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "httpowl-agent:", err)
	os.Exit(1)
}

func defaultConfig() string {
	if os.PathSeparator == '\\' {
		return `C:\ProgramData\HTTPowl\agent.json`
	}
	return "/etc/httpowl/agent.json"
}
