package agent

import (
	"context"
	"sync"

	"github.com/NazifSelimi/httpowl-api/internal/wire"
)

// firewall applies the full desired block list (implemented per OS in feature 7).
type firewall interface {
	Name() string
	Apply(cidrs []string, allow []string) error
	Applied() int64
}

type noFirewall struct{}

func (noFirewall) Name() string                   { return "off" }
func (noFirewall) Apply([]string, []string) error { return nil }
func (noFirewall) Applied() int64                 { return 0 }

func newFirewall(mode string) firewall { return noFirewall{} }

func (a *Agent) syncRules(ctx context.Context) error { return nil }

type botWatcher struct{ mu sync.Mutex }

func newBotWatcher() *botWatcher       { return &botWatcher{} }
func (b *botWatcher) see(wire.Request) {}
