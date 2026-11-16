// Package ws streams newly ingested requests to dashboards over WebSocket.
package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/NazifSelimi/httpowl-api/internal/sites"
)

// Event is one request as sent to live viewers.
type Event struct {
	TS       time.Time `json:"ts"`
	IP       string    `json:"ip"`
	Country  string    `json:"country"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Status   int       `json:"status"`
	Duration float32   `json:"duration_ms"`
	UA       string    `json:"ua"`
	Tag      string    `json:"tag"`
	Reason   string    `json:"reason,omitempty"`
}

type client struct {
	send chan []byte
}

type Hub struct {
	mu      sync.RWMutex
	subs    map[int64]map[*client]struct{}
	origins []string
}

// New creates a hub; publicURL's host is the only allowed browser origin.
func New(publicURL string) *Hub {
	h := &Hub{subs: map[int64]map[*client]struct{}{}}
	if u, err := url.Parse(publicURL); err == nil {
		h.origins = []string{u.Host}
	}
	return h
}

// Publish sends events to everyone watching siteID. Slow viewers miss messages instead of blocking ingest.
func (h *Hub) Publish(siteID int64, evs []Event) {
	h.mu.RLock()
	subs := h.subs[siteID]
	if len(subs) == 0 {
		h.mu.RUnlock()
		return
	}
	for len(evs) > 0 {
		n := min(len(evs), 200)
		msg, _ := json.Marshal(map[string]any{"type": "requests", "data": evs[:n]})
		for c := range subs {
			select {
			case c.send <- msg:
			default:
			}
		}
		evs = evs[n:]
	}
	h.mu.RUnlock()
}

// Watchers returns how many viewers a site has.
func (h *Hub) Watchers(siteID int64) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs[siteID])
}

// Serve handles GET /api/sites/{siteID}/live (after sites.Load).
func (h *Hub) Serve(w http.ResponseWriter, r *http.Request) {
	site := sites.FromContext(r.Context())
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: h.origins})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	c := &client{send: make(chan []byte, 64)}
	h.mu.Lock()
	if h.subs[site.ID] == nil {
		h.subs[site.ID] = map[*client]struct{}{}
	}
	h.subs[site.ID][c] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.subs[site.ID], c)
		if len(h.subs[site.ID]) == 0 {
			delete(h.subs, site.ID)
		}
		h.mu.Unlock()
	}()

	ctx := conn.CloseRead(r.Context()) // we never read; this handles pings/close
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	_ = write(ctx, conn, []byte(`{"type":"hello"}`))
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-c.send:
			if err := write(ctx, conn, msg); err != nil {
				return
			}
		case <-ping.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pctx)
			cancel()
			if err != nil {
				slog.Debug("ws ping failed", "err", err)
				return
			}
		}
	}
}

func write(ctx context.Context, c *websocket.Conn, msg []byte) error {
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.Write(wctx, websocket.MessageText, msg)
}
