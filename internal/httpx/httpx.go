// Package httpx has small HTTP helpers shared by all handlers.
package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// JSON writes v as JSON with the given status.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error writes {"error": msg}.
func Error(w http.ResponseWriter, status int, msg string) {
	JSON(w, status, map[string]string{"error": msg})
}

// Internal logs err and writes a generic 500.
func Internal(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("internal error", "path", r.URL.Path, "err", err)
	Error(w, http.StatusInternalServerError, "something went wrong")
}

// Decode reads a JSON body (max 1 MB) into v.
func Decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		Error(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// ClientIP returns the visitor IP. X-Real-IP is trusted only when the
// direct peer is loopback (i.e. our own nginx in front).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if a, err := netip.ParseAddr(host); err == nil && a.IsLoopback() {
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			if _, err := netip.ParseAddr(xr); err == nil {
				return xr
			}
		}
	}
	return host
}

// IDParam parses a chi URL param as a positive int64.
func IDParam(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("bad id")
	}
	return id, nil
}

// SameOrigin blocks cross-site state-changing requests: mutations must be
// JSON (forces a CORS preflight) and any Origin header must match publicURL.
func SameOrigin(publicURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
			default:
				if o := r.Header.Get("Origin"); o != "" && o != publicURL {
					Error(w, http.StatusForbidden, "cross-site request blocked")
					return
				}
				if r.ContentLength > 0 && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
					Error(w, http.StatusUnsupportedMediaType, "use application/json")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Limiter is a tiny fixed-window limiter keyed by string (e.g. IP).
type Limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*window
}

type window struct {
	start time.Time
	n     int
}

func NewLimiter(max int, w time.Duration) *Limiter {
	return &Limiter{max: max, window: w, hits: map[string]*window{}}
}

// Allow reports whether key may do one more action now.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.hits) > 100000 { // crude memory cap
		l.hits = map[string]*window{}
	}
	h := l.hits[key]
	if h == nil || now.Sub(h.start) > l.window {
		l.hits[key] = &window{start: now, n: 1}
		return true
	}
	h.n++
	return h.n <= l.max
}
