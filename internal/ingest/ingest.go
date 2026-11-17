// Package ingest receives request batches and heartbeats from agents.
package ingest

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/NazifSelimi/httpowl-api/internal/httpx"
	"github.com/NazifSelimi/httpowl-api/internal/sites"
	"github.com/NazifSelimi/httpowl-api/internal/store"
	"github.com/NazifSelimi/httpowl-api/internal/wire"
)

const maxBatch = 5000

// Row is a request ready to be stored (after enrichment).
type Row = store.InsertRequestsParams

type Handler struct {
	Q *store.Queries
	// Enrich fills country/tag/reason (geo + analyse). Optional.
	Enrich func(rows []Row)
	// Publish pushes stored rows to live viewers. Optional.
	Publish func(siteID int64, rows []Row)

	limit *httpx.Limiter
}

func (h *Handler) Routes(r chi.Router) {
	h.limit = httpx.NewLimiter(120, time.Minute) // batches per site per minute
	r.Group(func(r chi.Router) {
		r.Use(sites.RequireAgent(h.Q))
		r.Post("/ingest", h.ingest)
		r.Post("/agent/heartbeat", h.heartbeat)
	})
}

// body returns the (possibly gzip) body limited to 32 MB decompressed.
func body(r *http.Request) (io.Reader, error) {
	var rd io.Reader = http.MaxBytesReader(nil, r.Body, 8<<20)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(rd)
		if err != nil {
			return nil, err
		}
		rd = zr
	}
	return io.LimitReader(rd, 32<<20), nil
}

func (h *Handler) ingest(w http.ResponseWriter, r *http.Request) {
	site := sites.AgentFromContext(r)
	if !h.limit.Allow(strconv.FormatInt(site.ID, 10)) {
		httpx.Error(w, http.StatusTooManyRequests, "slow down")
		return
	}
	rd, err := body(r)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad gzip body")
		return
	}
	var b wire.IngestBatch
	if err := json.NewDecoder(rd).Decode(&b); err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad JSON body")
		return
	}
	if len(b.Requests) > maxBatch {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "max 5000 requests per batch")
		return
	}
	router, err := h.router(r, site.ID)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	rows := make([]Row, 0, len(b.Requests))
	skipped := 0
	for _, q := range b.Requests {
		ip, err := netip.ParseAddr(q.IP)
		if err != nil || !InWindow(q.TS) || q.Status < 100 || q.Status > 999 || strings.HasPrefix(q.UA, "httpowl-agent/") {
			skipped++
			continue
		}
		rows = append(rows, Row{
			SiteID: router.SiteFor(q.Host), Ts: q.TS.UTC(), Ip: ip.Unmap(), Method: clip(q.Method, 16), Host: clip(q.Host, 253),
			Path: clip(q.Path, 1000), Query: clip(q.Query, 500), Proto: clip(q.Proto, 16), Status: int16(q.Status),
			Bytes: max(q.Bytes, 0), DurationMs: float32(max(q.DurationMS, 0)), Ua: clip(q.UA, 500), Referer: clip(q.Referer, 500),
			Tag: "human",
		})
	}
	if len(rows) > 0 {
		if h.Enrich != nil {
			h.Enrich(rows)
		}
		if _, err := h.Q.InsertRequests(r.Context(), rows); err != nil {
			httpx.Internal(w, r, err)
			return
		}
		bySite := map[int64][]Row{}
		for _, row := range rows {
			bySite[row.SiteID] = append(bySite[row.SiteID], row)
		}
		served := make([]int64, 0, len(bySite))
		for id, siteRows := range bySite {
			served = append(served, id)
			if h.Publish != nil {
				h.Publish(id, siteRows)
			}
		}
		if len(served) > 1 || served[0] != site.ID {
			if err := h.Q.MarkServedBy(r.Context(), store.MarkServedByParams{AgentSiteID: &site.ID, SiteIds: served}); err != nil {
				slog.Error("mark served_by", "site", site.ID, "err", err)
			}
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]int{"stored": len(rows), "skipped": skipped})
}

// router builds the domain → site map for this agent's owner(s).
func (h *Handler) router(r *http.Request, agentSiteID int64) (*Router, error) {
	rows, err := h.Q.RouteCandidates(r.Context(), agentSiteID)
	if err != nil {
		return nil, err
	}
	candidates := make([]Candidate, len(rows))
	for i, c := range rows {
		candidates[i] = Candidate{ID: c.ID, Domain: c.Domain}
	}
	return NewRouter(agentSiteID, candidates), nil
}

func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request) {
	site := sites.AgentFromContext(r)
	rd, err := body(r)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad gzip body")
		return
	}
	var hb wire.Heartbeat
	if err := json.NewDecoder(io.LimitReader(rd, 1<<20)).Decode(&hb); err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad JSON body")
		return
	}
	// Server IPs + live SSH peers must never be blocked.
	protected := []string{} // never nil: the column is NOT NULL
	seen := map[string]bool{}
	for _, s := range append(append([]string{}, hb.ServerIPs...), hb.SSHPeers...) {
		if a, err := netip.ParseAddr(s); err == nil && !seen[a.String()] && len(protected) < 200 {
			seen[a.String()] = true
			protected = append(protected, a.String())
		}
	}
	cleanHeartbeat(&hb)
	info, _ := json.Marshal(hb)
	if err := h.Q.AgentHeartbeat(r.Context(), store.AgentHeartbeatParams{ID: site.ID, AgentInfo: info, ProtectedIps: protected}); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if err := h.Q.AgentHeartbeatServed(r.Context(), store.AgentHeartbeatServedParams{ServedBy: &site.ID, AgentInfo: info, ProtectedIps: protected}); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	slog.Debug("heartbeat", "site", site.ID, "host", hb.Hostname)
	w.WriteHeader(http.StatusNoContent)
}

// cleanHeartbeat caps the free-text fields the agent sends (shown on the dashboard).
func cleanHeartbeat(hb *wire.Heartbeat) {
	hb.LastError = clip(hb.LastError, 500)
	hb.SiteBlocksError = clip(hb.SiteBlocksError, 500)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
