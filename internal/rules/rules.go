package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NazifSelimi/httpowl-api/internal/audit"
	"github.com/NazifSelimi/httpowl-api/internal/auth"
	"github.com/NazifSelimi/httpowl-api/internal/geo"
	"github.com/NazifSelimi/httpowl-api/internal/httpx"
	"github.com/NazifSelimi/httpowl-api/internal/sites"
	"github.com/NazifSelimi/httpowl-api/internal/store"
	"github.com/NazifSelimi/httpowl-api/internal/wire"
)

const maxActive = 500

type Handler struct {
	Q   *store.Queries
	Geo *geo.DB
}

// SiteRoutes mounts under /sites/{siteID}.
func (h *Handler) SiteRoutes(r chi.Router) {
	r.With(sites.Load(h.Q, sites.RoleViewer)).Get("/rules", h.list)
	r.With(sites.Load(h.Q, sites.RoleAdmin)).Post("/rules", h.create)
	r.With(sites.Load(h.Q, sites.RoleAdmin)).Post("/rules/check", h.check)
	r.With(sites.Load(h.Q, sites.RoleAdmin)).Delete("/rules/{ruleID}", h.remove)
	r.With(sites.Load(h.Q, sites.RoleAdmin)).Post("/rules/{ruleID}/restore", h.restore)
}

// AgentRoutes mounts the agent's rule pull (inside the agent-auth group).
func (h *Handler) AgentRoutes(r chi.Router) {
	r.With(sites.RequireAgent(h.Q)).Get("/agent/rules", h.agentRules)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	rows, err := h.Q.ListRules(r.Context(), s.ID)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if rows == nil {
		rows = []store.ListRulesRow{}
	}
	httpx.JSON(w, http.StatusOK, rows)
}

type ruleInput struct {
	Kind         string `json:"kind"`
	Value        string `json:"value"`
	Note         string `json:"note"`
	ExpiresHours int    `json:"expires_hours"` // 0 = never
}

// protected gathers every address that must stay reachable for this site.
func (h *Handler) protected(r *http.Request, site sites.Site) Protected {
	p := Protected{}
	if a, err := netip.ParseAddr(httpx.ClientIP(r)); err == nil {
		p.RequesterIP = a.Unmap()
	}
	for _, s := range site.ProtectedIps {
		if a, err := netip.ParseAddr(s); err == nil {
			p.IPs = append(p.IPs, a)
		}
	}
	if ips, err := h.Q.MemberSessionIPs(r.Context(), site.ID); err == nil {
		for _, s := range ips {
			if a, err := netip.ParseAddr(s); err == nil {
				p.IPs = append(p.IPs, a.Unmap())
			}
		}
	}
	if h.Geo != nil && h.Geo.Ready() {
		p.CountryOf = h.Geo.Country
	}
	return p
}

func (h *Handler) validate(r *http.Request, site sites.Site, kind, value string) (string, error) {
	v, err := Normalize(kind, value)
	if err != nil {
		return "", err
	}
	if kind == KindCountry && h.Geo != nil && len(h.Geo.CountryCIDRs(v)) == 0 {
		return "", errors.New("unknown country code " + v)
	}
	return v, Check(kind, v, h.protected(r, site))
}

// check is a dry run: "would this rule be allowed?" (for the UI's confirm dialog).
func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	var in ruleInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := h.validate(r, s, in.Kind, in.Value)
	if err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "value": v, "explain": Explain(in.Kind, v) + ScopeNote(s)})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	u, _ := auth.FromContext(r.Context())
	var in ruleInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := h.validate(r, s, in.Kind, in.Value)
	if err != nil {
		httpx.Error(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if n, err := h.Q.CountActiveRules(r.Context(), s.ID); err != nil || n >= maxActive {
		httpx.Error(w, http.StatusUnprocessableEntity, "too many active rules (max 500); remove some first")
		return
	}
	if in.ExpiresHours < 0 || in.ExpiresHours > 24*365 {
		httpx.Error(w, http.StatusBadRequest, "expires_hours must be 0..8760")
		return
	}
	var exp *time.Time
	if in.ExpiresHours > 0 {
		t := time.Now().Add(time.Duration(in.ExpiresHours) * time.Hour)
		exp = &t
	}
	note := strings.TrimSpace(in.Note)
	if len(note) > 200 {
		note = note[:200]
	}
	rule, err := h.Q.CreateRule(r.Context(), store.CreateRuleParams{SiteID: s.ID, Kind: in.Kind, Value: v, Note: note, CreatedBy: &u.ID, ExpiresAt: exp})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		httpx.Error(w, http.StatusConflict, "this is already blocked")
		return
	}
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	audit.Log(r.Context(), h.Q, &s.ID, &u.ID, "rule.create", map[string]any{"rule_id": rule.ID, "kind": rule.Kind, "value": rule.Value, "note": note}, httpx.ClientIP(r))
	httpx.JSON(w, http.StatusCreated, map[string]any{"rule": rule, "explain": Explain(rule.Kind, rule.Value) + ScopeNote(s), "undo": fmt.Sprintf("DELETE /api/sites/%d/rules/%d", s.ID, rule.ID)})
}

func (h *Handler) remove(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	u, _ := auth.FromContext(r.Context())
	id, err := httpx.IDParam(r, "ruleID")
	if err != nil {
		httpx.Error(w, http.StatusNotFound, "rule not found")
		return
	}
	n, err := h.Q.RemoveRule(r.Context(), store.RemoveRuleParams{ID: id, SiteID: s.ID, RemovedBy: &u.ID})
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if n == 0 {
		httpx.Error(w, http.StatusNotFound, "rule not found or already removed")
		return
	}
	audit.Log(r.Context(), h.Q, &s.ID, &u.ID, "rule.remove", map[string]any{"rule_id": id}, httpx.ClientIP(r))
	httpx.JSON(w, http.StatusOK, map[string]any{"removed": id, "undo": fmt.Sprintf("POST /api/sites/%d/rules/%d/restore", s.ID, id)})
}

// restore re-creates a removed rule (undo of "unblock"), with fresh safety checks.
func (h *Handler) restore(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	u, _ := auth.FromContext(r.Context())
	id, err := httpx.IDParam(r, "ruleID")
	if err != nil {
		httpx.Error(w, http.StatusNotFound, "rule not found")
		return
	}
	old, err := h.Q.GetRule(r.Context(), store.GetRuleParams{ID: id, SiteID: s.ID})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && old.RemovedAt == nil) {
		httpx.Error(w, http.StatusNotFound, "no removed rule with this id")
		return
	}
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if _, err := h.validate(r, s, old.Kind, old.Value); err != nil {
		httpx.Error(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	rule, err := h.Q.CreateRule(r.Context(), store.CreateRuleParams{SiteID: s.ID, Kind: old.Kind, Value: old.Value, Note: old.Note, CreatedBy: &u.ID})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		httpx.Error(w, http.StatusConflict, "this is already blocked")
		return
	}
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	audit.Log(r.Context(), h.Q, &s.ID, &u.ID, "rule.restore", map[string]any{"rule_id": rule.ID, "restored_from": id, "kind": rule.Kind, "value": rule.Value}, httpx.ClientIP(r))
	httpx.JSON(w, http.StatusCreated, map[string]any{"rule": rule})
}

// agentRules returns the full desired state. ETag lets the agent skip unchanged lists.
// Rules of the agent's own site block the whole server (firewall); rules of the
// sites it serves block only that website (enforced by the web server).
func (h *Handler) agentRules(w http.ResponseWriter, r *http.Request) {
	site := sites.AgentFromContext(r)
	active, err := h.Q.ActiveRulesForAgent(r.Context(), site.ID)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	served, err := h.Q.ServedSites(r.Context(), &site.ID)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	out := wire.Rules{BlockCIDRs: []string{}, BotPatterns: []string{}, AllowIPs: []string{}}
	bySite := map[int64]*wire.SiteRules{}
	for _, s := range served {
		sr := wire.SiteRules{Domains: HostNames(s.Domain), BlockCIDRs: []string{}, BotPatterns: []string{}}
		out.Sites = append(out.Sites, sr)
	}
	for i, s := range served {
		bySite[s.ID] = &out.Sites[i]
	}
	for _, rl := range active {
		cidrs, bots := &out.BlockCIDRs, &out.BotPatterns
		if sr, ok := bySite[rl.SiteID]; ok {
			cidrs, bots = &sr.BlockCIDRs, &sr.BotPatterns
		} else if rl.SiteID != site.ID {
			continue // served_by changed between the two queries
		}
		switch rl.Kind {
		case KindIP, KindCIDR:
			*cidrs = append(*cidrs, rl.Value)
		case KindCountry:
			if h.Geo != nil {
				*cidrs = append(*cidrs, h.Geo.CountryCIDRs(rl.Value)...)
			}
		case KindBot:
			*bots = append(*bots, rl.Value)
		}
	}
	out.AllowIPs = append(out.AllowIPs, site.ProtectedIPs...)
	if ips, err := h.Q.MemberSessionIPsForAgent(r.Context(), site.ID); err == nil {
		out.AllowIPs = append(out.AllowIPs, ips...)
	}
	b, _ := json.Marshal(out)
	sum := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// HostNames are the exact host names a site's blocks cover: the domain and its www twin.
func HostNames(domain string) []string {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	d = strings.TrimPrefix(d, "www.")
	return []string{d, "www." + d}
}

// ScopeNote says which websites a block on this site reaches.
func ScopeNote(s sites.Site) string {
	if s.ServedBy != nil {
		return " Only " + s.Domain + " is affected; your other websites on the same server stay open."
	}
	return " This blocks them on the whole server, so every website on it."
}

// Explain says in plain words what a rule does.
func Explain(kind, value string) string {
	switch kind {
	case KindIP:
		return "Visitors from " + value + " can't open your website (ports 80/443). SSH and everything else stay open. Undo any time."
	case KindCIDR:
		return "Every address in " + value + " can't open your website (ports 80/443). Undo any time."
	case KindCountry:
		return "Visitors from country " + value + " can't open your website. You, your team and your SSH sessions are always let through. Undo any time."
	case KindBot:
		return "Any address that visits as \"" + value + "\" is blocked from your website for 24 hours. Undo any time."
	}
	return ""
}
