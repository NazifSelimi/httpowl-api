package sites

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/NazifSelimi/httpowl-api/internal/audit"
	"github.com/NazifSelimi/httpowl-api/internal/auth"
	"github.com/NazifSelimi/httpowl-api/internal/httpx"
	"github.com/NazifSelimi/httpowl-api/internal/store"
)

type Handler struct {
	Pool      *pgxpool.Pool
	Q         *store.Queries
	PublicURL string
	// Sub mounts more routes under /sites/{siteID} (stats, rules, team...).
	Sub []func(r chi.Router)
}

// Routes mounts /sites... on an authenticated router.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/sites", h.list)
	r.Post("/sites", h.create)
	r.Route("/sites/{siteID}", func(r chi.Router) {
		r.With(Load(h.Q, RoleClient)).Get("/", h.get)
		r.With(Load(h.Q, RoleAdmin)).Patch("/", h.update)
		r.With(Load(h.Q, RoleOwner)).Delete("/", h.delete)
		r.With(Load(h.Q, RoleAdmin)).Post("/agent-token", h.newToken)
		for _, f := range h.Sub {
			f(r)
		}
	})
}

var domainRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

type siteInput struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

func (in *siteInput) clean() string {
	in.Name = strings.TrimSpace(in.Name)
	d := strings.ToLower(strings.TrimSpace(in.Domain))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
	in.Domain = strings.TrimSuffix(strings.SplitN(d, "/", 2)[0], ".")
	if in.Name == "" {
		in.Name = in.Domain
	}
	switch {
	case !domainRe.MatchString(in.Domain) || len(in.Domain) > 253:
		return "enter a domain like example.com"
	case len(in.Name) > 100:
		return "name is too long"
	}
	return ""
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.FromContext(r.Context())
	rows, err := h.Q.ListSitesForUser(r.Context(), u.ID)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if rows == nil {
		rows = []store.ListSitesForUserRow{}
	}
	httpx.JSON(w, http.StatusOK, rows)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.FromContext(r.Context())
	var in siteInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	if msg := in.clean(); msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
		return
	}
	var site store.Site
	err := pgx.BeginFunc(r.Context(), h.Pool, func(tx pgx.Tx) error {
		q := h.Q.WithTx(tx)
		var err error
		if site, err = q.CreateSite(r.Context(), store.CreateSiteParams{Name: in.Name, Domain: in.Domain}); err != nil {
			return err
		}
		return q.AddMember(r.Context(), store.AddMemberParams{SiteID: site.ID, UserID: u.ID, Role: RoleOwner})
	})
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	audit.Log(r.Context(), h.Q, &site.ID, &u.ID, "site.create", map[string]any{"name": site.Name, "domain": site.Domain}, httpx.ClientIP(r))
	httpx.JSON(w, http.StatusCreated, map[string]any{"id": site.ID, "name": site.Name, "domain": site.Domain, "role": RoleOwner})
}

type siteView struct {
	ID              int64           `json:"id"`
	Name            string          `json:"name"`
	Domain          string          `json:"domain"`
	Role            string          `json:"role"`
	CreatedAt       time.Time       `json:"created_at"`
	AgentLastSeenAt *time.Time      `json:"agent_last_seen_at"`
	AgentOnline     bool            `json:"agent_online"`
	AgentInfo       json.RawMessage `json:"agent_info,omitempty"`
	TokenPrefix     string          `json:"token_prefix,omitempty"`
	ProtectedIPs    []string        `json:"protected_ips,omitempty"` // server IPs + live SSH peers: never blockable
	InstallCommand  string          `json:"install_hint,omitempty"`
	// Where this site's blocks apply: "site" = only this domain (another site's
	// agent serves it, blocks run in the web server); "server" = the whole
	// server (firewall), which includes every domain in Serves.
	BlockScope string   `json:"block_scope"`
	Serves     []string `json:"serves,omitempty"`
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	s := FromContext(r.Context())
	v := siteView{ID: s.ID, Name: s.Name, Domain: s.Domain, Role: s.Role, CreatedAt: s.CreatedAt, AgentLastSeenAt: s.AgentLastSeenAt}
	v.AgentOnline = s.AgentLastSeenAt != nil && time.Since(*s.AgentLastSeenAt) < 2*time.Minute
	v.BlockScope = "server"
	if s.ServedBy != nil {
		v.BlockScope = "site"
	} else if served, err := h.Q.ServedSites(r.Context(), &s.ID); err == nil {
		for _, x := range served {
			v.Serves = append(v.Serves, x.Domain)
		}
	}
	if AtLeast(s.Role, RoleAdmin) {
		v.AgentInfo = s.AgentInfo
		v.ProtectedIPs = s.ProtectedIps
		if t, err := h.Q.ActiveTokenPrefix(r.Context(), s.ID); err == nil {
			v.TokenPrefix = t.Prefix
		}
		v.InstallCommand = "curl -sL " + h.PublicURL + "/install | sudo sh -s -- --token <YOUR_TOKEN>"
	}
	httpx.JSON(w, http.StatusOK, v)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	s := FromContext(r.Context())
	u, _ := auth.FromContext(r.Context())
	var in siteInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	if msg := in.clean(); msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
		return
	}
	if err := h.Q.UpdateSite(r.Context(), store.UpdateSiteParams{ID: s.ID, Name: in.Name, Domain: in.Domain}); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	audit.Log(r.Context(), h.Q, &s.ID, &u.ID, "site.update", map[string]any{"name": in.Name, "domain": in.Domain}, httpx.ClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	s := FromContext(r.Context())
	u, _ := auth.FromContext(r.Context())
	if err := h.Q.DeleteSite(r.Context(), s.ID); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	// site_id kept in the audit row so the history survives.
	audit.Log(r.Context(), h.Q, &s.ID, &u.ID, "site.delete", map[string]any{"domain": s.Domain}, httpx.ClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// newToken creates a fresh agent token and revokes the old one. The token is shown once.
func (h *Handler) newToken(w http.ResponseWriter, r *http.Request) {
	s := FromContext(r.Context())
	u, _ := auth.FromContext(r.Context())
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	token := "owl_" + base64.RawURLEncoding.EncodeToString(raw)
	err := pgx.BeginFunc(r.Context(), h.Pool, func(tx pgx.Tx) error {
		q := h.Q.WithTx(tx)
		if err := q.RevokeAgentTokens(r.Context(), s.ID); err != nil {
			return err
		}
		return q.CreateAgentToken(r.Context(), store.CreateAgentTokenParams{SiteID: s.ID, TokenHash: HashToken(token), Prefix: token[:10], CreatedBy: &u.ID})
	})
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	audit.Log(r.Context(), h.Q, &s.ID, &u.ID, "agent.token_created", map[string]any{"prefix": token[:10]}, httpx.ClientIP(r))
	httpx.JSON(w, http.StatusCreated, map[string]string{
		"token":           token,
		"install_command": "curl -sL " + h.PublicURL + "/install | sudo sh -s -- --token " + token,
		"note":            "Copy it now: it is shown only once. Any older token for this site stopped working.",
	})
}

// HashToken hashes an agent token for storage/lookup.
func HashToken(t string) []byte {
	s := sha256.Sum256([]byte(t))
	return s[:]
}

// AgentSite is the site an agent token belongs to.
type AgentSite struct {
	ID           int64
	ProtectedIPs []string
}

type agentCtxKey struct{}

// AgentFromContext returns the site set by RequireAgent.
func AgentFromContext(r *http.Request) AgentSite {
	s, _ := r.Context().Value(agentCtxKey{}).(AgentSite)
	return s
}

// RequireAgent authenticates "Authorization: Bearer owl_..." agent requests.
func RequireAgent(q *store.Queries) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !strings.HasPrefix(tok, "owl_") || len(tok) != 47 {
				httpx.Error(w, http.StatusUnauthorized, "missing or bad agent token")
				return
			}
			row, err := q.SiteByAgentToken(r.Context(), HashToken(tok))
			if errors.Is(err, pgx.ErrNoRows) {
				httpx.Error(w, http.StatusUnauthorized, "agent token is not valid (revoked?)")
				return
			}
			if err != nil {
				httpx.Internal(w, r, err)
				return
			}
			ctx := r.Context()
			next.ServeHTTP(w, r.WithContext(contextWith(ctx, AgentSite{ID: row.ID, ProtectedIPs: row.ProtectedIps})))
		})
	}
}
