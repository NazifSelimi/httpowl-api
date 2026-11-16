// Package sites: websites, per-site roles and agent tokens.
package sites

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/NazifSelimi/httpowl-api/internal/auth"
	"github.com/NazifSelimi/httpowl-api/internal/httpx"
	"github.com/NazifSelimi/httpowl-api/internal/store"
)

// Roles, from least to most powerful.
const (
	RoleClient = "client" // daily notes + summary stats only
	RoleViewer = "viewer" // everything read-only
	RoleAdmin  = "admin"  // + rules, agent token
	RoleOwner  = "owner"  // + team, delete site
)

var rank = map[string]int{RoleClient: 1, RoleViewer: 2, RoleAdmin: 3, RoleOwner: 4}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { _, ok := rank[r]; return ok }

// AtLeast reports whether role has min's permissions.
func AtLeast(role, min string) bool { return rank[role] >= rank[min] }

// Site is the site the request is about, with the caller's role on it.
type Site = store.GetSiteForUserRow

type ctxKey struct{}

// FromContext returns the site loaded by Load.
func FromContext(ctx context.Context) Site {
	s, _ := ctx.Value(ctxKey{}).(Site)
	return s
}

// Load reads {siteID} from the URL, checks membership and min role.
// Non-members get 404 so site ids can't be probed.
func Load(q *store.Queries, min string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := httpx.IDParam(r, "siteID")
			if err != nil {
				httpx.Error(w, http.StatusNotFound, "site not found")
				return
			}
			u, _ := auth.FromContext(r.Context())
			s, err := q.GetSiteForUser(r.Context(), store.GetSiteForUserParams{ID: id, UserID: u.ID})
			if errors.Is(err, pgx.ErrNoRows) {
				httpx.Error(w, http.StatusNotFound, "site not found")
				return
			}
			if err != nil {
				httpx.Internal(w, r, err)
				return
			}
			if !AtLeast(s.Role, min) {
				httpx.Error(w, http.StatusForbidden, "your role ("+s.Role+") can't do this")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
		})
	}
}

func contextWith(ctx context.Context, s AgentSite) context.Context {
	return context.WithValue(ctx, agentCtxKey{}, s)
}
