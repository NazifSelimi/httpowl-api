// Package team manages who can see/act on a site: Owner, Admin, Viewer, Client.
package team

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/NazifSelimi/httpowl-api/internal/audit"
	"github.com/NazifSelimi/httpowl-api/internal/auth"
	"github.com/NazifSelimi/httpowl-api/internal/httpx"
	"github.com/NazifSelimi/httpowl-api/internal/sites"
	"github.com/NazifSelimi/httpowl-api/internal/store"
)

type Handler struct {
	Q *store.Queries
}

// Routes mounts under /sites/{siteID}.
func (h *Handler) Routes(r chi.Router) {
	r.With(sites.Load(h.Q, sites.RoleViewer)).Get("/team", h.list)
	r.With(sites.Load(h.Q, sites.RoleAdmin)).Post("/team", h.add)
	r.With(sites.Load(h.Q, sites.RoleOwner)).Patch("/team/{userID}", h.setRole)
	r.With(sites.Load(h.Q, sites.RoleClient)).Delete("/team/{userID}", h.remove)
	r.With(sites.Load(h.Q, sites.RoleAdmin)).Delete("/team/invites/{email}", h.cancelInvite)
	r.With(sites.Load(h.Q, sites.RoleAdmin)).Get("/audit", h.siteAudit)
}

// UserRoutes mounts account-level routes.
func (h *Handler) UserRoutes(r chi.Router) {
	r.Get("/audit/me", h.myAudit)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	members, err := h.Q.ListMembers(r.Context(), s.ID)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	invites, err := h.Q.ListInvites(r.Context(), s.ID)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if invites == nil {
		invites = []store.ListInvitesRow{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"members": members, "invites": invites, "roles": roleHelp})
}

var roleHelp = map[string]string{
	sites.RoleOwner:  "Everything, including team and deleting the site",
	sites.RoleAdmin:  "See everything, block/unblock, agent token, invite viewers and clients",
	sites.RoleViewer: "See everything, change nothing",
	sites.RoleClient: "See the daily note and summary charts only (good for your customers)",
}

// canGrant: owners grant any role; admins only viewer/client.
func canGrant(actor, role string) bool {
	if actor == sites.RoleOwner {
		return true
	}
	return actor == sites.RoleAdmin && (role == sites.RoleViewer || role == sites.RoleClient)
}

type addInput struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (h *Handler) add(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	u, _ := auth.FromContext(r.Context())
	var in addInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	in.Email = strings.TrimSpace(in.Email)
	if a, err := mail.ParseAddress(in.Email); err != nil || a.Address != in.Email {
		httpx.Error(w, http.StatusBadRequest, "enter a valid email address")
		return
	}
	if !sites.ValidRole(in.Role) {
		httpx.Error(w, http.StatusBadRequest, "role must be owner, admin, viewer or client")
		return
	}
	if !canGrant(s.Role, in.Role) {
		httpx.Error(w, http.StatusForbidden, "admins can only add viewers and clients")
		return
	}
	ip := httpx.ClientIP(r)
	target, err := h.Q.GetUserByEmail(r.Context(), in.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := h.Q.UpsertInvite(r.Context(), store.UpsertInviteParams{SiteID: s.ID, Email: in.Email, Role: in.Role, InvitedBy: &u.ID}); err != nil {
			httpx.Internal(w, r, err)
			return
		}
		audit.Log(r.Context(), h.Q, &s.ID, &u.ID, "team.invite", map[string]any{"email": in.Email, "role": in.Role}, ip)
		httpx.JSON(w, http.StatusCreated, map[string]any{"invited": in.Email, "role": in.Role,
			"note": "No account with this email yet. They get access as soon as they sign up with it."})
		return
	}
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if old, err := h.Q.GetMemberRole(r.Context(), store.GetMemberRoleParams{SiteID: s.ID, UserID: target.ID}); err == nil {
		if !canGrant(s.Role, old) {
			httpx.Error(w, http.StatusForbidden, "this person is already "+old+"; only an owner can change that")
			return
		}
		if old == sites.RoleOwner && in.Role != sites.RoleOwner {
			httpx.Error(w, http.StatusConflict, "use change role to demote an owner")
			return
		}
	}
	if err := h.Q.AddMember(r.Context(), store.AddMemberParams{SiteID: s.ID, UserID: target.ID, Role: in.Role}); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	audit.Log(r.Context(), h.Q, &s.ID, &u.ID, "team.add", map[string]any{"user_id": target.ID, "email": target.Email, "role": in.Role}, ip)
	httpx.JSON(w, http.StatusCreated, map[string]any{"added": target.Email, "role": in.Role})
}

func (h *Handler) setRole(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	u, _ := auth.FromContext(r.Context())
	target, err := httpx.IDParam(r, "userID")
	if err != nil {
		httpx.Error(w, http.StatusNotFound, "member not found")
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if !sites.ValidRole(in.Role) {
		httpx.Error(w, http.StatusBadRequest, "role must be owner, admin, viewer or client")
		return
	}
	old, err := h.Q.GetMemberRole(r.Context(), store.GetMemberRoleParams{SiteID: s.ID, UserID: target})
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.Error(w, http.StatusNotFound, "member not found")
		return
	}
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if old == sites.RoleOwner && in.Role != sites.RoleOwner && !h.hasOtherOwner(r.Context(), s.ID) {
		httpx.Error(w, http.StatusConflict, "a site needs at least one owner; make someone else owner first")
		return
	}
	if _, err := h.Q.SetMemberRole(r.Context(), store.SetMemberRoleParams{SiteID: s.ID, UserID: target, Role: in.Role}); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	audit.Log(r.Context(), h.Q, &s.ID, &u.ID, "team.role", map[string]any{"user_id": target, "from": old, "to": in.Role}, httpx.ClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// remove: owners remove anyone, admins remove viewers/clients, anyone can leave.
func (h *Handler) remove(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	u, _ := auth.FromContext(r.Context())
	target, err := httpx.IDParam(r, "userID")
	if err != nil {
		httpx.Error(w, http.StatusNotFound, "member not found")
		return
	}
	old, err := h.Q.GetMemberRole(r.Context(), store.GetMemberRoleParams{SiteID: s.ID, UserID: target})
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.Error(w, http.StatusNotFound, "member not found")
		return
	}
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if target != u.ID && !canGrant(s.Role, old) {
		httpx.Error(w, http.StatusForbidden, "your role ("+s.Role+") can't remove a "+old)
		return
	}
	if old == sites.RoleOwner && !h.hasOtherOwner(r.Context(), s.ID) {
		httpx.Error(w, http.StatusConflict, "a site needs at least one owner; make someone else owner first (or delete the site)")
		return
	}
	if _, err := h.Q.RemoveMember(r.Context(), store.RemoveMemberParams{SiteID: s.ID, UserID: target}); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	action := "team.remove"
	if target == u.ID {
		action = "team.leave"
	}
	audit.Log(r.Context(), h.Q, &s.ID, &u.ID, action, map[string]any{"user_id": target, "role": old}, httpx.ClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) hasOtherOwner(ctx context.Context, siteID int64) bool {
	n, err := h.Q.CountOwners(ctx, siteID)
	return err == nil && n > 1
}

func (h *Handler) cancelInvite(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	u, _ := auth.FromContext(r.Context())
	email := chi.URLParam(r, "email")
	n, err := h.Q.DeleteInvite(r.Context(), store.DeleteInviteParams{SiteID: s.ID, Lower: email})
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if n == 0 {
		httpx.Error(w, http.StatusNotFound, "no invite for this email")
		return
	}
	audit.Log(r.Context(), h.Q, &s.ID, &u.ID, "team.invite_cancel", map[string]any{"email": email}, httpx.ClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// AcceptInvites is the auth.OnSignup hook.
func (h *Handler) AcceptInvites(ctx context.Context, userID int64, email string) {
	invites, err := h.Q.TakeInvites(ctx, email)
	if err != nil {
		return
	}
	for _, inv := range invites {
		if err := h.Q.AddMember(ctx, store.AddMemberParams{SiteID: inv.SiteID, UserID: userID, Role: inv.Role}); err == nil {
			audit.Log(ctx, h.Q, &inv.SiteID, &userID, "team.invite_accepted", map[string]any{"role": inv.Role}, "")
		}
	}
}

func beforeID(r *http.Request) *int64 {
	if v, err := httpx.IDParamQuery(r, "before"); err == nil {
		return &v
	}
	return nil
}

func (h *Handler) siteAudit(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	rows, err := h.Q.ListSiteAudit(r.Context(), store.ListSiteAuditParams{SiteID: &s.ID, Limit: 100, BeforeID: beforeID(r)})
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if rows == nil {
		rows = []store.ListSiteAuditRow{}
	}
	httpx.JSON(w, http.StatusOK, rows)
}

func (h *Handler) myAudit(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.FromContext(r.Context())
	rows, err := h.Q.ListUserAudit(r.Context(), store.ListUserAuditParams{UserID: &u.ID, Limit: 100, BeforeID: beforeID(r)})
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if rows == nil {
		rows = []store.ListUserAuditRow{}
	}
	httpx.JSON(w, http.StatusOK, rows)
}
