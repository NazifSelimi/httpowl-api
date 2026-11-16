// Package auth: sign up, log in, log out and cookie sessions.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NazifSelimi/httpowl-api/internal/audit"
	"github.com/NazifSelimi/httpowl-api/internal/httpx"
	"github.com/NazifSelimi/httpowl-api/internal/store"
)

const (
	CookieName = "owl_session"
	sessionTTL = 30 * 24 * time.Hour
)

type User struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type ctxKey struct{}

// FromContext returns the logged-in user (set by Require).
func FromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(ctxKey{}).(User)
	return u, ok
}

// OnSignup is called after a new account is created (used by team invites).
type OnSignup func(ctx context.Context, userID int64, email string)

type Handler struct {
	Q            *store.Queries
	CookieSecure bool
	OnSignup     OnSignup
	loginLimit   *httpx.Limiter
	signupLimit  *httpx.Limiter
}

func New(q *store.Queries, cookieSecure bool) *Handler {
	return &Handler{
		Q:            q,
		CookieSecure: cookieSecure,
		loginLimit:   httpx.NewLimiter(10, 10*time.Minute),
		signupLimit:  httpx.NewLimiter(5, time.Hour),
	}
}

func (h *Handler) Routes(r chi.Router) {
	r.Post("/auth/signup", h.signup)
	r.Post("/auth/login", h.login)
	r.Post("/auth/logout", h.logout)
	r.With(h.Require).Get("/auth/me", h.me)
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func (h *Handler) signup(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if !h.signupLimit.Allow(ip) {
		httpx.Error(w, http.StatusTooManyRequests, "too many sign-ups from this address, try later")
		return
	}
	var c credentials
	if !httpx.Decode(w, r, &c) {
		return
	}
	c.Email = strings.TrimSpace(c.Email)
	c.Name = strings.TrimSpace(c.Name)
	if a, err := mail.ParseAddress(c.Email); err != nil || a.Address != c.Email || len(c.Email) > 254 {
		httpx.Error(w, http.StatusBadRequest, "enter a valid email address")
		return
	}
	if len(c.Password) < 10 || len(c.Password) > 200 {
		httpx.Error(w, http.StatusBadRequest, "password must be 10 to 200 characters")
		return
	}
	if len(c.Name) > 100 {
		httpx.Error(w, http.StatusBadRequest, "name is too long")
		return
	}
	hash, err := HashPassword(c.Password)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	u, err := h.Q.CreateUser(r.Context(), store.CreateUserParams{Email: c.Email, Name: c.Name, PasswordHash: hash})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		httpx.Error(w, http.StatusConflict, "an account with this email already exists")
		return
	}
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	audit.Log(r.Context(), h.Q, nil, &u.ID, "user.signup", nil, ip)
	if h.OnSignup != nil {
		h.OnSignup(r.Context(), u.ID, u.Email)
	}
	if err := h.startSession(w, r, u.ID); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, User{ID: u.ID, Email: u.Email, Name: u.Name})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	var c credentials
	if !httpx.Decode(w, r, &c) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	if !h.loginLimit.Allow(ip) || !h.loginLimit.Allow("email:"+email) {
		httpx.Error(w, http.StatusTooManyRequests, "too many login attempts, wait 10 minutes")
		return
	}
	u, err := h.Q.GetUserByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		httpx.Internal(w, r, err)
		return
	}
	hash := dummyHash
	if err == nil {
		hash = u.PasswordHash
	}
	ok, _ := CheckPassword(hash, c.Password)
	if err != nil || !ok {
		if err == nil {
			audit.Log(r.Context(), h.Q, nil, &u.ID, "user.login_failed", nil, ip)
		}
		httpx.Error(w, http.StatusUnauthorized, "wrong email or password")
		return
	}
	if err := h.startSession(w, r, u.ID); err != nil {
		httpx.Internal(w, r, err)
		return
	}
	audit.Log(r.Context(), h.Q, nil, &u.ID, "user.login", nil, ip)
	httpx.JSON(w, http.StatusOK, User{ID: u.ID, Email: u.Email, Name: u.Name})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		hash := hashToken(c.Value)
		if su, err := h.Q.GetSessionUser(r.Context(), hash); err == nil {
			audit.Log(r.Context(), h.Q, nil, &su.ID, "user.logout", nil, httpx.ClientIP(r))
		}
		_ = h.Q.DeleteSession(r.Context(), hash)
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.CookieSecure, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

// me returns the signed-in user plus the IP they connect from, so the UI can
// mark "You" in traffic lists instead of offering to block yourself.
func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	u, _ := FromContext(r.Context())
	httpx.JSON(w, http.StatusOK, map[string]any{"id": u.ID, "email": u.Email, "name": u.Name, "ip": httpx.ClientIP(r)})
}

func (h *Handler) startSession(w http.ResponseWriter, r *http.Request, userID int64) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	exp := time.Now().Add(sessionTTL)
	ua := r.UserAgent()
	if len(ua) > 300 {
		ua = ua[:300]
	}
	if err := h.Q.CreateSession(r.Context(), store.CreateSessionParams{
		TokenHash: hashToken(token), UserID: userID, Ip: httpx.ClientIP(r), UserAgent: ua, ExpiresAt: exp,
	}); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Path: "/", Expires: exp,
		HttpOnly: true, Secure: h.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Require rejects requests without a valid session and puts the User in the context.
func (h *Handler) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := h.UserFromRequest(r)
		if !ok {
			httpx.Error(w, http.StatusUnauthorized, "please log in")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

// UserFromRequest validates the session cookie (also used by the WebSocket).
func (h *Handler) UserFromRequest(r *http.Request) (User, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || len(c.Value) != 43 {
		return User{}, false
	}
	hash := hashToken(c.Value)
	su, err := h.Q.GetSessionUser(r.Context(), hash)
	if err != nil {
		return User{}, false
	}
	if time.Since(su.LastSeenAt) > 5*time.Minute {
		_ = h.Q.TouchSession(r.Context(), store.TouchSessionParams{TokenHash: hash, Ip: httpx.ClientIP(r)})
	}
	return User{ID: su.ID, Email: su.Email, Name: su.Name}, true
}

func hashToken(t string) []byte {
	s := sha256.Sum256([]byte(t))
	return s[:]
}
