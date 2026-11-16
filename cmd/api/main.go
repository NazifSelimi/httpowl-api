// Command api is the HTTPowl web API.
package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/NazifSelimi/httpowl-api/internal/analyse"
	"github.com/NazifSelimi/httpowl-api/internal/auth"
	"github.com/NazifSelimi/httpowl-api/internal/config"
	"github.com/NazifSelimi/httpowl-api/internal/httpx"
	"github.com/NazifSelimi/httpowl-api/internal/ingest"
	"github.com/NazifSelimi/httpowl-api/internal/sites"
	"github.com/NazifSelimi/httpowl-api/internal/store"
	"github.com/NazifSelimi/httpowl-api/migrations"
)

var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := migrate(pool); err != nil {
		return err
	}
	q := store.New(pool)

	a := &app{cfg: cfg, pool: pool, q: q, auth: auth.New(q, cfg.CookieSecure)}
	a.analyser = analyse.New()
	a.ingest = &ingest.Handler{Q: q, Enrich: a.enrich}
	if err := ingest.MaintainPartitions(ctx, pool); err != nil {
		return err
	}
	a.startBackground(ctx)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           a.router(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	slog.Info("httpowl api listening", "addr", cfg.ListenAddr, "version", version)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type app struct {
	cfg    config.Config
	pool   *pgxpool.Pool
	q      *store.Queries
	auth   *auth.Handler
	ingest *ingest.Handler

	analyser *analyse.Analyzer
}

// enrich tags each stored request (and adds its country once GeoIP is set up).
func (a *app) enrich(rows []ingest.Row) {
	for i := range rows {
		r := &rows[i]
		r.Tag, r.Reason = a.analyser.Classify(analyse.Input{
			SiteID: r.SiteID, TS: r.Ts, IP: r.Ip, Method: r.Method, Path: r.Path, Query: r.Query, Status: int(r.Status), UA: r.Ua,
		})
	}
}

func (a *app) router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer, securityHeaders)
	r.Route("/api", func(r chi.Router) {
		r.Use(httpx.SameOrigin(a.cfg.PublicURL))
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok", "version": version})
		})
		a.auth.Routes(r)
		a.ingest.Routes(r)
		r.Group(func(r chi.Router) {
			r.Use(a.auth.Require)
			a.userRoutes(r)
		})
	})
	return r
}

// userRoutes is extended by later features.
func (a *app) userRoutes(r chi.Router) {
	(&sites.Handler{Pool: a.pool, Q: a.q, PublicURL: a.cfg.PublicURL}).Routes(r)
}

func (a *app) startBackground(ctx context.Context) {
	go every(ctx, time.Hour, func(ctx context.Context) {
		if err := ingest.MaintainPartitions(ctx, a.pool); err != nil {
			slog.Error("partitions", "err", err)
		}
	})
	go every(ctx, time.Hour, func(ctx context.Context) {
		if err := a.q.DeleteExpiredSessions(ctx); err != nil {
			slog.Error("session cleanup", "err", err)
		}
	})
}

// every runs fn now and then every d until ctx ends.
func every(ctx context.Context, d time.Duration, fn func(context.Context)) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		fn(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func migrate(pool *pgxpool.Pool) error {
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	db := stdlib.OpenDBFromPool(pool)
	defer func(db *sql.DB) { _ = db.Close() }(db)
	return goose.Up(db, ".")
}
