package notes

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/NazifSelimi/httpowl-api/internal/httpx"
	"github.com/NazifSelimi/httpowl-api/internal/sites"
	"github.com/NazifSelimi/httpowl-api/internal/store"
)

type Handler struct {
	Q *store.Queries
}

// Routes mounts under /sites/{siteID}. Clients may read notes.
func (h *Handler) Routes(r chi.Router) {
	r.With(sites.Load(h.Q, sites.RoleClient)).Get("/notes", h.list)
	r.With(sites.Load(h.Q, sites.RoleClient)).Get("/notes/today", h.today)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	rows, err := h.Q.ListNotes(r.Context(), s.ID)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	type note struct {
		Day       string          `json:"day"`
		Body      string          `json:"body"`
		Stats     json.RawMessage `json:"stats"`
		CreatedAt time.Time       `json:"created_at"`
	}
	out := make([]note, len(rows))
	for i, n := range rows {
		out[i] = note{Day: n.Day.Format("2006-01-02"), Body: n.Body, Stats: n.Stats, CreatedAt: n.CreatedAt}
	}
	httpx.JSON(w, http.StatusOK, out)
}

// today returns a live "so far today" note (not stored).
func (h *Handler) today(w http.ResponseWriter, r *http.Request) {
	s := sites.FromContext(r.Context())
	day := time.Now().UTC().Truncate(24 * time.Hour)
	d, err := h.collect(r.Context(), s.ID, day, time.Now().UTC())
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	d.Day = "today"
	httpx.JSON(w, http.StatusOK, map[string]any{"day": day.Format("2006-01-02"), "body": Compose(d), "stats": d})
}

func (h *Handler) collect(ctx context.Context, siteID int64, from, to time.Time) (Data, error) {
	d := Data{Day: from.Format("Monday, 2 January")}
	var err error
	if d.Totals, err = h.Q.StatsTotals(ctx, store.StatsTotalsParams{SiteID: siteID, FromTs: from, ToTs: to}); err != nil {
		return d, err
	}
	if d.Prev, err = h.Q.StatsTotals(ctx, store.StatsTotalsParams{SiteID: siteID, FromTs: from.Add(-24 * time.Hour), ToTs: to.Add(-24 * time.Hour)}); err != nil {
		return d, err
	}
	if d.Countries, err = h.Q.TopCountries(ctx, store.TopCountriesParams{SiteID: siteID, FromTs: from, ToTs: to, Lim: 5}); err != nil {
		return d, err
	}
	if d.Reasons, err = h.Q.TopReasons(ctx, store.TopReasonsParams{SiteID: siteID, FromTs: from, ToTs: to, Lim: 10}); err != nil {
		return d, err
	}
	if d.Slow, err = h.Q.SlowPaths(ctx, store.SlowPathsParams{SiteID: siteID, FromTs: from, ToTs: to}); err != nil {
		return d, err
	}
	if d.Errors, err = h.Q.ErrorPaths(ctx, store.ErrorPathsParams{SiteID: siteID, FromTs: from, ToTs: to}); err != nil {
		return d, err
	}
	d.NewRules, err = h.Q.NewRulesBetween(ctx, store.NewRulesBetweenParams{SiteID: siteID, CreatedAt: from, CreatedAt_2: to})
	return d, err
}

// WriteYesterday stores yesterday's (UTC) note for every site that lacks one.
func (h *Handler) WriteYesterday(ctx context.Context) {
	day := time.Now().UTC().Truncate(24 * time.Hour).Add(-24 * time.Hour)
	ids, err := h.Q.SitesMissingNote(ctx, day)
	if err != nil {
		slog.Error("daily notes", "err", err)
		return
	}
	for _, id := range ids {
		d, err := h.collect(ctx, id, day, day.Add(24*time.Hour))
		if err != nil {
			slog.Error("daily note", "site", id, "err", err)
			continue
		}
		stats, _ := json.Marshal(d)
		if err := h.Q.UpsertNote(ctx, store.UpsertNoteParams{SiteID: id, Day: day, Body: Compose(d), Stats: stats}); err != nil {
			slog.Error("daily note save", "site", id, "err", err)
		}
	}
	if len(ids) > 0 {
		slog.Info("daily notes written", "day", day.Format("2006-01-02"), "sites", len(ids))
	}
}
