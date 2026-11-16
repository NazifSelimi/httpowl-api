package analyse

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/NazifSelimi/httpowl-api/internal/httpx"
	"github.com/NazifSelimi/httpowl-api/internal/sites"
	"github.com/NazifSelimi/httpowl-api/internal/store"
)

// StatsHandler serves the read-only dashboards API.
type StatsHandler struct {
	Q *store.Queries
}

// Routes mounts under /sites/{siteID}.
func (h *StatsHandler) Routes(r chi.Router) {
	r.With(sites.Load(h.Q, sites.RoleClient)).Get("/stats", h.stats)
	r.With(sites.Load(h.Q, sites.RoleViewer)).Get("/requests", h.requests)
}

var ranges = map[string]struct{ span, bucket time.Duration }{
	"15m": {15 * time.Minute, time.Minute},
	"1h":  {time.Hour, time.Minute},
	"24h": {24 * time.Hour, 15 * time.Minute},
	"7d":  {7 * 24 * time.Hour, 2 * time.Hour},
	"30d": {30 * 24 * time.Hour, 24 * time.Hour},
}

// timeRange reads ?range=1h (default 24h) or ?from=&to= (RFC3339).
func timeRange(r *http.Request) (from, to time.Time, bucket time.Duration, ok bool) {
	to = time.Now().UTC()
	q := r.URL.Query()
	if f := q.Get("from"); f != "" {
		var err error
		if from, err = time.Parse(time.RFC3339, f); err != nil {
			return
		}
		if t := q.Get("to"); t != "" {
			if to, err = time.Parse(time.RFC3339, t); err != nil {
				return
			}
		}
		span := to.Sub(from)
		if span <= 0 || span > 31*24*time.Hour {
			return
		}
		bucket = time.Minute
		for _, rg := range []string{"1h", "24h", "7d", "30d"} {
			if span > ranges[rg].span {
				continue
			}
			bucket = ranges[rg].bucket
			break
		}
		return from, to, bucket, true
	}
	name := q.Get("range")
	if name == "" {
		name = "24h"
	}
	rg, found := ranges[name]
	if !found {
		return
	}
	return to.Add(-rg.span), to, rg.bucket, true
}

func (h *StatsHandler) stats(w http.ResponseWriter, r *http.Request) {
	site := sites.FromContext(r.Context())
	from, to, bucket, ok := timeRange(r)
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "range must be 15m, 1h, 24h, 7d or 30d (or from/to within 31 days)")
		return
	}
	ctx := r.Context()
	totals, err := h.Q.StatsTotals(ctx, store.StatsTotalsParams{SiteID: site.ID, FromTs: from, ToTs: to})
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	series, err := h.Q.StatsSeries(ctx, store.StatsSeriesParams{SiteID: site.ID, FromTs: from, ToTs: to, BucketSecs: int32(bucket.Seconds())})
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	countries, err := h.Q.TopCountries(ctx, store.TopCountriesParams{SiteID: site.ID, FromTs: from, ToTs: to, Lim: 20})
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	out := map[string]any{
		"from": from, "to": to, "bucket_seconds": int(bucket.Seconds()),
		"totals": totals, "series": nonNil(series), "countries": nonNil(countries),
	}
	// Clients see the summary only; IPs and paths are for viewers and up.
	if sites.AtLeast(site.Role, sites.RoleViewer) {
		ips, err := h.Q.TopIPs(ctx, store.TopIPsParams{SiteID: site.ID, FromTs: from, ToTs: to, Lim: 20})
		if err != nil {
			httpx.Internal(w, r, err)
			return
		}
		paths, err := h.Q.TopPaths(ctx, store.TopPathsParams{SiteID: site.ID, FromTs: from, ToTs: to, Lim: 20})
		if err != nil {
			httpx.Internal(w, r, err)
			return
		}
		reasons, err := h.Q.TopReasons(ctx, store.TopReasonsParams{SiteID: site.ID, FromTs: from, ToTs: to, Lim: 20})
		if err != nil {
			httpx.Internal(w, r, err)
			return
		}
		out["top_ips"], out["top_paths"], out["top_reasons"] = nonNil(ips), nonNil(paths), nonNil(reasons)
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (h *StatsHandler) requests(w http.ResponseWriter, r *http.Request) {
	site := sites.FromContext(r.Context())
	from, to, _, ok := timeRange(r)
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "bad range")
		return
	}
	q := r.URL.Query()
	p := store.ListRequestsParams{SiteID: site.ID, FromTs: from, ToTs: to, Lim: 100}
	// cursor: ?before=<ts of the last row seen>
	if b := q.Get("before"); b != "" {
		t, err := time.Parse(time.RFC3339Nano, b)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "before must be an RFC3339 time")
			return
		}
		if t.Before(p.ToTs) {
			p.ToTs = t
		}
	}
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 && l <= 500 {
		p.Lim = int32(l)
	}
	if v := q.Get("tag"); v != "" {
		if v != Human && v != Bot && v != Attack {
			httpx.Error(w, http.StatusBadRequest, "tag must be human, bot or attack")
			return
		}
		p.Tag = &v
	}
	if v := q.Get("ip"); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "bad ip")
			return
		}
		p.Ip = &a
	}
	if v := strings.ToUpper(q.Get("country")); v != "" {
		p.Country = &v
	}
	if v := q.Get("method"); v != "" {
		v = strings.ToUpper(v)
		p.Method = &v
	}
	if v := q.Get("status"); v != "" { // 404, 4xx, 5xx
		lo, hi, ok := statusRange(v)
		if !ok {
			httpx.Error(w, http.StatusBadRequest, "status must be like 404, 4xx or 5xx")
			return
		}
		p.StatusMin, p.StatusMax = &lo, &hi
	}
	if v := q.Get("path"); v != "" {
		v = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(v)
		p.PathPrefix = &v
	}
	rows, err := h.Q.ListRequests(r.Context(), p)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	resp := map[string]any{"requests": nonNil(rows)}
	if len(rows) == int(p.Lim) {
		resp["next_before"] = rows[len(rows)-1].Ts.Format(time.RFC3339Nano)
	}
	httpx.JSON(w, http.StatusOK, resp)
}

func statusRange(v string) (int32, int32, bool) {
	if len(v) == 3 && strings.HasSuffix(v, "xx") && v[0] >= '1' && v[0] <= '5' {
		base := int32(v[0]-'0') * 100
		return base, base + 99, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 100 || n > 999 {
		return 0, 0, false
	}
	return int32(n), int32(n), true
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
