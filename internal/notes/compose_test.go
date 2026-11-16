package notes

import (
	"strings"
	"testing"

	"github.com/NazifSelimi/httpowl-api/internal/store"
)

func TestCompose(t *testing.T) {
	d := Data{
		Day:       "2026-11-15",
		Totals:    store.StatsTotalsRow{Requests: 12400, UniqueIps: 830, Humans: 9000, Bots: 3000, Attacks: 400, Errors5xx: 3},
		Prev:      store.StatsTotalsRow{Requests: 8000},
		Countries: []store.TopCountriesRow{{Country: "MK", Requests: 7000}, {Country: "DE", Requests: 2000}},
		Reasons:   []store.TopReasonsRow{{Tag: "attack", Reason: "looked for a secret settings file (.env)", Requests: 120, Ips: 4}},
		Errors:    []store.ErrorPathsRow{{Path: "/checkout", Status: 502, Requests: 3}},
	}
	s := Compose(d)
	for _, want := range []string{"12,400 requests", "55% more", "73% were people", "MK (7,000)", "4 addresses looked for a secret", "/checkout (502)", "Tip:"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if !strings.Contains(Compose(Data{Day: "x"}), "agent is running") {
		t.Error("empty-day note")
	}
}
