// Package notes writes a short, plain-words daily summary per site.
package notes

import (
	"fmt"
	"strings"

	"github.com/NazifSelimi/httpowl-api/internal/store"
)

// Data is everything a note talks about.
type Data struct {
	Day       string                  `json:"day"`
	Totals    store.StatsTotalsRow    `json:"totals"`
	Prev      store.StatsTotalsRow    `json:"previous"`
	Countries []store.TopCountriesRow `json:"countries"`
	Reasons   []store.TopReasonsRow   `json:"reasons"`
	Slow      []store.SlowPathsRow    `json:"slow"`
	Errors    []store.ErrorPathsRow   `json:"errors"`
	NewRules  int64                   `json:"new_rules"`
}

// Compose turns Data into a few short sentences anyone can read.
func Compose(d Data) string {
	t := d.Totals
	var b strings.Builder
	if t.Requests == 0 {
		return "No visits were recorded on " + d.Day + ". If that's unexpected, check that the HTTPowl agent is running on your server."
	}
	when := "On " + d.Day
	if d.Day == "today" {
		when = "So far today"
	}
	fmt.Fprintf(&b, "%s your site got %s requests from %s different addresses", when, num(t.Requests), num(t.UniqueIps))
	if d.Prev.Requests > 0 {
		ch := float64(t.Requests-d.Prev.Requests) / float64(d.Prev.Requests) * 100
		switch {
		case ch >= 20:
			fmt.Fprintf(&b, " — %.0f%% more than the day before", ch)
		case ch <= -20:
			fmt.Fprintf(&b, " — %.0f%% less than the day before", -ch)
		default:
			b.WriteString(", about the same as the day before")
		}
	}
	b.WriteString(".\n")
	fmt.Fprintf(&b, "%s were people, %s were bots and %s were attacks.\n", pct(t.Humans, t.Requests), pct(t.Bots, t.Requests), pct(t.Attacks, t.Requests))
	if len(d.Countries) > 0 {
		var cs []string
		for i, c := range d.Countries {
			if i == 3 {
				break
			}
			name := c.Country
			if name == "" {
				name = "unknown"
			}
			cs = append(cs, fmt.Sprintf("%s (%s)", name, num(c.Requests)))
		}
		b.WriteString("Most visits came from " + strings.Join(cs, ", ") + ".\n")
	}
	var attacks []string
	for _, r := range d.Reasons {
		if r.Tag == "attack" && len(attacks) < 3 {
			attacks = append(attacks, fmt.Sprintf("%s %s (%s)", plural(r.Ips, "address", "addresses"), r.Reason, plural(r.Requests, "time", "times")))
		}
	}
	if len(attacks) > 0 {
		b.WriteString("Attacks: " + strings.Join(attacks, "; ") + ".\n")
		if d.NewRules == 0 {
			b.WriteString("Tip: open Attacks and block the worst addresses with one click (you can undo it).\n")
		}
	} else {
		b.WriteString("No attacks were seen. 👍\n")
	}
	if d.NewRules > 0 {
		fmt.Fprintf(&b, "Your team added %s.\n", plural(d.NewRules, "block rule", "block rules"))
	}
	if t.Errors5xx > 0 {
		fmt.Fprintf(&b, "%s ended in a server error", plural(t.Errors5xx, "request", "requests"))
		if len(d.Errors) > 0 {
			fmt.Fprintf(&b, ", mostly on %s (%d)", d.Errors[0].Path, d.Errors[0].Status)
		}
		b.WriteString(" — worth checking.\n")
	}
	if len(d.Slow) > 0 && d.Slow[0].AvgMs >= 1000 {
		fmt.Fprintf(&b, "Slowest page: %s took %.1f seconds on average.\n", d.Slow[0].Path, d.Slow[0].AvgMs/1000)
	}
	return strings.TrimSpace(b.String())
}

func num(n int64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func pct(part, total int64) string {
	if total == 0 {
		return "0%"
	}
	p := float64(part) / float64(total) * 100
	if p > 0 && p < 1 {
		return "under 1%"
	}
	return fmt.Sprintf("%.0f%%", p)
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return num(n) + " " + many
}
