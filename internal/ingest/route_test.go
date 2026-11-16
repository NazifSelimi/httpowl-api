package ingest

import "testing"

func TestRouter(t *testing.T) {
	r := NewRouter(1, []Candidate{{1, "tessa.mk"}, {2, "oya.com.mk"}, {3, "www.epower.example"}})
	cases := map[string]int64{
		"":                   1, // no domain in the log: agent's own site
		"tessa.mk":           1,
		"www.tessa.mk":       1,
		"OYA.com.mk":         2,
		"www.oya.com.mk.":    2,
		"epower.example":     3,
		"unknown.example":    1, // not added by the owner: stays home
		"213.130.144.132":    1,
		"evil-oya.com.mk.io": 1,
	}
	for host, want := range cases {
		if got := r.SiteFor(host); got != want {
			t.Errorf("%q -> %d, want %d", host, got, want)
		}
	}
}
