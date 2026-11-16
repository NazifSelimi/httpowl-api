package ingest

import "strings"

// Candidate is a site a visit may belong to (same owner as the agent's site).
type Candidate struct {
	ID     int64
	Domain string
}

// Router sends each visit to the site whose domain matches the visit's Host.
// Visits without a host, or for a domain the owner hasn't added, stay on the agent's site.
type Router struct {
	home    int64
	domains map[string]int64
}

// NewRouter indexes candidates by domain; "www." on either side is ignored.
func NewRouter(home int64, candidates []Candidate) *Router {
	r := &Router{home: home, domains: map[string]int64{}}
	for _, c := range candidates {
		r.domains[bareDomain(c.Domain)] = c.ID
	}
	return r
}

// SiteFor returns the site ID for a visit's host.
func (r *Router) SiteFor(host string) int64 {
	if host == "" {
		return r.home
	}
	if id, ok := r.domains[bareDomain(host)]; ok {
		return id
	}
	return r.home
}

func bareDomain(d string) string {
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	return strings.TrimPrefix(d, "www.")
}
