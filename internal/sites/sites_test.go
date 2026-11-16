package sites

import "testing"

func TestCleanDomain(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/path": "example.com",
		"shop.example.co.uk":       "shop.example.co.uk",
	}
	for in, want := range cases {
		s := siteInput{Domain: in}
		if msg := s.clean(); msg != "" || s.Domain != want {
			t.Errorf("%q -> %q (%s), want %q", in, s.Domain, msg, want)
		}
	}
	for _, bad := range []string{"", "localhost", "a b.com", "<script>.com"} {
		s := siteInput{Domain: bad}
		if s.clean() == "" {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRoles(t *testing.T) {
	if !AtLeast(RoleOwner, RoleAdmin) || AtLeast(RoleViewer, RoleAdmin) || AtLeast("bogus", RoleClient) {
		t.Fatal("role ranking wrong")
	}
}
