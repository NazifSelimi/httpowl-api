package analyse

import (
	"net/netip"
	"testing"
	"time"
)

func in(method, path, query, ua string) Input {
	return Input{SiteID: 1, TS: time.Now(), IP: netip.MustParseAddr("192.0.2.1"), Method: method, Path: path, Query: query, Status: 200, UA: ua}
}

func TestClassify(t *testing.T) {
	a := New()
	browser := "Mozilla/5.0 (Windows NT 10.0) Chrome/130"
	cases := []struct {
		in  Input
		tag string
	}{
		{in("GET", "/", "", browser), Human},
		{in("GET", "/shop/item", "id=4", browser), Human},
		{in("GET", "/robots.txt", "", "Mozilla/5.0 (compatible; Googlebot/2.1)"), Bot},
		{in("GET", "/", "", ""), Bot},
		{in("GET", "/", "", "curl/8.4"), Bot},
		{in("GET", "/.env", "", browser), Attack},
		{in("GET", "/.git/config", "", browser), Attack},
		{in("GET", "/search", "q=1 union select password", browser), Attack},
		{in("GET", "/", "", "sqlmap/1.7"), Attack},
		{in("-", "\\x16\\x03", "", ""), Attack},
		{in("GET", "/xmlrpc.php", "", browser), Human}, // GET alone isn't an attack
	}
	for _, c := range cases {
		if tag, why := a.Classify(c.in); tag != c.tag {
			t.Errorf("%s %s %q: got %s (%s), want %s", c.in.Method, c.in.Path, c.in.UA, tag, why, c.tag)
		}
	}
}

func TestBruteForce(t *testing.T) {
	a := New()
	var tag string
	for i := 0; i <= LoginPostsPerMin; i++ {
		tag, _ = a.Classify(in("POST", "/wp-login.php", "", "Mozilla/5.0"))
	}
	if tag != Attack {
		t.Fatalf("brute force not detected: %s", tag)
	}
	other := in("POST", "/wp-login.php", "", "Mozilla/5.0")
	other.IP = netip.MustParseAddr("192.0.2.2")
	if tag, _ := a.Classify(other); tag != Human {
		t.Fatalf("other IP tagged %s", tag)
	}
}

func TestRateSpike(t *testing.T) {
	a := New()
	var tag string
	for i := 0; i <= RequestsPerMin; i++ {
		tag, _ = a.Classify(in("GET", "/", "", "Mozilla/5.0"))
	}
	if tag != Attack {
		t.Fatalf("rate spike not detected: %s", tag)
	}
}
