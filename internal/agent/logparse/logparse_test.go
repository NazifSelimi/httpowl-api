package logparse

import "testing"

func TestFormats(t *testing.T) {
	cases := []struct {
		name, line           string
		ip, method, path, ua string
		status               int
		durMS                float64
		host                 string
	}{
		{"nginx combined", `203.0.113.5 - - [16/Nov/2026:10:00:00 +0100] "GET /index.html?a=1 HTTP/1.1" 200 512 "https://g.com/" "Mozilla/5.0 (X11)"`, "203.0.113.5", "GET", "/index.html", "Mozilla/5.0 (X11)", 200, 0, ""},
		{"nginx with rt", `203.0.113.5 - - [16/Nov/2026:10:00:00 +0100] "POST /wp-login.php HTTP/1.1" 401 0 "-" "curl/8" rt=0.250`, "203.0.113.5", "POST", "/wp-login.php", "curl/8", 401, 250, ""},
		{"apache common", `2001:db8::1 - frank [16/Nov/2026:10:00:00 -0700] "GET /.env HTTP/1.0" 404 -`, "2001:db8::1", "GET", "/.env", "", 404, 0, ""},
		{"apache vhost", `shop.example.com:443 198.51.100.7 - - [16/Nov/2026:10:00:00 +0000] "GET / HTTP/2.0" 200 10 "-" "Googlebot/2.1"`, "198.51.100.7", "GET", "/", "Googlebot/2.1", 200, 0, "shop.example.com"},
		{"traefik clf", `192.0.2.1 - - [16/Nov/2026:10:00:00 +0000] "GET /api HTTP/1.1" 200 33 "-" "ua" 42 "router@docker" "http://10.0.0.2:80" 17ms`, "192.0.2.1", "GET", "/api", "ua", 200, 17, ""},
		{"garbage request", `192.0.2.9 - - [16/Nov/2026:10:00:00 +0000] "\x16\x03\x01" 400 157 "-" "-"`, "192.0.2.9", "-", `\x16\x03\x01`, "-", 400, 0, ""},
		{"caddy json", `{"level":"info","ts":1763287200.5,"logger":"http.log.access","request":{"remote_ip":"192.0.2.2","client_ip":"192.0.2.3","proto":"HTTP/2.0","method":"GET","host":"ex.com","uri":"/x?y=1","headers":{"User-Agent":["Bot/1"]}},"duration":0.012,"size":99,"status":304}`, "192.0.2.3", "GET", "/x", "Bot/1", 304, 12, "ex.com"},
		{"traefik json", `{"ClientHost":"192.0.2.4","RequestMethod":"PUT","RequestHost":"a.io","RequestPath":"/p","DownstreamStatus":201,"DownstreamContentSize":5,"Duration":3000000,"StartUTC":"2026-11-16T10:00:00.1Z","request_User-Agent":"k6"}`, "192.0.2.4", "PUT", "/p", "k6", 201, 3, "a.io"},
	}
	for _, c := range cases {
		var p Parser
		r, err := p.Parse(c.line)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if r.IP != c.ip || r.Method != c.method || r.Path != c.path || r.UA != c.ua || r.Status != c.status || r.DurationMS != c.durMS || r.Host != c.host {
			t.Errorf("%s: got %+v", c.name, r)
		}
	}
}

func TestIIS(t *testing.T) {
	var p Parser
	lines := []string{
		"#Software: Microsoft Internet Information Services 10.0",
		"#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken",
		"2026-11-16 10:00:00 10.0.0.1 GET /default.aspx id=3 443 - 203.0.113.9 Mozilla/5.0+(Windows) - 200 0 0 15",
	}
	var got []string
	for _, l := range lines {
		if r, err := p.Parse(l); err == nil {
			got = append(got, r.IP+" "+r.Path+" "+r.Query+" "+r.UA)
		}
	}
	if len(got) != 1 || got[0] != "203.0.113.9 /default.aspx id=3 Mozilla/5.0 (Windows)" {
		t.Fatalf("got %q", got)
	}
}

func TestRejects(t *testing.T) {
	var p Parser
	for _, l := range []string{"", "hello world", `notanip - - [16/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`, `{"msg":"x"}`} {
		if _, err := p.Parse(l); err == nil {
			t.Errorf("accepted %q", l)
		}
	}
}
