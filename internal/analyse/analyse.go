// Package analyse tags every request as human, bot or attack, with a plain-words reason.
package analyse

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Human  = "human"
	Bot    = "bot"
	Attack = "attack"
)

// Thresholds per IP per minute.
const (
	LoginPostsPerMin = 10
	RequestsPerMin   = 300
)

// Input is what the classifier looks at.
type Input struct {
	SiteID int64
	TS     time.Time
	IP     netip.Addr
	Method string
	Path   string
	Query  string
	Status int
	UA     string
}

// scanner tools: always an attack.
var attackUAs = []string{"sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "wpscan", "dirbuster", "gobuster", "ffuf", "acunetix", "nessus", "openvas", "jorgee", "zmeu", "l9explore", "fuzz faster", "havij", "w3af", "netsparker", "hydra"}

// known bots and scripts. Order matters only for the name shown.
var botUAs = []struct{ match, name string }{
	{"googlebot", "Google"}, {"bingbot", "Bing"}, {"yandex", "Yandex"}, {"baiduspider", "Baidu"}, {"duckduckbot", "DuckDuckGo"},
	{"applebot", "Apple"}, {"facebookexternalhit", "Facebook"}, {"twitterbot", "X/Twitter"}, {"linkedinbot", "LinkedIn"},
	{"slackbot", "Slack"}, {"telegrambot", "Telegram"}, {"whatsapp", "WhatsApp"}, {"discordbot", "Discord"},
	{"gptbot", "OpenAI GPTBot"}, {"chatgpt-user", "ChatGPT"}, {"oai-searchbot", "OpenAI search"}, {"claudebot", "Anthropic ClaudeBot"},
	{"claude-user", "Claude"}, {"perplexitybot", "Perplexity"}, {"ccbot", "Common Crawl"}, {"bytespider", "ByteDance"},
	{"amazonbot", "Amazon"}, {"ahrefsbot", "Ahrefs"}, {"semrushbot", "Semrush"}, {"mj12bot", "Majestic"}, {"dotbot", "Moz"},
	{"petalbot", "Petal"}, {"dataforseobot", "DataForSEO"}, {"uptimerobot", "UptimeRobot"}, {"pingdom", "Pingdom"},
	{"censysinspect", "Censys"}, {"expanse", "Palo Alto Expanse"}, {"internetmeasurement", "scanner"},
	{"headlesschrome", "headless Chrome"}, {"phantomjs", "PhantomJS"}, {"curl/", "curl"}, {"wget/", "wget"},
	{"python-requests", "Python script"}, {"python-urllib", "Python script"}, {"aiohttp", "Python script"}, {"go-http-client", "Go script"},
	{"java/", "Java script"}, {"okhttp", "OkHttp"}, {"libwww-perl", "Perl script"}, {"scrapy", "Scrapy"}, {"axios/", "Node script"},
	{"node-fetch", "Node script"}, {"httpclient", "HTTP client"}, {"bot", "a bot"}, {"crawler", "a crawler"}, {"spider", "a spider"},
}

// paths that only attackers ask for.
var attackPaths = []struct{ match, why string }{
	{"/.env", "looked for a secret settings file (.env)"},
	{"/.git", "tried to download source code (.git)"},
	{"/.aws", "looked for cloud keys (.aws)"},
	{"/.ssh", "looked for SSH keys"},
	{"/.htpasswd", "looked for a password file"},
	{"/.ds_store", "looked for a file listing (.DS_Store)"},
	{"wp-config", "looked for the WordPress config file"},
	{"/phpmyadmin", "looked for phpMyAdmin"},
	{"/pma/", "looked for phpMyAdmin"},
	{"/vendor/phpunit", "tried a known PHPUnit exploit"},
	{"/cgi-bin/", "probed for old CGI scripts"},
	{"/boaform", "tried a router exploit"},
	{"/hnap1", "tried a router exploit"},
	{"/actuator", "probed a Java admin endpoint"},
	{"/server-status", "looked for server status page"},
	{"/etc/passwd", "tried to read system files"},
	{"/wp-admin/setup-config.php", "tried to re-install WordPress"},
	{"/xmlrpc.php", "poked WordPress xmlrpc (often used for attacks)"},
	{"/shell", "looked for a web shell"},
	{"/eval-stdin.php", "tried a known PHP exploit"},
	{"/.well-known/../", "tried path traversal"},
	{"/owa/auth", "probed for Outlook Web Access"},
	{"/sftp-config.json", "looked for saved FTP passwords"},
	{"/config.json", "looked for a config file"},
	{"/backup.sql", "looked for a database backup"},
	{"/dump.sql", "looked for a database backup"},
}

// payload fragments in path or query.
var attackPayloads = []struct{ match, why string }{
	{"../", "tried path traversal (../)"},
	{"..%2f", "tried path traversal (../)"},
	{"%2e%2e", "tried path traversal (../)"},
	{"union select", "tried SQL injection"},
	{"union%20select", "tried SQL injection"},
	{"' or '1'='1", "tried SQL injection"},
	{"%27%20or%20", "tried SQL injection"},
	{"sleep(", "tried SQL injection"},
	{"<script", "tried script injection (XSS)"},
	{"%3cscript", "tried script injection (XSS)"},
	{"${jndi:", "tried the Log4Shell exploit"},
	{"%24%7bjndi", "tried the Log4Shell exploit"},
	{"base64_decode", "tried PHP code injection"},
	{"/bin/sh", "tried to run shell commands"},
	{"wget%20http", "tried to make the server download malware"},
	{"cmd=", "tried to run commands"},
	{"allow_url_include", "tried PHP code injection"},
}

// login endpoints for brute-force counting (POST only).
var loginPaths = []string{"/wp-login.php", "/xmlrpc.php", "/login", "/user/login", "/admin/login", "/administrator/index.php", "/signin", "/auth/login", "/account/login"}

// Analyzer keeps per-IP counters for rate rules. Safe for concurrent use.
type Analyzer struct {
	mu     sync.Mutex
	minute int64
	hits   map[key]*counter
}

type key struct {
	site int64
	ip   netip.Addr
}

type counter struct{ all, logins int }

func New() *Analyzer { return &Analyzer{hits: map[key]*counter{}} }

// Classify returns tag and reason for one request.
func (a *Analyzer) Classify(in Input) (string, string) {
	ua := strings.ToLower(in.UA)
	p := strings.ToLower(in.Path)
	q := strings.ToLower(in.Query)
	full := p + "?" + q

	// rate counters (per wall-clock minute of the request time)
	c := a.count(in, p)

	for _, s := range attackUAs {
		if strings.Contains(ua, s) {
			return Attack, "used the attack tool " + s
		}
	}
	if in.Method == "-" || in.Method == "" {
		return Attack, "sent a broken request (typical of scanners)"
	}
	for _, ap := range attackPaths {
		if strings.Contains(p, ap.match) {
			if ap.match == "/xmlrpc.php" && in.Method != "POST" {
				continue
			}
			return Attack, ap.why + " (" + clip(in.Path, 60) + ")"
		}
	}
	for _, pl := range attackPayloads {
		if strings.Contains(full, pl.match) {
			return Attack, pl.why
		}
	}
	if c.logins > LoginPostsPerMin {
		return Attack, "tried to guess a password (" + strconv.Itoa(c.logins) + " login tries in a minute)"
	}
	if c.all > RequestsPerMin {
		return Attack, "sent too many requests (" + strconv.Itoa(c.all) + " in a minute)"
	}
	if ua == "" || ua == "-" {
		return Bot, "no browser name (a script)"
	}
	for _, b := range botUAs {
		if strings.Contains(ua, b.match) {
			return Bot, "identified as " + b.name
		}
	}
	return Human, ""
}

func (a *Analyzer) count(in Input, lowerPath string) counter {
	min := in.TS.Unix() / 60
	a.mu.Lock()
	defer a.mu.Unlock()
	if min > a.minute { // new minute: reset (old batches still count into the current one)
		a.minute = min
		a.hits = map[key]*counter{}
	}
	k := key{in.SiteID, in.IP}
	c := a.hits[k]
	if c == nil {
		c = &counter{}
		a.hits[k] = c
	}
	c.all++
	if in.Method == "POST" {
		for _, lp := range loginPaths {
			if lowerPath == lp {
				c.logins++
				break
			}
		}
	}
	return *c
}

// BotName returns a friendly bot name for a UA, or "".
func BotName(ua string) string {
	ua = strings.ToLower(ua)
	for _, b := range botUAs {
		if strings.Contains(ua, b.match) {
			return b.name
		}
	}
	return ""
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
