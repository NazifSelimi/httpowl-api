// Package config reads settings from the environment (loaded from /var/www/httpowl/.env by systemd).
package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL  string // postgres://...
	ListenAddr   string // 127.0.0.1:8090
	PublicURL    string // https://httpowl.net
	CookieSecure bool   // true behind HTTPS
	GeoIPPath    string // dbip-country-lite.mmdb
	DownloadsDir string // agent binaries + install.sh
}

func Load() (Config, error) {
	c := Config{
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		ListenAddr:   env("LISTEN_ADDR", "127.0.0.1:8090"),
		PublicURL:    strings.TrimRight(env("PUBLIC_URL", "http://localhost:8090"), "/"),
		CookieSecure: env("COOKIE_SECURE", "true") == "true",
		GeoIPPath:    os.Getenv("GEOIP_PATH"),
		DownloadsDir: env("DOWNLOADS_DIR", "./dist"),
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL is not set")
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
