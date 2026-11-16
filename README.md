# HTTPowl API + agent

Live HTTP traffic for websites, explained in plain words, with one-click reversible blocks.
Go (chi, pgx + sqlc, goose, slog, coder/websocket) + PostgreSQL. Frontend lives in the separate `httpowl-ui` repo. API reference: [API.md](API.md).

```
cmd/api      web API (serves /api on 127.0.0.1:8090)
cmd/agent    httpowl-agent: reads access logs, ships them, applies blocks
internal/    auth sites ingest analyse rules notes team audit ws geo agent/…
migrations/  goose SQL (embedded, run on API start)
queries/     sqlc queries → internal/store (run `sqlc generate` after editing)
deploy/      deploy.sh, systemd unit, nginx site, install.sh / install.ps1, landing page
```

## Develop (Mac)
```
go test ./...                      # unit tests (parsers, tagging, safety rules, firewall, tail)
sqlc generate                      # after changing migrations/ or queries/
```
No local database: run the API against the VPS test DB through an SSH tunnel
(`ssh -fN -L 15432:127.0.0.1:5432 root@213.130.144.132`, DB `httpowl_test`, password in `/root/.httpowl_test-db-pass` on the VPS).

## Deploy / update
```
git push && deploy/deploy.sh
```
Builds the API + agents (linux amd64/arm64, windows amd64) on the Mac, uploads to `/var/www/httpowl`, restarts `httpowl-api`,
checks `/api/health` and rolls back to `bin/httpowl-api.prev` if it fails. Migrations run automatically on start.

## Server layout (VPS)
- `/var/www/httpowl/{bin,dl,data,landing,app}` · secrets in `/var/www/httpowl/.env` (600, never in git)
- systemd `httpowl-api` (user `httpowl`) · logs: `journalctl -u httpowl-api -f`
- nginx `/etc/nginx/sites-available/httpowl.conf` (certbot TLS) · PostgreSQL 16 DB `httpowl` (localhost only)
- GeoIP: DB-IP country lite (CC BY 4.0), refreshed monthly by `/etc/cron.d/httpowl-geoip`
- Requests are partitioned per day and kept 30 days (hourly job).

## Safety design
- Blocks only drop ports **80/443**; SSH and every other port are never touched.
- The API refuses any rule that covers the person clicking, the server's own IPs, live SSH sessions or team login IPs.
- The agent adds its own allow-list (server IPs, SSH peers, loopback) and drops any block range containing them.
- nftables: one table `inet httpowl`, replaced atomically; `httpowl-agent -cleanup` (or the uninstaller) removes it.
