#!/usr/bin/env bash
# Build the API on this Mac and ship it to the VPS. Usage: deploy/deploy.sh
# (The agent and its installers are released from the httpowl-agent repo.)
# Keeps the previous API binary as httpowl-api.prev and rolls back if /api/health fails.
set -euo pipefail
cd "$(dirname "$0")/.."
HOST=${HOST:-root@213.130.144.132}
# Target: production (default) or staging, e.g. `deploy/deploy.sh staging`.
TARGET=${1:-production}
case "$TARGET" in
  production) DIR=/var/www/httpowl;         SERVICE=httpowl-api;         PORT=8090; URL=https://httpowl.net ;;
  staging)    DIR=/var/www/httpowl-staging; SERVICE=httpowl-staging-api; PORT=8091; URL=https://staging.httpowl.net ;;
  *) echo "usage: $0 [production|staging]"; exit 1 ;;
esac
VERSION=$(git describe --always --dirty)
OUT=dist
rm -rf "$OUT"; mkdir -p "$OUT/bin"
LD="-s -w -X main.version=$VERSION"
echo "building $VERSION"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "$OUT/bin/httpowl-api" ./cmd/api
cp -R deploy/landing "$OUT/landing"
echo "uploading"
COPYFILE_DISABLE=1 tar --no-xattrs -czf - -C "$OUT" . | ssh "$HOST" "rm -rf $DIR/incoming && mkdir -p $DIR/incoming && tar xzf - -C $DIR/incoming"
ssh "$HOST" bash -s <<REMOTE
set -euo pipefail
cd $DIR
find incoming -name '._*' -delete
[ -f bin/httpowl-api ] && cp -p bin/httpowl-api bin/httpowl-api.prev
install -o root -g httpowl -m 0755 incoming/bin/httpowl-api bin/httpowl-api
if [ ! -f landing/.keep-custom ]; then cp -R incoming/landing/. landing/; fi
chmod -R a+rX landing
rm -rf incoming
systemctl restart $SERVICE
for i in \$(seq 1 20); do curl -fs http://127.0.0.1:$PORT/api/health && echo && exit 0; sleep 1; done
echo "health check failed — rolling back"
journalctl -u $SERVICE -n 30 --no-pager
if [ -f bin/httpowl-api.prev ]; then cp -p bin/httpowl-api.prev bin/httpowl-api; systemctl restart $SERVICE; fi
exit 1
REMOTE
echo "deployed $VERSION to $TARGET ($URL)"
