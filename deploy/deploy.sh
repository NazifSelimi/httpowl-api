#!/usr/bin/env bash
# Build on this Mac and ship to the VPS. Usage: deploy/deploy.sh
# Keeps the previous API binary as httpowl-api.prev and rolls back if /api/health fails.
set -euo pipefail
cd "$(dirname "$0")/.."
HOST=${HOST:-root@213.130.144.132}
DIR=/var/www/httpowl
VERSION=$(git describe --always --dirty)
OUT=dist
rm -rf "$OUT"; mkdir -p "$OUT/bin" "$OUT/dl"
LD="-s -w -X main.version=$VERSION"
echo "building $VERSION"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "$OUT/bin/httpowl-api" ./cmd/api
for t in linux/amd64 linux/arm64 windows/amd64; do
  os=${t%/*}; arch=${t#*/}; ext=""; [ "$os" = windows ] && ext=.exe
  GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "$OUT/dl/httpowl-agent-$os-$arch$ext" ./cmd/agent
done
cp deploy/install.sh deploy/install.ps1 "$OUT/dl/"
(cd "$OUT/dl" && shasum -a 256 httpowl-agent-* > SHA256SUMS)
cp -R deploy/landing "$OUT/landing"
echo "uploading"
COPYFILE_DISABLE=1 tar --no-xattrs -czf - -C "$OUT" . | ssh "$HOST" "rm -rf $DIR/incoming && mkdir -p $DIR/incoming && tar xzf - -C $DIR/incoming"
ssh "$HOST" bash -s <<REMOTE
set -euo pipefail
cd $DIR
find incoming -name '._*' -delete
[ -f bin/httpowl-api ] && cp -p bin/httpowl-api bin/httpowl-api.prev
install -o root -g httpowl -m 0755 incoming/bin/httpowl-api bin/httpowl-api
install -o root -g root -m 0644 incoming/dl/* dl/
if [ ! -f landing/.keep-custom ]; then cp -R incoming/landing/. landing/; fi
chmod -R a+rX dl landing
rm -rf incoming
systemctl restart httpowl-api
for i in \$(seq 1 20); do curl -fs http://127.0.0.1:8090/api/health && echo && exit 0; sleep 1; done
echo "health check failed — rolling back"
journalctl -u httpowl-api -n 30 --no-pager
if [ -f bin/httpowl-api.prev ]; then cp -p bin/httpowl-api.prev bin/httpowl-api; systemctl restart httpowl-api; fi
exit 1
REMOTE
echo "deployed $VERSION"
