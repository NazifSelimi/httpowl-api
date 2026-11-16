#!/bin/sh
# Monthly refresh of the free DB-IP country database (CC BY 4.0, https://db-ip.com).
set -eu
D=/var/www/httpowl/data
M=$(date -u +%Y-%m)
TMP=$(mktemp)
if curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-$M.mmdb.gz" | gunzip > "$TMP" && [ -s "$TMP" ]; then
  install -o root -g httpowl -m 0644 "$TMP" "$D/dbip-country-lite.mmdb"
  systemctl restart httpowl-api
fi
rm -f "$TMP"
