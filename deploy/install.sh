#!/bin/sh
# HTTPowl agent installer.
#   curl -sL https://httpowl.net/install | sudo sh -s -- --token owl_xxx
# Options: --token T  --server URL  --log PATH (repeatable)  --no-firewall  --uninstall
set -eu

SERVER="https://httpowl.net"
TOKEN=""
LOGS=""
FIREWALL="auto"
UNINSTALL=0
BIN=/usr/local/bin/httpowl-agent
CONF_DIR=/etc/httpowl
UNIT=/etc/systemd/system/httpowl-agent.service

say() { printf '\033[1;35mhttpowl:\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mhttpowl:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --server) SERVER="${2%/}"; shift 2 ;;
    --log) LOGS="$LOGS \"$2\""; shift 2 ;;
    --no-firewall) FIREWALL="off"; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "please run as root (curl ... | sudo sh -s -- --token ...)"
[ "$(uname -s)" = Linux ] || die "this installer is for Linux. On Windows use install.ps1 from $SERVER/install.ps1"
command -v systemctl >/dev/null || die "systemd is required"

if [ "$UNINSTALL" = 1 ]; then
  say "removing the agent and every block it added"
  systemctl disable --now httpowl-agent 2>/dev/null || true
  [ -x "$BIN" ] && "$BIN" -cleanup || true
  rm -f "$UNIT" "$BIN"; rm -rf "$CONF_DIR" /var/lib/httpowl-agent
  systemctl daemon-reload
  say "done — HTTPowl agent removed"
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported CPU: $(uname -m)" ;;
esac

if [ -z "$TOKEN" ] && [ -f "$CONF_DIR/agent.json" ]; then
  say "no --token given, keeping the existing config"
elif ! printf '%s' "$TOKEN" | grep -Eq '^owl_[A-Za-z0-9_-]{43}$'; then
  die "missing or wrong --token (copy the command from your site page on HTTPowl)"
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
say "downloading agent ($ARCH)"
curl -fsSL "$SERVER/dl/httpowl-agent-linux-$ARCH" -o "$TMP/httpowl-agent"
curl -fsSL "$SERVER/dl/SHA256SUMS" -o "$TMP/SHA256SUMS"
( cd "$TMP" && grep " httpowl-agent-linux-$ARCH\$" SHA256SUMS | sed "s/httpowl-agent-linux-$ARCH/httpowl-agent/" | sha256sum -c - >/dev/null ) || die "checksum mismatch — download was corrupted, try again"
install -m 0755 "$TMP/httpowl-agent" "$BIN"

if [ -n "$TOKEN" ]; then
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  LOGJSON='"auto"'
  if [ -n "$LOGS" ]; then LOGJSON=$(echo $LOGS | sed 's/" "/", "/g'); fi
  umask 077
  cat > "$CONF_DIR/agent.json" <<JSON
{
  "server": "$SERVER",
  "token": "$TOKEN",
  "logs": [$LOGJSON],
  "firewall": "$FIREWALL",
  "state_dir": "/var/lib/httpowl-agent"
}
JSON
fi

cat > "$UNIT" <<'UNITEOF'
[Unit]
Description=HTTPowl agent (reads access logs, applies HTTPowl blocks on ports 80/443)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/httpowl-agent -config /etc/httpowl/agent.json
Restart=always
RestartSec=5
StateDirectory=httpowl-agent
# Only what it needs: read logs, manage its own firewall table.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/httpowl-agent -/run/xtables.lock
ProtectKernelModules=yes
ProtectControlGroups=yes
MemoryMax=200M
CPUQuota=30%

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable httpowl-agent >/dev/null 2>&1
systemctl restart httpowl-agent
say "detected:"
"$BIN" -config "$CONF_DIR/agent.json" -detect || true
sleep 2
if systemctl is-active --quiet httpowl-agent; then
  say "running ✔  logs: journalctl -u httpowl-agent -f"
  say "remove any time: curl -sL $SERVER/install | sudo sh -s -- --uninstall"
else
  journalctl -u httpowl-agent -n 20 --no-pager
  die "the agent did not start (see above)"
fi
