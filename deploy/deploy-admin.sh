#!/usr/bin/env bash
# deploy-admin.sh — build anet-hub-admin locally (linux/amd64, CGO+sqlite_fts5) and roll it onto emax.
# The PUBLIC hub (anet-hub.service, nginx `location /`) is never touched. Idempotent.
#
# Usage: deploy/deploy-admin.sh [host]     (default root@emax.chatchat.space)
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${1:-root@emax.chatchat.space}"
BIN=/tmp/anet-hub-admin.build
SITE=/etc/nginx/sites-available/hub.agentnetwork.org.cn

echo "==> test"
CGO_ENABLED=1 go test -tags sqlite_fts5 ./internal/admin/ >/dev/null

echo "==> build"
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags sqlite_fts5 -o "$BIN" ./cmd/anet-hub-admin

echo "==> ship binary"
scp -q "$BIN" "$HOST":/data/projs/anet-hub/bin/anet-hub-admin.new
ssh "$HOST" 'mv /data/projs/anet-hub/bin/anet-hub-admin.new /data/projs/anet-hub/bin/anet-hub-admin && chmod 755 /data/projs/anet-hub/bin/anet-hub-admin'

echo "==> systemd unit"
scp -q deploy/anet-hub-admin.service "$HOST":/etc/systemd/system/anet-hub-admin.service
ssh "$HOST" 'systemctl daemon-reload && systemctl enable anet-hub-admin >/dev/null 2>&1; systemctl restart anet-hub-admin'

echo "==> nginx /admin location (insert once, before location /)"
scp -q deploy/nginx-admin.locations "$HOST":/tmp/nginx-admin.locations
ssh "$HOST" SITE="$SITE" 'bash -s' <<'EOF'
set -euo pipefail
if grep -q "location \^~ /admin" "$SITE"; then
  echo "    already present"
else
  cp "$SITE" "$SITE.bak-admin-$(date +%s)"
  # Insert the /admin block above `location / {` of the 443 server block ONLY — the port-80 block
  # also has a `location / {` (the https redirect), which must stay first-match untouched.
  awk '
    /listen 443/ { tls=1 }
    tls && !done && /^[[:space:]]*location \/ \{/ {
      while ((getline line < "/tmp/nginx-admin.locations") > 0) print line
      close("/tmp/nginx-admin.locations")
      done=1
    }
    { print }
  ' "$SITE" > "$SITE.tmp" && mv "$SITE.tmp" "$SITE"
  grep -A2 "listen 443" "$SITE" >/dev/null # sanity: file still parses as text
fi
if ! grep -q "location \^~ /admin" "$SITE"; then
  echo "ERROR: /admin location not present after edit" >&2; exit 1
fi
nginx -t
systemctl reload nginx
EOF

echo "==> smoke"
sleep 1
ssh "$HOST" 'curl -sf http://127.0.0.1:8078/admin/healthz && systemctl is-active anet-hub anet-hub-admin'
curl -sf https://hub.agentnetwork.org.cn/admin/healthz
echo
echo "OK — https://hub.agentnetwork.org.cn/admin"
