#!/usr/bin/env bash
# deploy-admin.sh — build anet-hub-admin locally (linux/amd64) and roll it onto emax.
# The PUBLIC hub (anet-hub.service, nginx `location /`) is never touched. Idempotent.
#
# Usage: deploy/deploy-admin.sh [host]     (default root@emax.chatchat.space)
#        COMMIT=<sha> deploy/deploy-admin.sh   build outside a git checkout
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${1:-root@emax.chatchat.space}"
BIN=/tmp/anet-hub-admin.build
SITE=/etc/nginx/sites-available/hub.agentnetwork.org.cn
PKG=github.com/ANetResearch/ANetHub/internal/version

# The commit and build time are stamped into the binary.
#
# This script is the release path for the operator plane, and it built with a
# bare `go build`. version.Commit and version.BuiltAt default to "unknown", so
# /admin/healthz — whose entire purpose is to say which build is answering —
# reported "unknown" for every deployment made this way, and an admin plane a
# release behind the hub looked identical to a current one. That happened: the
# recovery endpoints were absent from production for a release while every
# check reported the surface healthy.
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || true)}"
if [ -z "$COMMIT" ]; then
  echo "ERROR: cannot determine the commit; shipping an unstamped binary is the defect this guards." >&2
  echo "       Run inside the git checkout, or pass COMMIT=<sha>." >&2
  exit 1
fi
# -dirty, because a binary built from uncommitted work is not the commit it
# names and saying so is cheaper than discovering it later.
git diff --quiet 2>/dev/null || COMMIT="$COMMIT-dirty"
BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "==> test"
CGO_ENABLED=0 go test ./internal/admin/ >/dev/null

echo "==> build (commit=$COMMIT built_at=$BUILT)"
# CGO_ENABLED=0 and no build tags: the sqlite driver is modernc.org/sqlite
# (pure Go). The sqlite_fts5 tag this script used to pass belongs to the cgo
# driver, which this binary does not import, and CGO_ENABLED=1 with GOOS=linux
# only cross-compiles by accident. scripts/build.sh builds the same binary this
# way.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X $PKG.Commit=$COMMIT -X $PKG.BuiltAt=$BUILT" \
  -o "$BIN" ./cmd/anet-hub-admin

# The artifact has to carry the stamp before it is shipped, not only after.
# Skipped when the binary cannot run on this machine (cross-build); the healthz
# check after the restart is the gate that always applies.
if VER=$("$BIN" --version 2>/dev/null); then
  echo "    $VER"
  case "$VER" in
    *unknown*) echo "ERROR: the built binary reports an unknown build — the -ldflags stamp did not apply." >&2; exit 1 ;;
  esac
else
  echo "    (cross-built for linux/amd64; version check deferred to healthz)"
fi

echo "==> ship binary"
scp -q "$BIN" "$HOST":/data/projs/anet-hub/bin/anet-hub-admin.new
ssh "$HOST" 'mv /data/projs/anet-hub/bin/anet-hub-admin.new /data/projs/anet-hub/bin/anet-hub-admin && chmod 755 /data/projs/anet-hub/bin/anet-hub-admin'

# officials.json is configuration, not code: it names production hosts and the ssh user the ops plane
# connects as, which is why it is not compiled into a binary that gets distributed. Absent file → no
# official agents, which is a correct and safe state. Ship it only if the operator has staged one, and
# never overwrite what is already on the host.
echo "==> official-agent directory"
if [ -f deploy/officials.json ]; then
  scp -q deploy/officials.json "$HOST":/data/projs/anet-hub/admin/officials.json
  echo "    shipped deploy/officials.json"
else
  ssh "$HOST" 'test -f /data/projs/anet-hub/admin/officials.json' \
    && echo "    keeping the copy already on $HOST" \
    || echo "    none here and none on $HOST — the ops plane will list no official agents (see deploy/officials.example.json)"
fi

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
ssh "$HOST" 'systemctl is-active anet-hub anet-hub-admin'
HEALTH=$(ssh "$HOST" 'curl -sf http://127.0.0.1:8078/admin/healthz')
echo "    $HEALTH"
# healthz must name the build that is answering. "unknown" here means either the
# binary was not stamped or the unit is still running the previous one — both are
# the failure this check exists for, and both used to pass silently.
case "$HEALTH" in
  *unknown*) echo "ERROR: /admin/healthz reports an unknown build — the running binary is not the one just built." >&2; exit 1 ;;
esac
case "$HEALTH" in
  *"$COMMIT"*) : ;;
  *) echo "ERROR: /admin/healthz does not report commit $COMMIT; the restart did not pick up the new binary." >&2; exit 1 ;;
esac
curl -sf https://hub.agentnetwork.org.cn/admin/healthz
echo
echo "OK — https://hub.agentnetwork.org.cn/admin  (commit $COMMIT)"
