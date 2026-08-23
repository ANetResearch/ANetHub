#!/usr/bin/env bash
# build.sh — build with the commit stamped in.
#
# The version constant is hand-maintained and answers "which release is
# this". It cannot answer "is the binary running in production the one I
# just built", because every build between two releases carries the same
# string. The commit stamp answers that, and a check comparing what a
# service reports against what was shipped needs it to mean something.
#
#   bash scripts/build.sh                  build for this machine
#   GOOS=linux GOARCH=amd64 bash scripts/build.sh   cross-build
set -euo pipefail
cd "$(dirname "$0")/.."

# The web UI is embedded in this binary, and building the binary did not
# rebuild it. The embedded copy was from 2026-08-18 while five hub
# deployments went out after it, so every change to the page since then
# reached the repository, passed its tests, and never reached production.
#
# It is a step in the deployment rather than a thing to remember, because
# remembering is what failed. SKIP_WEBUI=1 for a Go-only iteration; the
# staleness check below still runs.
build_webui(){
  if [ "${SKIP_WEBUI:-0}" = 1 ]; then
    echo "webui: 跳过重建(SKIP_WEBUI=1)"
  elif command -v docker >/dev/null 2>&1; then
    docker run --rm -v "$PWD/webui:/w" -w /w "${NODE_IMAGE:-node:22-alpine}" \
      sh -c "npm run build" >/dev/null 2>&1 \
      && echo "webui: 重建完成" \
      || { echo "webui: 构建失败" >&2; return 1; }
  elif command -v npm >/dev/null 2>&1; then
    (cd webui && npm run build >/dev/null 2>&1) && echo "webui: 重建完成(本机 npm)" \
      || { echo "webui: 构建失败" >&2; return 1; }
  else
    echo "webui: 无 docker 也无 npm,无法重建" >&2
    return 1
  fi
  cp webui/dist/index.html internal/aghub/web/index.html
}
build_webui || exit 1

# The embedded copy must match what was just built. A mismatch here means
# the copy step failed silently, which is the shape the original problem
# had.
if ! cmp -s webui/dist/index.html internal/aghub/web/index.html; then
  echo "webui: 嵌入的副本与刚构建的不一致" >&2
  exit 1
fi

PKG=github.com/ANetResearch/ANetHub/internal/version
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
# -dirty, because a binary built from uncommitted work is not the commit
# it names and saying so is cheaper than discovering it later.
git diff --quiet 2>/dev/null || COMMIT="$COMMIT-dirty"
BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUT=${OUT:-./anet-hub}

CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X $PKG.Commit=$COMMIT -X $PKG.BuiltAt=$BUILT" \
  -o "$OUT" ./cmd/anet-hub
echo "built $OUT  commit=$COMMIT  at=$BUILT"
