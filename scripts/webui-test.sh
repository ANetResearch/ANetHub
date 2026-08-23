#!/usr/bin/env bash
# webui-test.sh — run the web UI tests without a local node.
#
# CI has node and runs these on every push. A developer machine may not,
# and "no node here" is a bad reason for the browser half of a project to
# go unverified — which is how the TypeScript AgentView came to be
# missing three fields the hub had been sending for two days, leaving the
# page unable to tell a federated agent from a local one.
#
#   bash scripts/webui-test.sh          run the tests
#   bash scripts/webui-test.sh build    also check the bundle still builds
set -euo pipefail
cd "$(dirname "$0")/../webui"

IMAGE=${IMAGE:-node:22-alpine}
run(){ docker run --rm -v "$PWD:/w" -w /w "$IMAGE" sh -c "$1"; }

run "npx vitest run"
[ "${1:-}" = build ] && run "npm run build"
