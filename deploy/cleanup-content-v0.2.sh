#!/usr/bin/env bash
# cleanup-content-v0.2.sh — delete the task content an earlier hub stored (A2A-DESIGN §9)
#
# REQUIRES THE PRODUCT OWNER'S APPROVAL BEFORE IT IS RUN WITH --apply.
# It deletes production data irreversibly (A2A-DESIGN §2, row "对外提交与发布": cleaning production
# data is done only with the product owner's consent). No CI job, deploy script or service runs it.
# Run it once on each hub host (emax, fmax), after the wire-2 hub and admin binaries are installed.
#
# Without --apply it only reports what it would delete: row counts, file names and sizes. It never
# prints row contents.
#
# What it removes, per the §9 production cleanup list:
#   1. relay_message rows holding wire-1 plaintext (delegations, chat bodies, deliverables).
#      On a hub.db that has not been migrated yet (relay_message still has delivered_at) every row
#      is wire-1 plaintext and all are deleted. On a migrated hub.db the wire-1 rows that were still
#      undelivered were copied into the new table; they are the rows created before the upgrade,
#      and --relay-before <unix-ms> names that instant. Without it these rows are only counted
#      (wire-2 daemons ack and so delete them, and the hub deletes them after the 14-day TTL).
#   2. Weekly backups hub-backup-*.db: every one written before the upgrade holds relay payloads and
#      review content. All existing ones are deleted; the next weekly run writes a clean backup.
#   3. Review content: review.goal / review.deliverable and review_blob.request_doc_raw /
#      review_blob.deliverable_raw. The wire-2 hub removes these columns when it first opens
#      hub.db; this step verifies that, and on a hub.db not yet migrated it blanks them in place.
#   4. The task board database data/taskboard.db with its -wal and -shm files (titles and notes
#      of cards; the board is an opt-in module since v0.2 and a default hub does not build it).
#   5. admin/datasets/<every source>: the JSONL events and cards the harvest wrote (relay payloads,
#      official agents' job prompts).
#   6. admin.db: every row of session (goal column included) and of harvest_state.
#   7. Official-agent manifests: the runtime, monitor, ops and datasets sections, in admin.db
#      official_agent and in admin/officials.json. The wire-2 admin refuses a manifest file that
#      still has them.
#   8. data/guest_identity.kel: the private key of the guest broker identity the hub signed with.
#      The broker's registry row stays; without the key nobody can sign as it.
# After deleting, hub.db and admin.db are vacuumed and their WAL checkpointed and truncated, so the
# removed bytes are not left in free pages or in -wal files.
#
# Not reachable from here, and reported instead:
#   - Content that peer hubs already received through GET /fed/v1/reviews cannot be recalled.
#   - Copies outside the two data directories (ad-hoc backups, copies on other machines) are not
#     known to this script. It lists files under the data directories whose names look like
#     backups other than hub-backup-*.db, for the operator to review; it does not delete them.
#
# The hub and admin services must be stopped for --apply (the script refuses otherwise), so that
# no process writes to the databases while rows are deleted and the files are vacuumed.
#
# Usage:
#   deploy/cleanup-content-v0.2.sh [--hub-data DIR] [--admin-data DIR] [--relay-before UNIX_MS] [--apply]
# Defaults: --hub-data /data/projs/anet-hub/data  --admin-data /data/projs/anet-hub/admin
set -euo pipefail

main() {
  local hub_data=/data/projs/anet-hub/data admin_data=/data/projs/anet-hub/admin
  local relay_before="" apply=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --hub-data) hub_data=$2; shift 2 ;;
      --admin-data) admin_data=$2; shift 2 ;;
      --relay-before) relay_before=$2; shift 2 ;;
      --apply) apply=1; shift ;;
      -h|--help) sed -n '2,50p' "$0"; exit 0 ;;
      *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
  done
  if [ -n "$relay_before" ] && ! [[ "$relay_before" =~ ^[0-9]+$ ]]; then
    echo "--relay-before takes unix milliseconds" >&2; exit 2
  fi
  command -v sqlite3 >/dev/null || { echo "sqlite3 is required" >&2; exit 1; }

  local hubdb="$hub_data/hub.db" admindb="$admin_data/admin.db"
  if [ "$apply" = 1 ]; then
    for svc in anet-hub anet-hub-admin; do
      if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "refusing to apply: $svc is running; stop it first (systemctl stop $svc)" >&2
        exit 1
      fi
    done
    echo "mode: APPLY — deleting (approved by the product owner?)"
  else
    echo "mode: dry run — nothing is deleted; pass --apply to delete"
  fi
  echo "hub data:   $hub_data"
  echo "admin data: $admin_data"
  echo

  if [ -f "$hubdb" ]; then
    relay_step "$hubdb" "$relay_before" "$apply"
    review_step "$hubdb" "$apply"
  else
    echo "[1,3] $hubdb not found; relay and review steps skipped"
  fi
  backups_step "$hub_data" "$apply"
  taskboard_step "$hub_data" "$apply"
  datasets_step "$admin_data" "$apply"
  if [ -f "$admindb" ]; then
    admin_rows_step "$admindb" "$apply"
    manifests_step "$admindb" "$admin_data/officials.json" "$apply"
  else
    echo "[6,7] $admindb not found; admin.db steps skipped"
  fi
  guest_key_step "$hub_data" "$apply"
  other_copies_report "$hub_data" "$admin_data"

  if [ "$apply" = 1 ]; then
    for db in "$hubdb" "$admindb"; do
      [ -f "$db" ] || continue
      sqlite3 "$db" ".timeout 15000" "PRAGMA secure_delete=ON;" "VACUUM;" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
      echo "vacuumed and checkpointed $db"
    done
  fi
  echo
  echo "Not recoverable by any step here: review content already served to peer hubs via /fed/v1/reviews."
}

# q runs one statement against a database and prints the result.
q() { sqlite3 "$1" ".timeout 15000" "$2"; }

has_column() { [ "$(q "$1" "SELECT COUNT(*) FROM pragma_table_info('$2') WHERE name='$3';")" != 0 ]; }
has_table() { [ "$(q "$1" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$2';")" != 0 ]; }

relay_step() {
  local db=$1 before=$2 apply=$3
  if ! has_table "$db" relay_message; then echo "[1] relay_message: no table"; return; fi
  if has_column "$db" relay_message delivered_at; then
    local n; n=$(q "$db" "SELECT COUNT(*) FROM relay_message;")
    echo "[1] relay_message: not migrated; all $n rows are wire-1 plaintext"
    [ "$apply" = 1 ] && q "$db" "PRAGMA secure_delete=ON; DELETE FROM relay_message;" >/dev/null && echo "    deleted $n rows"
    return 0
  fi
  if [ -z "$before" ]; then
    local total; total=$(q "$db" "SELECT COUNT(*) FROM relay_message;")
    echo "[1] relay_message: migrated; $total queued envelopes. Pass --relay-before <unix-ms of the upgrade>"
    echo "    to delete the wire-1 rows copied by the migration; without it none are deleted"
    return 0
  fi
  local n; n=$(q "$db" "SELECT COUNT(*) FROM relay_message WHERE created_at < $before;")
  echo "[1] relay_message: $n rows created before $before (wire-1 plaintext copied by the migration)"
  [ "$apply" = 1 ] && q "$db" "PRAGMA secure_delete=ON; DELETE FROM relay_message WHERE created_at < $before;" >/dev/null \
    && echo "    deleted $n rows"
  return 0
}

review_step() {
  local db=$1 apply=$2
  local stale=0
  if has_table "$db" review && has_column "$db" review goal; then
    stale=1
    echo "[3] review: goal/deliverable columns present (hub.db not yet migrated): $(q "$db" \
      "SELECT COUNT(*) FROM review WHERE goal != '' OR deliverable != '';") rows with content"
    [ "$apply" = 1 ] && q "$db" "PRAGMA secure_delete=ON; UPDATE review SET goal='', deliverable='';" >/dev/null \
      && echo "    blanked"
  fi
  if has_table "$db" review_blob && has_column "$db" review_blob request_doc_raw; then
    stale=1
    echo "[3] review_blob: request_doc_raw/deliverable_raw present: $(q "$db" "SELECT COUNT(*) FROM review_blob;") rows"
    [ "$apply" = 1 ] && q "$db" "PRAGMA secure_delete=ON; UPDATE review_blob SET request_doc_raw=x'', deliverable_raw=x'';" >/dev/null \
      && echo "    blanked"
  fi
  [ "$stale" = 0 ] && echo "[3] review, review_blob: no content columns (migrated by the wire-2 hub)"
  return 0
}

backups_step() {
  local dir=$1 apply=$2 f found=0
  for f in "$dir"/hub-backup-*.db; do
    [ -e "$f" ] || continue
    found=1
    echo "[2] backup $f ($(stat -c %s "$f") bytes)"
    [ "$apply" = 1 ] && rm -f -- "$f" "$f-wal" "$f-shm" "$f-journal" && echo "    deleted"
  done
  [ "$found" = 0 ] && echo "[2] no hub-backup-*.db"
  return 0
}

taskboard_step() {
  local dir=$1 apply=$2 f found=0
  for f in "$dir/taskboard.db" "$dir/taskboard.db-wal" "$dir/taskboard.db-shm"; do
    [ -e "$f" ] || continue
    found=1
    echo "[4] $f ($(stat -c %s "$f") bytes)"
    [ "$apply" = 1 ] && rm -f -- "$f" && echo "    deleted"
  done
  [ "$found" = 0 ] && echo "[4] no taskboard.db"
  return 0
}

datasets_step() {
  local dir=$1/datasets apply=$2
  if [ ! -d "$dir" ]; then echo "[5] no $dir"; return 0; fi
  local src
  for src in "$dir"/*; do
    [ -e "$src" ] || continue
    echo "[5] $src: $(find "$src" -type f | wc -l) files, $(du -sb "$src" | cut -f1) bytes"
  done
  if [ "$apply" = 1 ]; then
    find "$dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    echo "    deleted everything under $dir"
  fi
  return 0
}

admin_rows_step() {
  local db=$1 apply=$2 t
  for t in session harvest_state; do
    if has_table "$db" "$t"; then
      echo "[6] admin.db $t: $(q "$db" "SELECT COUNT(*) FROM $t;") rows"
      [ "$apply" = 1 ] && q "$db" "PRAGMA secure_delete=ON; DELETE FROM $t;" >/dev/null && echo "    deleted"
    fi
  done
  return 0
}

manifests_step() {
  local db=$1 file=$2 apply=$3
  local strip="json_remove(manifest,'\$.runtime','\$.monitor','\$.ops','\$.datasets')"
  local carries="(json_type(manifest,'\$.runtime') IS NOT NULL OR json_type(manifest,'\$.monitor') IS NOT NULL OR
                  json_type(manifest,'\$.ops') IS NOT NULL OR json_type(manifest,'\$.datasets') IS NOT NULL)"
  if has_table "$db" official_agent; then
    echo "[7] admin.db official_agent: $(q "$db" "SELECT COUNT(*) FROM official_agent WHERE $carries;") manifests carry runtime/monitor/ops/datasets"
    [ "$apply" = 1 ] && q "$db" "UPDATE official_agent SET manifest=$strip WHERE $carries;" >/dev/null && echo "    stripped"
  fi
  if [ -f "$file" ]; then
    local n
    n=$(sqlite3 :memory: "SELECT COUNT(*) FROM json_each(readfile('$file')) WHERE
          json_type(value,'\$.runtime') IS NOT NULL OR json_type(value,'\$.monitor') IS NOT NULL OR
          json_type(value,'\$.ops') IS NOT NULL OR json_type(value,'\$.datasets') IS NOT NULL;")
    echo "[7] $file: $n manifests carry runtime/monitor/ops/datasets"
    if [ "$apply" = 1 ] && [ "$n" != 0 ]; then
      cp -p -- "$file" "$file.pre-v0.2"
      sqlite3 :memory: "SELECT json_group_array(json(json_remove(value,'\$.runtime','\$.monitor','\$.ops','\$.datasets')))
                        FROM json_each(readfile('$file'));" > "$file.tmp"
      mv -- "$file.tmp" "$file"
      rm -f -- "$file.pre-v0.2"
      echo "    stripped"
    fi
  fi
  return 0
}

guest_key_step() {
  local f=$1/guest_identity.kel apply=$2
  if [ -e "$f" ]; then
    echo "[8] $f (private key of the guest broker identity)"
    [ "$apply" = 1 ] && rm -f -- "$f" && echo "    deleted"
  else
    echo "[8] no guest_identity.kel"
  fi
  return 0
}

other_copies_report() {
  local hub=$1 admin=$2
  local list
  list=$(find "$hub" "$admin" -maxdepth 2 -type f \( -name '*.bak' -o -name '*backup*' -o -name '*.orig' -o -name '*.old' \) \
    ! -name 'hub-backup-*.db' 2>/dev/null || true)
  if [ -n "$list" ]; then
    echo "[report] other files that look like copies (review by hand; not deleted):"
    echo "$list" | sed 's/^/    /'
  fi
}

main "$@"
