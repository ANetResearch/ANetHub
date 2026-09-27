#!/usr/bin/env bash
# cleanup-content-v0.2.sh — delete the task content an earlier hub stored (A2A-DESIGN §9)
#
# REQUIRES THE PRODUCT OWNER'S APPROVAL BEFORE IT IS RUN WITH --apply.
# It deletes production data irreversibly (A2A-DESIGN §2, row "对外提交与发布": cleaning production
# data is done only with the product owner's consent). No CI job, deploy script or service runs it.
# Run it once on each hub host (emax, fmax), after the wire-2 hub and admin binaries are installed.
#
# Without --apply it only reports what it would delete: row counts, file names and sizes. It never
# prints row contents or credential values. With --apply it first prints the same report, then asks
# for confirmation on the terminal (or takes --yes), then deletes.
#
# What it removes, per the §9 production cleanup list:
#   1. relay_message rows holding wire-1 plaintext (delegations, chat bodies, deliverables).
#      On a hub.db that has not been migrated yet (relay_message still has delivered_at) every row
#      is wire-1 plaintext and all are deleted. The wire-2 hub drops every wire-1 row when it
#      migrates the table and records what it dropped in hub_meta; the report shows that record,
#      and there is nothing left to delete. A hub.db migrated by an earlier wire-2 build, which
#      copied the undelivered wire-1 rows, has no such record: there --relay-before <unix-ms of the
#      upgrade> deletes the rows created before the upgrade; without it they are only counted.
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
#   9. The credentials of the removed official-agent ops plane (§9 row "admin 官方 agent", §15,
#      [C39]). The old admin ran as root, reached official-agent hosts over ssh with the account's
#      default key (runtime.ssh_user, root by default, no -i), and logged into their consoles with
#      ADMIN_MONITOR_TOKEN, which defaulted to ADMIN_TOKEN. Deleting that code deleted neither.
#      Reported: the hosts and ssh users the manifests named (read before step 7 strips them), the
#      private keys in --ssh-dir with their fingerprints, and every ADMIN_MONITOR_TOKEN assignment
#      in the admin unit, its drop-ins and their EnvironmentFiles (the value is never printed).
#      With --apply: those assignments are removed where one stands alone on its line (others are
#      reported for editing by hand), and the private keys named with --ops-ssh-key are deleted
#      with their .pub. A default key is never deleted unless named: the script cannot tell whether
#      the account uses it for anything else. What has to happen on other hosts, or needs a new
#      secret, is printed as a checklist and not done here (docs/ADMIN.md §5).
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
#   deploy/cleanup-content-v0.2.sh [--hub-data DIR] [--admin-data DIR] [--relay-before UNIX_MS]
#       [--ssh-dir DIR] [--systemd-dir DIR] [--ops-ssh-key FILE]... [--apply [--yes]]
# Defaults: --hub-data /data/projs/anet-hub/data  --admin-data /data/projs/anet-hub/admin
#           --ssh-dir /root/.ssh  --systemd-dir /etc/systemd/system
# Needs the sqlite3 CLI (3.38 or later, for the JSON functions and readfile()). Tested by
# deploy/scripts_test.go against fixture directories (skipped where sqlite3 is not installed).
set -euo pipefail

main() {
  local hub_data=/data/projs/anet-hub/data admin_data=/data/projs/anet-hub/admin
  local ssh_dir=/root/.ssh systemd_dir=/etc/systemd/system
  local relay_before="" apply=0 yes=0
  OPS_KEYS=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --hub-data) hub_data=${2:?}; shift 2 ;;
      --admin-data) admin_data=${2:?}; shift 2 ;;
      --relay-before) relay_before=${2:?}; shift 2 ;;
      --ssh-dir) ssh_dir=${2:?}; shift 2 ;;
      --systemd-dir) systemd_dir=${2:?}; shift 2 ;;
      --ops-ssh-key) OPS_KEYS+=("${2:?}"); shift 2 ;;
      --apply) apply=1; shift ;;
      --yes) yes=1; shift ;;
      -h|--help) awk 'NR > 1 && /^set -euo pipefail/ { exit } NR > 1' "$0"; exit 0 ;;
      *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
  done
  if [ -n "$relay_before" ] && ! [[ "$relay_before" =~ ^[0-9]+$ ]]; then
    echo "--relay-before takes unix milliseconds" >&2; exit 2
  fi
  if [ "$yes" = 1 ] && [ "$apply" = 0 ]; then
    echo "--yes only confirms --apply" >&2; exit 2
  fi
  command -v sqlite3 >/dev/null || die "sqlite3 is required"

  if [ "$apply" = 1 ]; then
    local svc
    for svc in anet-hub anet-hub-admin; do
      # A host without systemctl, or without the unit, answers non-zero: not running.
      if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "refusing to apply: $svc is running; stop it first (systemctl stop $svc)" >&2
        exit 1
      fi
    done
  fi

  if [ "$apply" = 1 ]; then
    echo "mode: APPLY — the report comes first; deletion follows after confirmation"
  else
    echo "mode: dry run — nothing is deleted; pass --apply to delete"
  fi
  echo "hub data:    $hub_data"
  echo "admin data:  $admin_data"
  echo "ssh dir:     $ssh_dir"
  echo "systemd dir: $systemd_dir"
  echo
  run_steps 0 "$hub_data" "$admin_data" "$relay_before" "$ssh_dir" "$systemd_dir"
  if [ "$apply" = 0 ]; then
    echo
    echo "dry run: nothing was deleted. Pass --apply (with the product owner's approval) to delete."
    return 0
  fi

  echo
  confirm_apply "$yes"
  echo "mode: APPLY — deleting"
  echo
  run_steps 1 "$hub_data" "$admin_data" "$relay_before" "$ssh_dir" "$systemd_dir"
  local db
  for db in "$hub_data/hub.db" "$admin_data/admin.db"; do
    [ -f "$db" ] || continue
    sqlite3 "$db" ".timeout 15000" "PRAGMA secure_delete=ON;" "VACUUM;" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null \
      || die "vacuum of $db failed"
    echo "vacuumed and checkpointed $db"
  done
}

# run_steps prints (apply=0) or performs (apply=1) every step once.
run_steps() {
  local apply=$1 hub_data=$2 admin_data=$3 relay_before=$4 ssh_dir=$5 systemd_dir=$6
  local hubdb="$hub_data/hub.db" admindb="$admin_data/admin.db"
  if [ -f "$hubdb" ]; then
    relay_step "$hubdb" "$relay_before" "$apply"
    review_step "$hubdb" "$apply"
  else
    echo "[1,3] $hubdb not found; relay and review steps skipped"
  fi
  backups_step "$hub_data" "$apply"
  taskboard_step "$hub_data" "$apply"
  datasets_step "$admin_data" "$apply"
  # Before step 7: it strips the runtime and monitor sections this reads.
  ops_inventory "$admindb" "$admin_data/officials.json"
  if [ -f "$admindb" ]; then
    admin_rows_step "$admindb" "$apply"
    manifests_step "$admindb" "$admin_data/officials.json" "$apply"
  else
    echo "[6,7] $admindb not found; admin.db steps skipped"
  fi
  guest_key_step "$hub_data" "$apply"
  ops_credentials_step "$ssh_dir" "$systemd_dir" "$apply"
  other_copies_report "$hub_data" "$admin_data"
  echo
  echo "Not recoverable by any step here: review content already served to peer hubs via /fed/v1/reviews."
}

# confirm_apply asks on the terminal, not on stdin, so a pipe cannot answer for the operator.
confirm_apply() {
  [ "$1" = 1 ] && { echo "confirmed by --yes"; return 0; }
  if ! { exec 3<>/dev/tty; } 2>/dev/null; then
    echo "refusing to apply: no terminal to confirm on. Pass --yes once the product owner has approved." >&2
    exit 2
  fi
  local ans=""
  printf '%s' "Delete everything listed above? It cannot be undone. Approved by the product owner? Type yes: " >&3
  read -r ans <&3 || true
  exec 3>&-
  [ "$ans" = yes ] || { echo "not confirmed; nothing was deleted" >&2; exit 1; }
}

die() { echo "cleanup: $*" >&2; exit 1; }

# A failing sqlite3 ends the script, wherever it is called from. Under set -e it would not: a
# failure inside `[ … ] && cmd`, inside a function called from `if`, or inside a $(…) that is an
# argument does not stop a bash script, and the first version of this file used all three — a
# deletion that failed was skipped silently, and a count that failed read as "table present".
# So a statement runs through q in the current shell (never inside $(…)), and a query result comes
# back in the global R through get.
q() { sqlite3 "$1" ".timeout 15000" "$2" >/dev/null || die "sqlite3 failed on $1: $2"; }
get() { R=$(sqlite3 "$1" ".timeout 15000" "$2") || die "sqlite3 failed on $1: $2"; }
# count is get for a number: empty reads as 0.
count() { get "$1" "$2"; R=${R:-0}; }

# sqlstr quotes a value as an SQL string literal.
sqlstr() { printf "'%s'" "${1//\'/\'\'}"; }

has_column() { count "$1" "SELECT COUNT(*) FROM pragma_table_info('$2') WHERE name='$3';"; [ "$R" != 0 ]; }
has_table() { count "$1" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$2';"; [ "$R" != 0 ]; }

# meta reads a hub_meta value the wire-2 hub wrote (keys Meta* in internal/aghub/relay.go) into R.
meta() { R=""; has_table "$1" hub_meta || { R=""; return 0; }; get "$1" "SELECT value FROM hub_meta WHERE key='$2';"; }

relay_step() {
  local db=$1 before=$2 apply=$3
  if ! has_table "$db" relay_message; then echo "[1] relay_message: no table"; return 0; fi
  if has_column "$db" relay_message delivered_at; then
    count "$db" "SELECT COUNT(*) FROM relay_message;"; local n=$R
    echo "[1] relay_message: not migrated; all $n rows are wire-1 plaintext"
    if [ "$apply" = 1 ]; then
      q "$db" "PRAGMA secure_delete=ON; DELETE FROM relay_message;"
      echo "    deleted $n rows"
    fi
    return 0
  fi
  count "$db" "SELECT COUNT(*) FROM relay_message;"; local total=$R
  meta "$db" relay_v2_migrated_at; local at=$R
  if [ -n "$at" ]; then
    meta "$db" relay_v2_dropped_undelivered; local undelivered=$R
    meta "$db" relay_v2_dropped_delivered; local delivered=$R
    echo "[1] relay_message: migrated to wire 2 at $(date -u -d "@$((at / 1000))" +%FT%TZ) ($at); the migration"
    echo "    dropped $undelivered undelivered and $delivered delivered wire-1 rows. The $total queued rows are"
    echo "    sealed wire-2 envelopes; nothing to delete"
    if [ -n "$before" ]; then echo "    --relay-before ignored: no wire-1 row remains after this migration"; fi
    return 0
  fi
  if [ -z "$before" ]; then
    echo "[1] relay_message: migrated by an earlier wire-2 build that copied undelivered wire-1 rows;"
    echo "    $total queued rows. Pass --relay-before <unix-ms of the upgrade> to delete those created"
    echo "    before it; without it none are deleted"
    return 0
  fi
  count "$db" "SELECT COUNT(*) FROM relay_message WHERE created_at < $before;"; local n=$R
  echo "[1] relay_message: $n rows created before $before (wire-1 plaintext copied by an earlier migration)"
  if [ "$apply" = 1 ]; then
    q "$db" "PRAGMA secure_delete=ON; DELETE FROM relay_message WHERE created_at < $before;"
    echo "    deleted $n rows"
  fi
  return 0
}

review_step() {
  local db=$1 apply=$2
  local stale=0
  if has_table "$db" review && has_column "$db" review goal; then
    stale=1
    count "$db" "SELECT COUNT(*) FROM review WHERE goal != '' OR deliverable != '';"
    echo "[3] review: goal/deliverable columns present (hub.db not yet migrated): $R rows with content"
    if [ "$apply" = 1 ]; then
      q "$db" "PRAGMA secure_delete=ON; UPDATE review SET goal='', deliverable='';"
      echo "    blanked"
    fi
  fi
  if has_table "$db" review_blob && has_column "$db" review_blob request_doc_raw; then
    stale=1
    count "$db" "SELECT COUNT(*) FROM review_blob;"
    echo "[3] review_blob: request_doc_raw/deliverable_raw present: $R rows"
    if [ "$apply" = 1 ]; then
      q "$db" "PRAGMA secure_delete=ON; UPDATE review_blob SET request_doc_raw=x'', deliverable_raw=x'';"
      echo "    blanked"
    fi
  fi
  if [ "$stale" = 0 ]; then echo "[3] review, review_blob: no content columns (migrated by the wire-2 hub)"; fi
  return 0
}

backups_step() {
  local dir=$1 apply=$2 f found=0
  for f in "$dir"/hub-backup-*.db; do
    [ -e "$f" ] || continue
    found=1
    echo "[2] backup $f ($(stat -c %s "$f") bytes)"
    if [ "$apply" = 1 ]; then
      rm -f -- "$f" "$f-wal" "$f-shm" "$f-journal"
      echo "    deleted"
    fi
  done
  if [ "$found" = 0 ]; then echo "[2] no hub-backup-*.db"; fi
  return 0
}

taskboard_step() {
  local dir=$1 apply=$2 f found=0
  for f in "$dir/taskboard.db" "$dir/taskboard.db-wal" "$dir/taskboard.db-shm"; do
    [ -e "$f" ] || continue
    found=1
    echo "[4] $f ($(stat -c %s "$f") bytes)"
    if [ "$apply" = 1 ]; then
      rm -f -- "$f"
      echo "    deleted"
    fi
  done
  if [ "$found" = 0 ]; then echo "[4] no taskboard.db"; fi
  return 0
}

datasets_step() {
  local dir=$1/datasets apply=$2
  if [ ! -d "$dir" ]; then echo "[5] no $dir"; return 0; fi
  local src files bytes
  for src in "$dir"/*; do
    [ -e "$src" ] || continue
    files=$(find "$src" -type f | wc -l)
    bytes=$(du -sb "$src" | cut -f1)
    echo "[5] $src: $files files, $bytes bytes"
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
      count "$db" "SELECT COUNT(*) FROM $t;"
      echo "[6] admin.db $t: $R rows"
      if [ "$apply" = 1 ]; then
        q "$db" "PRAGMA secure_delete=ON; DELETE FROM $t;"
        echo "    deleted"
      fi
    fi
  done
  return 0
}

# json_file reads a JSON file as TEXT. readfile() returns a BLOB, and SQLite 3.45 and later try a
# BLOB argument of the JSON functions as JSONB first; the cast keeps it plain JSON text.
json_file() { echo "CAST(readfile($(sqlstr "$1")) AS TEXT)"; }

manifests_step() {
  local db=$1 file=$2 apply=$3
  local strip="json_remove(manifest,'\$.runtime','\$.monitor','\$.ops','\$.datasets')"
  local carries="(json_type(manifest,'\$.runtime') IS NOT NULL OR json_type(manifest,'\$.monitor') IS NOT NULL OR
                  json_type(manifest,'\$.ops') IS NOT NULL OR json_type(manifest,'\$.datasets') IS NOT NULL)"
  if has_table "$db" official_agent; then
    count "$db" "SELECT COUNT(*) FROM official_agent WHERE json_valid(manifest) AND $carries;"
    echo "[7] admin.db official_agent: $R manifests carry runtime/monitor/ops/datasets"
    if [ "$apply" = 1 ]; then
      q "$db" "UPDATE official_agent SET manifest=$strip WHERE json_valid(manifest) AND $carries;"
      echo "    stripped"
    fi
  fi
  if [ -f "$file" ]; then
    local src; src=$(json_file "$file")
    count :memory: "SELECT COUNT(*) FROM json_each($src) WHERE
          json_type(value,'\$.runtime') IS NOT NULL OR json_type(value,'\$.monitor') IS NOT NULL OR
          json_type(value,'\$.ops') IS NOT NULL OR json_type(value,'\$.datasets') IS NOT NULL;"
    local n=$R
    echo "[7] $file: $n manifests carry runtime/monitor/ops/datasets"
    if [ "$apply" = 1 ] && [ "$n" != 0 ]; then
      get :memory: "SELECT json_group_array(json(json_remove(value,'\$.runtime','\$.monitor','\$.ops','\$.datasets')))
                    FROM json_each($src);"
      [ -n "$R" ] || die "rewriting $file produced nothing; left unchanged"
      printf '%s\n' "$R" > "$file.tmp"
      chmod --reference="$file" -- "$file.tmp"
      chown --reference="$file" -- "$file.tmp" 2>/dev/null || true
      mv -- "$file.tmp" "$file"
      echo "    stripped"
    fi
  fi
  return 0
}

guest_key_step() {
  local f=$1/guest_identity.kel apply=$2
  if [ -e "$f" ]; then
    echo "[8] $f (private key of the guest broker identity)"
    if [ "$apply" = 1 ]; then
      rm -f -- "$f"
      echo "    deleted"
    fi
  else
    echo "[8] no guest_identity.kel"
  fi
  return 0
}

# ops_inventory records which hosts the old ops plane reached over ssh (user@host) and how many
# manifests had a monitor section, from admin.db and officials.json. Step 7 strips both.
OPS_HOSTS="" OPS_MONITORS=0
ops_inventory() {
  local db=$1 file=$2 hosts=""
  # user@host of a manifest m, the user defaulting to root as the old ops plane did.
  who() { echo "COALESCE(NULLIF(json_extract($1,'\$.runtime.ssh_user'),''),'root') || '@' || json_extract($1,'\$.runtime.host')"; }
  OPS_MONITORS=0
  if [ -f "$db" ] && has_table "$db" official_agent; then
    get "$db" "SELECT $(who manifest) FROM official_agent
               WHERE json_valid(manifest) AND json_extract(manifest,'\$.runtime.host') IS NOT NULL;"
    hosts+="$R"$'\n'
    count "$db" "SELECT COUNT(*) FROM official_agent WHERE json_valid(manifest) AND json_type(manifest,'\$.monitor') IS NOT NULL;"
    OPS_MONITORS=$((OPS_MONITORS + R))
  fi
  if [ -f "$file" ]; then
    local src; src=$(json_file "$file")
    get :memory: "SELECT $(who value) FROM json_each($src) WHERE json_extract(value,'\$.runtime.host') IS NOT NULL;"
    hosts+="$R"$'\n'
    count :memory: "SELECT COUNT(*) FROM json_each($src) WHERE json_type(value,'\$.monitor') IS NOT NULL;"
    OPS_MONITORS=$((OPS_MONITORS + R))
  fi
  OPS_HOSTS=$(printf '%s' "$hosts" | sed '/^$/d' | sort -u)
}

# monitor_token_files lists the files that configure the admin service: the unit, its drop-ins, and
# the EnvironmentFiles they name.
monitor_token_files() {
  local dir=$1 f
  local unit="$dir/anet-hub-admin.service"
  local units=()
  [ -f "$unit" ] && units+=("$unit")
  for f in "$unit.d"/*.conf; do [ -f "$f" ] && units+=("$f"); done
  [ ${#units[@]} -eq 0 ] && return 0
  printf '%s\n' "${units[@]}"
  # EnvironmentFile=-/path (leading - = optional); several may be given on one line.
  sed -nE 's/^[[:space:]]*EnvironmentFile[[:space:]]*=[[:space:]]*//p' "${units[@]}" \
    | tr ' ' '\n' | sed -E 's/^-//; /^$/d' | while read -r f; do if [ -f "$f" ]; then echo "$f"; fi; done
  return 0
}

ops_credentials_step() {
  local ssh_dir=$1 systemd_dir=$2 apply=$3 f
  echo "[9] credentials of the removed official-agent ops plane (ssh keys, monitor token)"
  if [ -n "$OPS_HOSTS" ]; then
    echo "    the old admin reached these official-agent hosts over ssh:"
    printf '%s\n' "$OPS_HOSTS" | sed 's/^/      /'
  else
    echo "    no official-agent manifest names an ssh host"
  fi

  # Private keys of the account the admin ran as (root by default: the unit had no User=).
  if [ ! -d "$ssh_dir" ]; then
    echo "    $ssh_dir: not present"
  elif [ ! -r "$ssh_dir" ] || [ ! -x "$ssh_dir" ]; then
    echo "    $ssh_dir: not readable by $(id -un); run as root to list its keys"
  else
    local found=0
    for f in "$ssh_dir"/id_*; do
      [ -f "$f" ] || continue
      case "$f" in *.pub) continue ;; esac
      found=1
      echo "    private key $f ($(fingerprint "$f"))"
    done
    if [ "$found" = 0 ]; then echo "    no private key named id_* in $ssh_dir"; fi
  fi
  local k
  for k in "${OPS_KEYS[@]}"; do
    if [ ! -e "$k" ]; then
      echo "    --ops-ssh-key $k: not found"
      continue
    fi
    echo "    --ops-ssh-key $k ($(fingerprint "$k")): the ops key, to be deleted"
    if [ "$apply" = 1 ]; then
      rm -f -- "$k" "$k.pub"
      echo "    deleted $k and $k.pub"
    fi
  done
  if [ ${#OPS_KEYS[@]} -eq 0 ]; then
    echo "    no --ops-ssh-key given: no key is deleted (a default key may serve other purposes)"
  fi

  # ADMIN_MONITOR_TOKEN. A line that only assigns it is removed; any other line naming it is left
  # for the operator. The value is never printed.
  local re='^[[:space:]]*(Environment[[:space:]]*=[[:space:]]*)?"?(export[[:space:]]+)?ADMIN_MONITOR_TOKEN=("[^"]*"|[^[:space:]"]*)"?[[:space:]]*$'
  local files n left seen=0 edited=0
  files=$(monitor_token_files "$systemd_dir")
  while read -r f; do
    [ -n "$f" ] || continue
    n=$(grep -c 'ADMIN_MONITOR_TOKEN' -- "$f" || true)
    [ "$n" != 0 ] || continue
    seen=1
    echo "    $f: $n line(s) name ADMIN_MONITOR_TOKEN (value not shown)"
    if [ "$apply" = 1 ]; then
      sed -i -E "/$re/d" -- "$f"
      edited=1
      left=$(grep -c 'ADMIN_MONITOR_TOKEN' -- "$f" || true)
      if [ "$left" = 0 ]; then
        echo "    removed"
      else
        echo "    $left line(s) also set something else; remove ADMIN_MONITOR_TOKEN from them by hand"
      fi
    fi
  done <<<"$files"
  if [ -z "$files" ]; then
    echo "    no anet-hub-admin unit in $systemd_dir"
  elif [ "$seen" = 0 ] && [ "$OPS_MONITORS" != 0 ]; then
    echo "    ADMIN_MONITOR_TOKEN is not set in the admin unit: the old admin sent ADMIN_TOKEN itself"
    echo "    as the console token of the $OPS_MONITORS manifest(s) with a monitor section"
  elif [ "$seen" = 0 ]; then
    echo "    ADMIN_MONITOR_TOKEN is not set in the admin unit"
  fi
  if [ "$edited" = 1 ]; then echo "    run systemctl daemon-reload before starting anet-hub-admin again"; fi

  echo "    to do by hand (docs/ADMIN.md §5; not done by this script):"
  echo "      - on each host above, remove this host's public key (fingerprints above) from the ssh"
  echo "        user's ~/.ssh/authorized_keys"
  echo "      - rotate the console token of each official agent that had a monitor section ($OPS_MONITORS)"
  echo "      - rotate ADMIN_TOKEN if ADMIN_MONITOR_TOKEN was unset or had the same value"
  echo "      - run anet-hub-admin under a non-root account (deploy/anet-hub-admin.service)"
  return 0
}

fingerprint() {
  local f=$1
  command -v ssh-keygen >/dev/null || { echo "no ssh-keygen for a fingerprint"; return 0; }
  ssh-keygen -lf "$f.pub" 2>/dev/null || ssh-keygen -lf "$f" 2>/dev/null || echo "fingerprint unavailable"
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
  return 0
}

main "$@"
