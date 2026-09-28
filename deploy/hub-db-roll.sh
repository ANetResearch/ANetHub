#!/usr/bin/env bash
# hub-db-roll.sh — maintenance for the hub's hub.db (hub wire 2)
#
# Policy:
#   - Relay retention is not done here. Since wire 2 a relay_message row
#     exists only while it is undelivered: /relay/ack deletes it, and the
#     hub process deletes rows older than its -relay-ttl (default 14 days)
#     every 10 minutes. The hub opens the database with secure_delete=ON,
#     so deleted rows are overwritten in the file. The only relay figure
#     this script records is the current backlog, for the log.
#   - PRAGMA wal_checkpoint(TRUNCATE) on every run, so page images of
#     deleted rows do not stay in hub.db-wal.
#   - On Sundays: a rotating backup (keep newest 2) WITHOUT relay_message
#     rows, and VACUUM of the main db if the freelist exceeds 20% of pages.
#
# Backups exclude relay content (A2A-DESIGN §9 row "relay 存储", [C38]).
# Method: VACUUM INTO a temporary copy in the data directory, delete every
# relay_message row in that copy with secure_delete=ON (the copy's pages
# holding them are overwritten), then VACUUM INTO the final backup from the
# copy, which writes only live pages, and remove the copy. The temporary
# copy exists only for the duration of the backup, in the same directory
# and under the same account as hub.db, which already holds those rows; one
# left by a run killed outright is removed at the start of the next run.
# Backups written before wire 2 by earlier versions of this script still
# contain relay rows; removing those is part of the production cleanup
# (deploy/cleanup-content-v0.2.sh) and is not done here.
#
# Environment:
#   HUB_DATA_DIR   the hub's --data directory (default /data/projs/anet-hub/data)
#   FORCE_WEEKLY=1 run the Sunday part today (a backup that already exists for
#                  today's date is kept, not rewritten)
#
# Run it as the hub's account (anet-hub), from cron or a systemd timer, e.g.
#   17 4 * * *  HUB_DATA_DIR=/data/projs/anet-hub/data /data/projs/anet-hub/bin/hub-db-roll.sh
# deploy/hub-db-roll.service and deploy/hub-db-roll.timer are the units the production hubs run
# (daily at 04:30, as anet-hub, sandboxed to the data directory). It needs the sqlite3 CLI.
#
# Tested by deploy/scripts_test.go against a fixture hub.db (skipped where
# sqlite3 is not installed).
set -euo pipefail

DATA_DIR=${HUB_DATA_DIR:-/data/projs/anet-hub/data}
DB="$DATA_DIR/hub.db"
LOG="$DATA_DIR/roll.log"

command -v sqlite3 >/dev/null || { echo "hub-db-roll: sqlite3 is required" >&2; exit 1; }
[ -f "$DB" ] || { echo "hub-db-roll: $DB not found (set HUB_DATA_DIR)" >&2; exit 1; }

SQL() { sqlite3 "$DB" ".timeout 5000" "$@"; }
log() { echo "[$(date -Is)] $*" >>"$LOG"; }
# sqlstr quotes a path as an SQL string literal (HUB_DATA_DIR comes from the caller).
sqlstr() { printf "'%s'" "${1//\'/\'\'}"; }

size_before=$(stat -c %s "$DB")
backlog=$(SQL "SELECT COUNT(*) FROM relay_message;")
log "START db=$((size_before/1024/1024))MB relay_backlog=$backlog"

SQL "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
log "wal_checkpoint(TRUNCATE) done"

# A temporary backup copy from an earlier run that was killed before its
# EXIT trap (SIGKILL, power loss) still holds every relay row; it is
# nobody's backup and would otherwise stay on disk.
for stale in "$DATA_DIR"/.hub-backup-*.tmp.db; do
    [ -e "$stale" ] || continue
    rm -f -- "$stale" "$stale-journal" "$stale-wal" "$stale-shm"
    log "removed a temporary copy left by an interrupted run: $stale"
done

# Sunday: rotating backup without relay rows (keep 2) + conditional VACUUM
if [ "$(date +%u)" = "7" ] || [ "${FORCE_WEEKLY:-0}" = 1 ]; then
    backup="$DATA_DIR/hub-backup-$(date +%Y%m%d).db"
    if [ ! -e "$backup" ]; then
        tmp="$DATA_DIR/.hub-backup-$(date +%Y%m%d).tmp.db"
        rm -f -- "$tmp" "$tmp-journal" "$tmp-wal" "$tmp-shm"
        # The temporary copy still holds relay rows until the DELETE below
        # has run; it is removed on every exit path, including a failed
        # statement under set -e, so that it does not outlive this run.
        trap 'rm -f -- "$tmp" "$tmp-journal" "$tmp-wal" "$tmp-shm"' EXIT
        SQL "VACUUM INTO $(sqlstr "$tmp");"
        sqlite3 "$tmp" ".timeout 5000" \
            "PRAGMA secure_delete=ON;" \
            "DELETE FROM relay_message;" >/dev/null
        sqlite3 "$tmp" ".timeout 5000" "VACUUM INTO $(sqlstr "$backup");"
        rm -f -- "$tmp" "$tmp-journal" "$tmp-wal" "$tmp-shm"
        left=$(sqlite3 "$backup" "SELECT COUNT(*) FROM relay_message;")
        if [ "$left" != "0" ]; then
            log "ERROR: backup $backup holds $left relay rows; removing it"
            rm -f -- "$backup"
            exit 1
        fi
        log "weekly backup: $backup ($(stat -c %s "$backup" | awk '{printf "%dMB", $1/1024/1024}'), relay rows excluded)"
    fi
    # Keep the newest 2 backups. Not `ls | tail | while`: with pipefail an
    # ls that matches nothing fails the pipeline, and set -e then ended the
    # run before the VACUUM and the END line.
    mapfile -t backups < <(ls -1t -- "$DATA_DIR"/hub-backup-*.db 2>/dev/null || true)
    for old in "${backups[@]:2}"; do
        rm -f -- "$old" "$old-wal" "$old-shm" "$old-journal"
        log "pruned old backup: $old"
    done
    # VACUUM main db if freelist > 20% of pages
    freelist=$(SQL "PRAGMA freelist_count;")
    pages=$(SQL "PRAGMA page_count;")
    if [ "$pages" -gt 0 ] && [ $((freelist * 100 / pages)) -gt 20 ]; then
        log "VACUUM: freelist=$freelist/$pages pages"
        SQL "VACUUM;"
        SQL "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
        log "VACUUM done"
    fi
fi

size_after=$(stat -c %s "$DB")
log "END db=$((size_after/1024/1024))MB (was $((size_before/1024/1024))MB)"
