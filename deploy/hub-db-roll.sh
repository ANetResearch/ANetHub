#!/usr/bin/env bash
# hub-db-roll.sh — maintenance for /data/projs/anet-hub/data/hub.db (hub wire 2)
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
# and under the same account as hub.db, which already holds those rows.
# Backups written before wire 2 by earlier versions of this script still
# contain relay rows; removing those is part of the production cleanup and
# is not done here.
#
# Intended to run as user anet-hub (systemd hub-db-roll.service).
set -euo pipefail

DB=/data/projs/anet-hub/data/hub.db
DATA_DIR=/data/projs/anet-hub/data
LOG="$DATA_DIR/roll.log"

SQL() { sqlite3 "$DB" ".timeout 5000" "$@"; }
log() { echo "[$(date -Is)] $*" >>"$LOG"; }

size_before=$(stat -c %s "$DB")
backlog=$(SQL "SELECT COUNT(*) FROM relay_message;")
log "START db=$((size_before/1024/1024))MB relay_backlog=$backlog"

SQL "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
log "wal_checkpoint(TRUNCATE) done"

# Sunday: rotating backup without relay rows (keep 2) + conditional VACUUM
if [ "$(date +%u)" = "7" ]; then
    backup="$DATA_DIR/hub-backup-$(date +%Y%m%d).db"
    if [ ! -e "$backup" ]; then
        tmp="$DATA_DIR/.hub-backup-$(date +%Y%m%d).tmp.db"
        rm -f -- "$tmp" "$tmp-journal"
        # The temporary copy still holds relay rows until the DELETE below
        # has run; it is removed on every exit path, including a failed
        # statement under set -e, so that it does not outlive this run.
        trap 'rm -f -- "$tmp" "$tmp-journal" "$tmp-wal" "$tmp-shm"' EXIT
        SQL "VACUUM INTO '$tmp';"
        sqlite3 "$tmp" ".timeout 5000" \
            "PRAGMA secure_delete=ON;" \
            "DELETE FROM relay_message;" >/dev/null
        sqlite3 "$tmp" ".timeout 5000" "VACUUM INTO '$backup';"
        rm -f -- "$tmp" "$tmp-journal"
        left=$(sqlite3 "$backup" "SELECT COUNT(*) FROM relay_message;")
        if [ "$left" != "0" ]; then
            log "ERROR: backup $backup holds $left relay rows; removing it"
            rm -f -- "$backup"
            exit 1
        fi
        log "weekly backup: $backup ($(stat -c %s "$backup" | awk '{printf "%dMB", $1/1024/1024}'), relay rows excluded)"
    fi
    # keep newest 2 backups
    ls -1t "$DATA_DIR"/hub-backup-*.db 2>/dev/null | tail -n +3 | while read -r old; do
        rm -f -- "$old"
        log "pruned old backup: $old"
    done
    # VACUUM main db if freelist > 20% of pages
    freelist=$(SQL "PRAGMA freelist_count;")
    pages=$(SQL "PRAGMA page_count;")
    if [ "$pages" -gt 0 ] && [ $((freelist * 100 / pages)) -gt 20 ]; then
        log "VACUUM: freelist=$freelist/$pages pages"
        SQL "VACUUM;"
        log "VACUUM done"
    fi
fi

size_after=$(stat -c %s "$DB")
log "END db=$((size_after/1024/1024))MB (was $((size_before/1024/1024))MB)"
