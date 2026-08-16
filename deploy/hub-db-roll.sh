#!/usr/bin/env bash
# hub-db-roll.sh — rolling retention for /data/projs/anet-hub/data/hub.db
# Policy:
#   - DELETE relay_message rows that are delivered (delivered_at NOT NULL) and older than 7 days
#   - DELETE relay_message rows that are undelivered and older than 14 days (conservative)
#   - agent / review / completed_task tables are never touched
#   - PRAGMA wal_checkpoint(TRUNCATE) after deletes
#   - On Sundays: VACUUM INTO rotating backup (keep newest 2), and VACUUM main db
#     if freelist exceeds 20% of pages
# Intended to run as user anet-hub (systemd hub-db-roll.service).
set -euo pipefail

DB=/data/projs/anet-hub/data/hub.db
DATA_DIR=/data/projs/anet-hub/data
LOG="$DATA_DIR/roll.log"

SQL() { sqlite3 "$DB" ".timeout 5000" "$@"; }
log() { echo "[$(date -Is)] $*" >>"$LOG"; }

CUTOFF_DELIVERED=$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)
CUTOFF_UNDELIVERED=$(date -u -d '14 days ago' +%Y-%m-%dT%H:%M:%SZ)

size_before=$(stat -c %s "$DB")
log "START db=$((size_before/1024/1024))MB cutoff_delivered=$CUTOFF_DELIVERED cutoff_undelivered=$CUTOFF_UNDELIVERED"

# Count before delete (safety: only delete what we counted)
n_delivered=$(SQL "SELECT COUNT(*) FROM relay_message WHERE delivered_at IS NOT NULL AND created_at < '$CUTOFF_DELIVERED';")
n_stale=$(SQL "SELECT COUNT(*) FROM relay_message WHERE delivered_at IS NULL AND created_at < '$CUTOFF_UNDELIVERED';")
log "candidates: delivered>7d=$n_delivered undelivered>14d=$n_stale"

if [ "$n_delivered" -gt 0 ]; then
    SQL "DELETE FROM relay_message WHERE delivered_at IS NOT NULL AND created_at < '$CUTOFF_DELIVERED';"
    log "deleted $n_delivered delivered rows"
fi
if [ "$n_stale" -gt 0 ]; then
    SQL "DELETE FROM relay_message WHERE delivered_at IS NULL AND created_at < '$CUTOFF_UNDELIVERED';"
    log "deleted $n_stale stale undelivered rows"
fi

SQL "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
log "wal_checkpoint(TRUNCATE) done"

# Sunday: rotating backup (keep 2) + conditional VACUUM
if [ "$(date +%u)" = "7" ]; then
    backup="$DATA_DIR/hub-backup-$(date +%Y%m%d).db"
    if [ ! -e "$backup" ]; then
        SQL "VACUUM INTO '$backup';"
        log "weekly backup: $backup ($(stat -c %s "$backup" | awk '{printf "%dMB", $1/1024/1024}'))"
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
