package admin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver (K207 A3: no cgo in distributed runtime)
)

// recovery —— 注册表删除的安全网。2026-07-20 一次针对公网 /admin 删除接口的脚本化批量删除（弱
// token）抹掉了约 67 个 agent。此文件提供：
//   1. 删除前归档整行（含 kel）到 admin.db deleted_agent —— 任何删除都可回滚，无需外部备份；
//   2. RestoreAgentsFromBackup —— 从一个 hub.db 备份 INSERT OR IGNORE 回 agent 表（一次性恢复）；
//   3. 破坏性操作限速（server.go 用）—— 单个循环无法再瞬间清空注册表。

// migrateRecovery adds the deleted-agent archive table (idempotent).
func (s *Store) migrateRecovery() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS deleted_agent (
	   aid TEXT NOT NULL,
	   row TEXT NOT NULL,          -- full agent row as JSON (incl. base64 kel) for restore
	   deleted_at TEXT NOT NULL,
	   actor TEXT NOT NULL DEFAULT 'admin'
	 )`)
	return err
}

// ArchiveDeletedAgent stores a full agent row (JSON) before it is deleted, so the delete is reversible.
func (s *Store) ArchiveDeletedAgent(aid, rowJSON, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO deleted_agent(aid,row,deleted_at,actor) VALUES(?,?,?,?)`,
		aid, rowJSON, nowRFC3339(), actor)
	return err
}

// FullAgentRow reads every column of one agent (incl. the kel blob) as a JSON string for archiving.
func (h *HubDB) FullAgentRow(aid string) (string, error) {
	var name, caps, summary, readme, pricing, registeredAt string
	var guestQuota int
	var kel []byte
	err := h.db.QueryRow(
		`SELECT name,caps,summary,readme,pricing,guest_quota,kel,registered_at FROM agent WHERE aid=?`, aid).
		Scan(&name, &caps, &summary, &readme, &pricing, &guestQuota, &kel, &registeredAt)
	if err != nil {
		return "", err
	}
	row := map[string]any{
		"aid": aid, "name": name, "caps": caps, "summary": summary, "readme": readme,
		"pricing": pricing, "guest_quota": guestQuota, "kel_b64": encB64(kel), "registered_at": registeredAt,
	}
	b, _ := json.Marshal(row)
	return string(b), nil
}

// RestoreAgentsFromBackup INSERT-OR-IGNOREs agents from a backup hub.db into the live hub store, run as
// a one-shot CLI recovery (anet-hub-admin --restore-agents-from <backup.db>). It only ADDS rows whose
// AID is absent — it can never delete or overwrite a live agent. Returns (before, after, restored).
func RestoreAgentsFromBackup(hubDataDir, backupPath string) (before, after int, err error) {
	hub, err := OpenHubDB(hubDataDir)
	if err != nil {
		return 0, 0, err
	}
	defer hub.Close()
	if err = hub.db.QueryRow(`SELECT COUNT(*) FROM agent`).Scan(&before); err != nil {
		return 0, 0, err
	}
	// Attach the backup and copy any missing agents (full row incl. kel).
	if _, err = hub.db.Exec(`ATTACH DATABASE ? AS bak`, backupPath); err != nil {
		return before, before, fmt.Errorf("attach backup: %w", err)
	}
	defer hub.db.Exec(`DETACH DATABASE bak`)
	if _, err = hub.db.Exec(`INSERT OR IGNORE INTO agent(aid,name,caps,summary,readme,pricing,guest_quota,kel,registered_at)
	   SELECT aid,name,caps,summary,readme,pricing,guest_quota,kel,registered_at FROM bak.agent`); err != nil {
		return before, before, fmt.Errorf("restore insert: %w", err)
	}
	if err = hub.db.QueryRow(`SELECT COUNT(*) FROM agent`).Scan(&after); err != nil {
		return before, after, err
	}
	return before, after, nil
}

// PruneAgentsExcept deletes every agent whose AID is NOT in keep, run as a one-shot CLI
// (anet-hub-admin --keep-only-agents "aid1,aid2,..."). Used to undo an over-broad restore. Refuses to
// run with an empty keep list (which would wipe the registry). The 07-19 backup remains, so this is
// reversible via --restore-agents-from. Returns (before, after, removed).
func PruneAgentsExcept(hubDataDir string, keep []string) (before, after, removed int, err error) {
	if len(keep) == 0 {
		return 0, 0, 0, fmt.Errorf("prune: empty keep list refused (would wipe the registry)")
	}
	hub, err := OpenHubDB(hubDataDir)
	if err != nil {
		return 0, 0, 0, err
	}
	defer hub.Close()
	if err = hub.db.QueryRow(`SELECT COUNT(*) FROM agent`).Scan(&before); err != nil {
		return 0, 0, 0, err
	}
	ph := make([]string, len(keep))
	args := make([]any, len(keep))
	for i, k := range keep {
		ph[i] = "?"
		args[i] = k
	}
	q := `DELETE FROM agent WHERE aid NOT IN (` + joinComma(ph) + `)`
	res, err := hub.db.Exec(q, args...)
	if err != nil {
		return before, before, 0, err
	}
	n, _ := res.RowsAffected()
	removed = int(n)
	if err = hub.db.QueryRow(`SELECT COUNT(*) FROM agent`).Scan(&after); err != nil {
		return before, after, removed, err
	}
	return before, after, removed, nil
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// destructiveLimiter bounds how many destructive registry ops (deletes) may run in a rolling window, so
// a scripted loop against the public admin API cannot wipe the registry.
type destructiveLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	times  []time.Time
}

func newDestructiveLimiter(max int, window time.Duration) *destructiveLimiter {
	return &destructiveLimiter{max: max, window: window}
}

// allow records an attempt and reports whether it is within the rate budget.
func (d *destructiveLimiter) allow() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	keep := d.times[:0]
	for _, t := range d.times {
		if now.Sub(t) < d.window {
			keep = append(keep, t)
		}
	}
	d.times = keep
	if len(d.times) >= d.max {
		return false
	}
	d.times = append(d.times, now)
	return true
}

func encB64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
