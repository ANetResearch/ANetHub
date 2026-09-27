// Package admin is the operator plane of the official Hub — a separate HTTP service (anet-hub-admin)
// that runs BESIDE the public anet-hub binary and never changes public behavior. It is:
//
//	registry ops — an operator view over the public hub.db registry (ALL agents, listed or not, with
//	               review counts and mailbox backlog), moderation state, and registry delete/restore.
//	               Official agents are registered by id, AID, hub and capabilities only.
//	audit        — every mutating admin action is recorded (who/what/when) in admin.db.
//
// It holds no task content and has no channel to any (A2A-DESIGN §9, [C39]). Earlier versions
// harvested relay payloads and official agents' job history into datasets/, proxied official agents'
// monitors and ran lifecycle commands on their hosts over ssh; all of that is removed. The session
// browser still reads whatever an earlier version left in admin.db and datasets/, and the production
// cleanup (deploy/cleanup-content-v0.2.sh) deletes it.
//
// admin.db is the admin plane's OWN store; the public hub.db is opened alongside it (same WAL file the
// hub serves from — busy_timeout guards cross-process writes, which are limited to registry deletes
// and restores).
package admin

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver (K207 A3: no cgo in distributed runtime)
)

// Store is the admin plane's durable state (SQLite at <dir>/admin.db).
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

// OpenStore opens (creating if needed) the admin store at dir.
func OpenStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("admin: dir required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("admin: mkdir: %w", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "admin.db")+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(15000)")
	if err != nil {
		return nil, fmt.Errorf("admin: open db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the db handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		// One row per official agent: the parsed AGENT manifest (JSON mirror of the ANetAgents repo's
		// AGENT.yaml). enabled=0 hides it from the ops plane without losing the manifest.
		`CREATE TABLE IF NOT EXISTS official_agent (
		   id TEXT PRIMARY KEY,
		   manifest TEXT NOT NULL,
		   enabled INTEGER NOT NULL DEFAULT 1,
		   created_at TEXT NOT NULL,
		   updated_at TEXT NOT NULL
		 )`,
		// Moderation state is admin-plane metadata keyed by AID. v0 semantics: "flagged" is an operator
		// note; "delisted" records the intent behind a registry delete (the public hub has no blocklist
		// yet — a delisted agent may re-register; enforcement is a hub-side roadmap item).
		`CREATE TABLE IF NOT EXISTS moderation (
		   aid TEXT PRIMARY KEY,
		   status TEXT NOT NULL DEFAULT 'ok',
		   note TEXT NOT NULL DEFAULT '',
		   updated_at TEXT NOT NULL
		 )`,
		`CREATE TABLE IF NOT EXISTS audit_log (
		   id INTEGER PRIMARY KEY AUTOINCREMENT,
		   ts TEXT NOT NULL,
		   actor TEXT NOT NULL DEFAULT 'admin',
		   action TEXT NOT NULL,
		   target TEXT NOT NULL DEFAULT '',
		   detail TEXT NOT NULL DEFAULT ''
		 )`,
		// Periodic hub health snapshot — the dashboard's time series.
		`CREATE TABLE IF NOT EXISTS stats_snapshot (
		   ts TEXT PRIMARY KEY,
		   agents INTEGER NOT NULL DEFAULT 0,
		   listed INTEGER NOT NULL DEFAULT 0,
		   tasks_completed INTEGER NOT NULL DEFAULT 0,
		   reviews INTEGER NOT NULL DEFAULT 0,
		   avg_rating REAL NOT NULL DEFAULT 0,
		   relay_backlog INTEGER NOT NULL DEFAULT 0,
		   hub_db_bytes INTEGER NOT NULL DEFAULT 0
		 )`,
		// Harvest cursors written by earlier versions (hub-relay, ai-studio). Nothing writes
		// them now; they are read for the overview until the production cleanup deletes them.
		`CREATE TABLE IF NOT EXISTS harvest_state (
		   source TEXT PRIMARY KEY,
		   cursor TEXT NOT NULL DEFAULT '',
		   last_run TEXT NOT NULL DEFAULT '',
		   sessions INTEGER NOT NULL DEFAULT 0,
		   records INTEGER NOT NULL DEFAULT 0,
		   note TEXT NOT NULL DEFAULT ''
		 )`,
		// Index of sessions harvested by earlier versions. Nothing writes it now; the session
		// browser reads it until the production cleanup deletes the rows.
		`CREATE TABLE IF NOT EXISTS session (
		   source TEXT NOT NULL,
		   session_id TEXT NOT NULL,
		   provider_aid TEXT NOT NULL DEFAULT '',
		   requester_aid TEXT NOT NULL DEFAULT '',
		   intent TEXT NOT NULL DEFAULT '',
		   goal TEXT NOT NULL DEFAULT '',
		   status TEXT NOT NULL DEFAULT '',
		   started_at TEXT NOT NULL DEFAULT '',
		   ended_at TEXT NOT NULL DEFAULT '',
		   events INTEGER NOT NULL DEFAULT 0,
		   bytes INTEGER NOT NULL DEFAULT 0,
		   card_path TEXT NOT NULL DEFAULT '',
		   data_path TEXT NOT NULL DEFAULT '',
		   updated_at TEXT NOT NULL,
		   PRIMARY KEY (source, session_id)
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_session_updated ON session(updated_at)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("admin: migrate: %w", err)
		}
	}
	return s.migrateRecovery()
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// Audit records one mutating admin action.
func (s *Store) Audit(actor, action, target, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.db.Exec(`INSERT INTO audit_log(ts,actor,action,target,detail) VALUES(?,?,?,?,?)`,
		nowRFC3339(), actor, action, target, detail)
}

// AuditEntry is one audit_log row.
type AuditEntry struct {
	ID     int64  `json:"id"`
	TS     string `json:"ts"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

// AuditTail returns the newest limit entries.
func (s *Store) AuditTail(limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id,ts,actor,action,target,detail FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PutOfficial upserts an official-agent manifest (already validated by the caller).
func (s *Store) PutOfficial(m *Manifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	now := nowRFC3339()
	_, err = s.db.Exec(
		`INSERT INTO official_agent(id,manifest,enabled,created_at,updated_at) VALUES(?,?,1,?,?)
		 ON CONFLICT(id) DO UPDATE SET manifest=excluded.manifest, updated_at=excluded.updated_at`,
		m.ID, string(raw), now, now)
	return err
}

// DeleteOfficial removes an official-agent manifest and reports whether a row
// existed to remove.
//
// found is returned because the HTTP layer used to answer 200 and write an
// audit row for the delete of an id that was never registered. The delete
// itself reports it, so there is no window between an existence check and the
// removal. Rows with enabled=0 count as present: they are hidden from the ops
// plane, not absent from the store.
func (s *Store) DeleteOfficial(id string) (found bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM official_agent WHERE id=?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// Officials returns all enabled official-agent manifests.
func (s *Store) Officials() ([]*Manifest, error) {
	rows, err := s.db.Query(`SELECT manifest FROM official_agent WHERE enabled=1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Manifest
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var m Manifest
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			continue // a corrupt row must not take the whole ops plane down
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

// Official returns one manifest by id.
func (s *Store) Official(id string) (*Manifest, error) {
	var raw string
	err := s.db.QueryRow(`SELECT manifest FROM official_agent WHERE id=? AND enabled=1`, id).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("admin: official agent %q not found", id)
	}
	var m Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("admin: official agent %q: corrupt manifest: %w", id, err)
	}
	return &m, nil
}

// Moderation is the admin-plane moderation state for one AID.
type Moderation struct {
	AID       string `json:"aid"`
	Status    string `json:"status"` // ok | flagged | delisted
	Note      string `json:"note"`
	UpdatedAt string `json:"updated_at"`
}

// SetModeration upserts moderation state for an AID.
func (s *Store) SetModeration(aid, status, note string) error {
	switch status {
	case "ok", "flagged", "delisted":
	default:
		return fmt.Errorf("admin: bad moderation status %q", status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO moderation(aid,status,note,updated_at) VALUES(?,?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET status=excluded.status, note=excluded.note, updated_at=excluded.updated_at`,
		aid, status, note, nowRFC3339())
	return err
}

// Moderations returns all non-ok moderation rows keyed by AID.
func (s *Store) Moderations() (map[string]Moderation, error) {
	rows, err := s.db.Query(`SELECT aid,status,note,updated_at FROM moderation`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Moderation{}
	for rows.Next() {
		var m Moderation
		if err := rows.Scan(&m.AID, &m.Status, &m.Note, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out[m.AID] = m
	}
	return out, rows.Err()
}

// Snapshot is one stats_snapshot row.
type Snapshot struct {
	TS             string  `json:"ts"`
	Agents         int     `json:"agents"`
	Listed         int     `json:"listed"`
	TasksCompleted int     `json:"tasks_completed"`
	Reviews        int     `json:"reviews"`
	AvgRating      float64 `json:"avg_rating"`
	RelayBacklog   int     `json:"relay_backlog"`
	HubDBBytes     int64   `json:"hub_db_bytes"`
}

// PutSnapshot stores one snapshot and prunes rows older than 30 days.
func (s *Store) PutSnapshot(sn Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO stats_snapshot(ts,agents,listed,tasks_completed,reviews,avg_rating,relay_backlog,hub_db_bytes)
		 VALUES(?,?,?,?,?,?,?,?)`,
		sn.TS, sn.Agents, sn.Listed, sn.TasksCompleted, sn.Reviews, sn.AvgRating, sn.RelayBacklog, sn.HubDBBytes)
	if err != nil {
		return err
	}
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	_, _ = s.db.Exec(`DELETE FROM stats_snapshot WHERE ts < ?`, cutoff)
	return nil
}

// Snapshots returns the newest limit snapshots, oldest first (chart order).
func (s *Store) Snapshots(limit int) ([]Snapshot, error) {
	if limit <= 0 || limit > 2000 {
		limit = 288
	}
	rows, err := s.db.Query(
		`SELECT ts,agents,listed,tasks_completed,reviews,avg_rating,relay_backlog,hub_db_bytes
		 FROM (SELECT * FROM stats_snapshot ORDER BY ts DESC LIMIT ?) ORDER BY ts`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Snapshot{}
	for rows.Next() {
		var sn Snapshot
		if err := rows.Scan(&sn.TS, &sn.Agents, &sn.Listed, &sn.TasksCompleted, &sn.Reviews,
			&sn.AvgRating, &sn.RelayBacklog, &sn.HubDBBytes); err != nil {
			return nil, err
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// HarvestState is one harvest_state row.
type HarvestState struct {
	Source   string `json:"source"`
	Cursor   string `json:"cursor"`
	LastRun  string `json:"last_run"`
	Sessions int    `json:"sessions"`
	Records  int    `json:"records"`
	Note     string `json:"note"`
}

// HarvestStates returns all harvest cursor rows.
func (s *Store) HarvestStates() ([]HarvestState, error) {
	rows, err := s.db.Query(`SELECT source,cursor,last_run,sessions,records,note FROM harvest_state ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HarvestState{}
	for rows.Next() {
		var st HarvestState
		if err := rows.Scan(&st.Source, &st.Cursor, &st.LastRun, &st.Sessions, &st.Records, &st.Note); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// SessionRow is one index row of a session an earlier version harvested (UI listing).
//
// The session table also has a goal column, which holds the first request goal of the harvested
// interaction or job, that is, task content. It is not read: the admin plane does not serve task
// content (A2A-DESIGN §9, SI-1), and the column is removed with the rows by the production cleanup.
type SessionRow struct {
	Source       string `json:"source"`
	SessionID    string `json:"session_id"`
	ProviderAID  string `json:"provider_aid"`
	RequesterAID string `json:"requester_aid"`
	Intent       string `json:"intent"`
	Status       string `json:"status"`
	StartedAt    string `json:"started_at"`
	EndedAt      string `json:"ended_at"`
	Events       int    `json:"events"`
	Bytes        int64  `json:"bytes"`
	CardPath     string `json:"card_path"`
	DataPath     string `json:"data_path"`
	UpdatedAt    string `json:"updated_at"`
}

// GetSession returns one session index row.
func (s *Store) GetSession(source, sessionID string) (SessionRow, error) {
	var r SessionRow
	err := s.db.QueryRow(
		`SELECT source,session_id,provider_aid,requester_aid,intent,status,started_at,ended_at,
		        events,bytes,card_path,data_path,updated_at
		 FROM session WHERE source=? AND session_id=?`, source, sessionID).
		Scan(&r.Source, &r.SessionID, &r.ProviderAID, &r.RequesterAID, &r.Intent, &r.Status,
			&r.StartedAt, &r.EndedAt, &r.Events, &r.Bytes, &r.CardPath, &r.DataPath, &r.UpdatedAt)
	return r, err
}

// Sessions lists sessions earlier versions harvested, newest activity first. source and q are
// optional filters (q matches session_id, AIDs or intent; not the goal, which is content).
func (s *Store) Sessions(source, q string, limit int) ([]SessionRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT source,session_id,provider_aid,requester_aid,intent,status,started_at,ended_at,
	                 events,bytes,card_path,data_path,updated_at FROM session`
	var conds []string
	var args []any
	if source != "" {
		conds = append(conds, `source=?`)
		args = append(args, source)
	}
	if q != "" {
		like := "%" + q + "%"
		conds = append(conds, `(session_id LIKE ? OR provider_aid LIKE ? OR requester_aid LIKE ? OR intent LIKE ?)`)
		args = append(args, like, like, like, like)
	}
	for i, c := range conds {
		if i == 0 {
			query += ` WHERE ` + c
		} else {
			query += ` AND ` + c
		}
	}
	query += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SessionRow{}
	for rows.Next() {
		var r SessionRow
		if err := rows.Scan(&r.Source, &r.SessionID, &r.ProviderAID, &r.RequesterAID, &r.Intent,
			&r.Status, &r.StartedAt, &r.EndedAt, &r.Events, &r.Bytes, &r.CardPath, &r.DataPath, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SessionCounts returns per-source {sessions, events, bytes} aggregates for the datasets overview.
func (s *Store) SessionCounts() (map[string]map[string]int64, error) {
	rows, err := s.db.Query(`SELECT source, COUNT(*), COALESCE(SUM(events),0), COALESCE(SUM(bytes),0) FROM session GROUP BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int64{}
	for rows.Next() {
		var src string
		var n, ev, by int64
		if err := rows.Scan(&src, &n, &ev, &by); err != nil {
			return nil, err
		}
		out[src] = map[string]int64{"sessions": n, "events": ev, "bytes": by}
	}
	return out, rows.Err()
}
