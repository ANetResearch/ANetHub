package admin

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver (K207 A3: no cgo in distributed runtime)
)

// What stands between an operator and a mistaken delete (hub-payment-privacy PAY-O3, PAY-O4).
//
// A delete revokes the AID's admission and deregisters it (HubDB.DeleteAgent). Undoing one is
// admitting the AID again, with anet-hub admit <AID>: the agent's own anet registers again with its
// current key history, and nothing else is needed. For a batch, GET /admin/api/deleted?format=admit
// lists the deleted AIDs one per line, which anet-hub admit --file takes as it is.
//
// There is no "restore the old row": the earlier restore and prune paths (RestoreDeletedAgent,
// RestoreAgentsFromBackup, PruneAgentsExcept) wrote a stored key history straight back into the
// registry, past the rule that a key history may only grow. Whoever holds a copy of the agent's data
// directory can sign a fork from an earlier event, and only the tombstone the delete leaves stops it
// from registering as the agent. A whole hub is restored with anet-hub restore.
//
// So the record kept here is only who was deleted, when and by whom: deleted_agent(aid, deleted_at,
// actor). No row, no key history, no profile text (PAY-O4). And destructive operations are rate
// limited, so a scripted loop cannot empty the registry.

// ErrAdminDBTooOld is an admin.db an earlier release wrote: its deleted_agent table still has the
// row column of the removed restore path. It is refused, not converted (§3.4a); anet-hub-admin says
// admin.db_too_old.
var ErrAdminDBTooOld = errors.New("admin: admin.db was written by a version before 0.3.0")

// checkAdminDB refuses the admin.db at path when an earlier release wrote it, and writes nothing: the
// file is read immutable (no lock, no -wal or -shm file). No file yet is fine.
func checkAdminDB(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	db, err := sql.Open("sqlite", immutableURI(path))
	if err != nil {
		return fmt.Errorf("admin: open %s: %w", path, err)
	}
	defer db.Close()
	return checkDeletedAgentTable(db)
}

// checkDeletedAgentTable is ErrAdminDBTooOld when q's deleted_agent table has a row column.
func checkDeletedAgentTable(q interface {
	QueryRow(query string, args ...any) *sql.Row
}) error {
	var n int
	if err := q.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('deleted_agent') WHERE name = 'row'`).
		Scan(&n); err != nil {
		return fmt.Errorf("admin: read admin.db: %w", err)
	}
	if n > 0 {
		return ErrAdminDBTooOld
	}
	return nil
}

// immutableURI is the SQLite URI that opens the file at path read-only and immutable.
func immutableURI(path string) string {
	p := filepath.ToSlash(path)
	if filepath.IsAbs(path) && !strings.HasPrefix(p, "/") {
		p = "/" + p // a drive letter: file:/C:/…
	}
	return "file:" + (&url.URL{Path: p}).EscapedPath() + "?mode=ro&immutable=1"
}

// migrateRecovery creates the deletion record (an earlier release's, with a row column, is refused
// before this runs: checkDeletedAgentTable).
func (s *Store) migrateRecovery() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS deleted_agent (
	   aid TEXT NOT NULL,
	   deleted_at TEXT NOT NULL,
	   actor TEXT NOT NULL DEFAULT 'admin'
	 )`)
	return err
}

// RecordDeletedAgent notes that actor deleted aid, now.
func (s *Store) RecordDeletedAgent(aid, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO deleted_agent(aid,deleted_at,actor) VALUES(?,?,?)`,
		aid, nowRFC3339(), actor)
	return err
}

// DeletedAgent is one operator delete: whom, when, by whom.
type DeletedAgent struct {
	AID       string `json:"aid"`
	DeletedAt string `json:"deleted_at"`
	Actor     string `json:"actor"`
}

// DeletedAgents lists the newest limit deletes, newest first.
func (s *Store) DeletedAgents(limit int) ([]DeletedAgent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT aid,deleted_at,actor FROM deleted_agent ORDER BY rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeletedAgent{}
	for rows.Next() {
		var d DeletedAgent
		if err := rows.Scan(&d.AID, &d.DeletedAt, &d.Actor); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
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
