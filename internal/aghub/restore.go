package aghub

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// A hub restored from a backup, or whose database went back to an older copy
// (KEL §4.2 H-20 to H-23, S-3).
//
// The witness notices this hub signs state the tip of the key history it
// holds for each agent. A database brought back from a backup holds the key
// histories as they were when the backup was made: an agent that rotated
// since, because its old key was copied, has its old key back at the tip
// here, and a notice signed now for that tip would let whoever holds the old
// key speak for the agent again. A restored hub therefore signs no notice for
// any AID until one of these (H-20):
//
//	(a) it takes a key history for the AID strictly longer than the one it
//	    held: the agent's node sends its newer history (D-27), which an
//	    online node does within seconds of the hub coming back;
//	(b) RestoreQuarantine has passed since the hub came back, and the AID
//	    signs a request with the key the hub holds as its current one: what
//	    the hub holds is then as current as anything the node told it.
//
// Each AID is released on its own; nothing releases them all. An AID this
// hub held no key history for when the quarantine began (one that registered
// after the backup was made, or a new one) is released the same way: its
// first registration is not "longer than what was held", so it waits for
// (b), or for a later rotation (a).
//
// A quarantine begins in two ways:
//
//   - anet-hub restore puts a backup in place as hub.db (Restore), with the
//     hub stopped;
//   - every start compares the database's count of key-history changes with
//     the count written beside it after each change (kel_hwm, H-21): a
//     database with a lower count than the file is an older copy, however
//     it came back (a file copied in by hand, a disk snapshot), and the
//     quarantine begins at that start.
//
// When it begins, the cached notices go and every directory entry is dropped
// (it may carry a notice signed before the backup), so nothing that states
// an old tip is served from the restored data. The hub process files the
// entries again, without notices, when it starts serving (BeginServing), and
// RestoreQuarantine counts from then: the nodes can only send their newer
// histories while the hub is up.

// RestoreQuarantine is how long after a restored hub starts serving an AID
// must wait, signing with the key the hub holds as current, before the hub
// states that key in a notice again (KEL §2.12, H-20 b). A code constant.
const RestoreQuarantine = 30 * time.Minute

// Why a quarantine began (restore_state.why).
const (
	quarantineRestore  = "restore"  // anet-hub restore
	quarantineRollback = "rollback" // a start found the database older than kel_hwm
)

// How an AID left the quarantine (restore_released.how).
const (
	releasedLongerKEL  = "longer_kel"  // H-20 a
	releasedCurrentKey = "current_key" // H-20 b
)

// kelHWMFile is the file beside hub.db that holds the database's count of
// key-history changes as of the last change this hub made (H-21).
const kelHWMFile = "kel_hwm"

// restoreSchema is the tables of the quarantine (core §2.16, KEL S-3). They
// go into backups with the ledger window's tables (hub-db-roll.sh excludes
// none of them): a backup of a hub in quarantine restores into one anyway.
func restoreSchema() []string {
	return []string{
		// The quarantine, when one began: one row, or none. began_at is
		// when (unix ms); serving_since is when the hub process started
		// serving the restored data, from which RestoreQuarantine counts,
		// NULL until then.
		`CREATE TABLE IF NOT EXISTS restore_state (
		   id INTEGER PRIMARY KEY CHECK (id = 1),
		   began_at INTEGER NOT NULL,
		   why TEXT NOT NULL,
		   serving_since INTEGER
		 )`,
		// The AIDs released from it (H-20), and how. Emptied when a
		// quarantine begins; an AID's row goes when it deregisters.
		`CREATE TABLE IF NOT EXISTS restore_released (
		   aid TEXT PRIMARY KEY,
		   released_at INTEGER NOT NULL,
		   how TEXT NOT NULL
		 )`,
		// The count of key-history changes this database has seen: every
		// registration that stores or extends a key history, every pushed
		// extension and every tombstone written (H-21). One row.
		`CREATE TABLE IF NOT EXISTS kel_hwm (
		   id INTEGER PRIMARY KEY CHECK (id = 1),
		   n INTEGER NOT NULL
		 )`,
	}
}

// inQuarantine is an SQL expression over the agent row a: true while a
// quarantine stands and a's AID has not been released from it.
const inQuarantine = `(EXISTS (SELECT 1 FROM restore_state)
	AND NOT EXISTS (SELECT 1 FROM restore_released r WHERE r.aid = a.aid))`

// countKELChangeTx counts one change of a key history this hub holds, in the
// transaction that makes it (H-21).
func countKELChangeTx(tx *sql.Tx) error {
	_, err := tx.Exec(`INSERT INTO kel_hwm(id, n) VALUES(1, 1) ON CONFLICT(id) DO UPDATE SET n = n + 1`)
	return err
}

// kelChanges is the database's count of key-history changes.
func kelChanges(q rowQuerier) (uint64, error) {
	var n int64
	if err := q.QueryRow(`SELECT COALESCE((SELECT n FROM kel_hwm WHERE id = 1), 0)`).Scan(&n); err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("hub: the count of key-history changes is %d", n)
	}
	return uint64(n), nil
}

// releaseTx releases aid from the quarantine, if one stands and aid is not
// released yet, for the reason how, in tx; its cached notice goes with it
// (KEL S-3), so the next request signs one for the tip now held. Without a
// quarantine it writes nothing.
func releaseTx(tx *sql.Tx, aid, how string, now time.Time) error {
	res, err := tx.Exec(`INSERT INTO restore_released(aid, released_at, how)
	    SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM restore_state)
	    ON CONFLICT(aid) DO NOTHING`, aid, now.UnixMilli(), how)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	if how == releasedCurrentKey {
		// The residual of H-20 b, said where the operator reads it (KEL J6):
		// an owner that rotated after the backup and has not come back since
		// gets its newer key stated again only when its node does.
		log.Printf("hub: %s leaves the restore quarantine: it signed a request with the key this hub holds as its "+
			"current one, %v after the hub came back; if it rotated after the backup was made, its node sends the "+
			"newer key history when it next connects", aid, RestoreQuarantine)
	} else {
		log.Printf("hub: %s leaves the restore quarantine: its node sent a newer key history", aid)
	}
	return forgetNoticeTx(tx, aid)
}

// startQuarantineTx begins a quarantine in tx (H-20), for why, at now: every
// AID is held again, every cached notice goes, and so does every directory
// entry (it carries the notice it was filed with; BeginServing files them
// again).
func startQuarantineTx(tx *sql.Tx, why string, now time.Time) error {
	for _, q := range []string{
		`DELETE FROM restore_released`,
		`DELETE FROM notice_cache`,
		`UPDATE agent SET dir_hash = NULL, dir_box = NULL WHERE dir_hash IS NOT NULL OR dir_box IS NOT NULL`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	_, err := tx.Exec(`INSERT INTO restore_state(id, began_at, why, serving_since) VALUES(1, ?, ?, NULL)
	    ON CONFLICT(id) DO UPDATE SET began_at = excluded.began_at, why = excluded.why, serving_since = NULL`,
		now.UnixMilli(), why)
	return err
}

// quarantineState is what the hub process keeps of the quarantine, so that a
// signed request costs no database read when there is none.
type quarantineState struct {
	mu sync.Mutex
	// active: restore_state has its row (read at Open, or begun here).
	active bool
	// servingSince is restore_state.serving_since in unix ms, 0 before the
	// hub process starts serving.
	servingSince int64
}

func (q *quarantineState) set(active bool, servingSince int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.active, q.servingSince = active, servingSince
}

// waitOver is whether, as far as this process knows, a quarantine stands
// whose wait (RestoreQuarantine since the hub came back) is over at now: a
// request signed with the current key may then release its AID (H-20 b).
func (q *quarantineState) waitOver(now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.active && q.servingSince != 0 && now.UnixMilli()-q.servingSince >= RestoreQuarantine.Milliseconds()
}

// loadQuarantine reads restore_state into s.quarantine.
func (s *Store) loadQuarantine() error {
	var serving sql.NullInt64
	err := s.db.QueryRow(`SELECT serving_since FROM restore_state WHERE id = 1`).Scan(&serving)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		s.quarantine.set(false, 0)
		return nil
	case err != nil:
		return err
	}
	s.quarantine.set(true, serving.Int64)
	return nil
}

// releaseOnCurrentKey is H-20 b for a request aid signed with the key this
// hub holds as its current one (relayauth under the stored tip, KEL H-3):
// once RestoreQuarantine has passed since the hub came back, aid is
// released, and its directory entry filed again. It is called after the
// signature verified, before the answer is written, so that a poll or a
// registration that releases the AID carries the notice it then gets.
func (s *Store) releaseOnCurrentKey(aid string) {
	now := s.now()
	if !s.quarantine.waitOver(now) {
		return
	}
	var held bool
	if err := s.db.QueryRow(`SELECT `+inQuarantine+` FROM agent a WHERE a.aid = ?`, aid).Scan(&held); err != nil || !held {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("hub: releasing %s from the restore quarantine: %v", aid, err)
		return
	}
	defer tx.Rollback()
	if err := releaseTx(tx, aid, releasedCurrentKey, now); err != nil {
		log.Printf("hub: releasing %s from the restore quarantine: %v", aid, err)
		return
	}
	if err := s.refreshDirTx(tx, aid); err != nil {
		log.Printf("hub: releasing %s from the restore quarantine: %v", aid, err)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("hub: releasing %s from the restore quarantine: %v", aid, err)
	}
}

// EndQuarantineWhenNoneHeld closes the record of a quarantine whose wait is
// over and that holds no registered agent any more: each one was released
// on its own (H-20). It releases nobody, and nothing changes for an AID that
// comes later: once the wait is over, the first request it signs, its
// registration, would release it anyway. What goes is the read every signed
// request makes while a quarantine stands. The hub process runs it every
// minute (RunNoticeRefresher).
func (s *Store) EndQuarantineWhenNoneHeld() error {
	now := s.now()
	if !s.quarantine.waitOver(now) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var held int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM agent a WHERE ` + inQuarantine).Scan(&held); err != nil {
		return err
	}
	if held > 0 {
		return nil
	}
	for _, q := range []string{`DELETE FROM restore_state`, `DELETE FROM restore_released`} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.quarantine.set(false, 0)
	log.Printf("hub: every agent is out of the restore quarantine")
	return nil
}

// BeginServing is what the hub process does once, as it starts serving,
// when a quarantine stands that has not been served yet: RestoreQuarantine
// starts counting now, and every agent is filed in the directory again,
// without a notice. Only the hub process calls it (RunNoticeRefresher); it
// needs the hub's identity (SetHubKey), which the directory entries name as
// the agents' home.
func (s *Store) BeginServing() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var serving sql.NullInt64
	var began int64
	var why string
	err = tx.QueryRow(`SELECT began_at, why, serving_since FROM restore_state WHERE id = 1`).Scan(&began, &why, &serving)
	if errors.Is(err, sql.ErrNoRows) || err == nil && serving.Valid {
		return nil
	}
	if err != nil {
		return err
	}
	now := s.now()
	if _, err := tx.Exec(`UPDATE restore_state SET serving_since = ? WHERE id = 1`, now.UnixMilli()); err != nil {
		return err
	}
	var aids []string
	rows, err := tx.Query(`SELECT aid FROM agent ORDER BY aid`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var aid string
		if err := rows.Scan(&aid); err != nil {
			rows.Close()
			return err
		}
		aids = append(aids, aid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, aid := range aids {
		if err := s.refreshDirTx(tx, aid); err != nil {
			return err
		}
	}
	var held int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM agent a WHERE ` + inQuarantine).Scan(&held); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.quarantine.set(true, now.UnixMilli())
	what := "restored from a backup"
	if why == quarantineRollback {
		what = "found older than the last key-history change it made (kel_hwm)"
	}
	log.Printf("hub: this hub's database was %s at %s: no key confirmation is signed for its %d agents until "+
		"each one's node sends a newer key history, or signs a request with its current key after %s",
		what, time.UnixMilli(began).UTC().Format(time.RFC3339), held, now.Add(RestoreQuarantine).UTC().Format(time.RFC3339))
	return nil
}

// QuarantineStatus is the state of the restore quarantine.
type QuarantineStatus struct {
	Active bool
	Why    string // "restore" or "rollback"
	// BeganAt is when it began; ServingSince when the hub process started
	// serving the restored data (zero before).
	BeganAt, ServingSince time.Time
	// Held is how many registered agents are still in it.
	Held int
}

// Quarantine reads the state of the restore quarantine.
func (s *Store) Quarantine() (QuarantineStatus, error) {
	var st QuarantineStatus
	var began int64
	var serving sql.NullInt64
	err := s.db.QueryRow(`SELECT began_at, why, serving_since FROM restore_state WHERE id = 1`).Scan(&began, &st.Why, &serving)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Active, st.BeganAt = true, time.UnixMilli(began)
	if serving.Valid {
		st.ServingSince = time.UnixMilli(serving.Int64)
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM agent a WHERE ` + inQuarantine).Scan(&st.Held)
	return st, err
}

// ---- kel_hwm: the high-water mark of key-history changes (H-21) ----

// hwmState is the count this process last wrote to kel_hwm.
type hwmState struct {
	mu      sync.Mutex
	written uint64
}

// checkKELHighWater is Open's half of H-21: the database's count of
// key-history changes against kel_hwm. A lower count, or a kel_hwm that does
// not read as a count, is a database older than the last change this hub
// made: a quarantine begins (why rollback), and the count is raised to the
// file's, so that the next start does not begin another one. Then kel_hwm is
// brought up to the count.
func (s *Store) checkKELHighWater() error {
	file, err := readKELHWM(s.dir)
	missing := errors.Is(err, fs.ErrNotExist)
	unreadable := err != nil && !missing
	if unreadable {
		log.Printf("hub: %s does not read as a count of key-history changes (%v); treating the database as an older copy",
			filepath.Join(s.dir, kelHWMFile), err)
	}
	// Read first: a database at or above kel_hwm, the case of every start
	// but one, takes no write lock (a subcommand opens the database beside
	// a running hub).
	n, err := kelChanges(s.db)
	if err != nil {
		return err
	}
	if n < file || unreadable {
		if err := s.beginRollbackQuarantine(file, unreadable); err != nil {
			return err
		}
	}
	if missing || unreadable {
		// A new data directory, or a file this hub cannot read: written
		// now, so that the next start has something to compare with.
		if err := writeKELHWM(s.dir, max(n, file)); err != nil {
			log.Printf("hub: writing %s: %v", kelHWMFile, err)
		} else {
			file = max(n, file)
		}
	}
	s.hwm.mu.Lock()
	s.hwm.written = file
	s.hwm.mu.Unlock()
	s.syncKELHighWater()
	return s.loadQuarantine()
}

// beginRollbackQuarantine is checkKELHighWater's write: in one transaction,
// read the count again and, when it is still below file (or kel_hwm did not
// read), begin a quarantine (why rollback) and raise the count to file.
func (s *Store) beginRollbackQuarantine(file uint64, unreadable bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	n, err := kelChanges(tx)
	if err != nil {
		return err
	}
	if n >= file && !unreadable {
		return nil
	}
	if err := startQuarantineTx(tx, quarantineRollback, s.now()); err != nil {
		return err
	}
	if n < file {
		if _, err := tx.Exec(`INSERT INTO kel_hwm(id, n) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET n = excluded.n`,
			int64(file)); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if n < file {
		log.Printf("hub: this hub's database has seen %d key-history changes, and %s says the hub made %d: it is an "+
			"older copy", n, kelHWMFile, file)
	}
	log.Printf("hub: no key confirmation is signed for an agent until its node sends a newer key history, or signs "+
		"a request with its current key %v after the hub starts serving", RestoreQuarantine)
	return nil
}

// syncKELHighWater writes the database's count of key-history changes to
// kel_hwm when it is above what this process last wrote: after every change
// this store commits, and when another process's change reaches the hub
// process (afterDereg). A count that cannot be written is logged and written
// at the next change; the file only ever lags, which costs a rollback found
// late, never a quarantine that was not due.
func (s *Store) syncKELHighWater() {
	n, err := kelChanges(s.db)
	if err != nil {
		log.Printf("hub: reading the count of key-history changes: %v", err)
		return
	}
	s.hwm.mu.Lock()
	defer s.hwm.mu.Unlock()
	if n <= s.hwm.written {
		return
	}
	// Another process may have written a higher count since this one read
	// the file: it is never lowered.
	if cur, err := readKELHWM(s.dir); err == nil && cur >= n {
		s.hwm.written = cur
		return
	}
	if err := writeKELHWM(s.dir, n); err != nil {
		log.Printf("hub: writing %s: %v", kelHWMFile, err)
		return
	}
	s.hwm.written = n
}

// maxKELHWMLen bounds what readKELHWM reads: a count of at most 20 digits and
// a newline.
const maxKELHWMLen = 21

// readKELHWM reads kel_hwm in dir: fs.ErrNotExist when there is none, 0 for
// it then.
func readKELHWM(dir string) (uint64, error) {
	f, err := os.Open(filepath.Join(dir, kelHWMFile))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	b := make([]byte, maxKELHWMLen+1)
	n, err := f.Read(b)
	if err != nil && n == 0 {
		return 0, fmt.Errorf("reading %s: %w", kelHWMFile, err)
	}
	return parseKELHWM(b[:n])
}

// parseKELHWM reads the contents of kel_hwm: a count in decimal without
// leading zeros, then a newline. Anything else is refused: the file is this
// hub's own, and one it did not write is not trusted to be low.
func parseKELHWM(b []byte) (uint64, error) {
	digits, ok := bytes.CutSuffix(b, []byte("\n"))
	if !ok || len(digits) == 0 || len(digits) > 20 || len(digits) > 1 && digits[0] == '0' {
		return 0, fmt.Errorf("%s is not a count and a newline", kelHWMFile)
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("%s is not a count and a newline", kelHWMFile)
		}
	}
	n, err := strconv.ParseUint(string(digits), 10, 64)
	if err != nil || n > maxKELChanges {
		return 0, fmt.Errorf("%s holds a count larger than a database counts", kelHWMFile)
	}
	return n, nil
}

// maxKELChanges is the largest count kel_hwm.n (an SQLite INTEGER) holds.
const maxKELChanges = 1<<63 - 1

// writeKELHWM writes n to kel_hwm in dir whole or not at all: a temporary
// file in dir, synced, renamed over it, and the directory synced.
func writeKELHWM(dir string, n uint64) error {
	f, err := os.CreateTemp(dir, "."+kelHWMFile+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.WriteString(strconv.FormatUint(n, 10) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, kelHWMFile)); err != nil {
		return err
	}
	return syncDir(dir) // tagkey.go
}

// ---- anet-hub restore ----

// ErrHubRunning is Restore's refusal while another process holds the data
// directory's lock (hubid.Lock): the hub is serving from it, or an identity
// operation is changing it.
var ErrHubRunning = errors.New("hub: the hub is running from this data directory")

// ErrNotABackup is Restore's refusal of a file that is not a whole hub
// database of this release: not SQLite, damaged, empty, or 0.2's.
var ErrNotABackup = errors.New("hub: not a backup of a hub database of this release")

// ErrBackupTooNew is Restore's refusal of a backup a newer anet-hub wrote.
var ErrBackupTooNew = errors.New("hub: the backup was written by a newer anet-hub than this one")

// restoreCleared are the tables whose rows no backup holds (deploy/hub-db-roll.sh
// EXCLUDED_TABLES; core §2.16). Restore deletes them from what it restores,
// so a restored hub holds what a backup holds, whatever copy it came from: no
// envelope a sender has since been told was delivered, no notice signed
// before the copy was made.
var restoreCleared = []string{"relay_message", "relay_redelivery", "dereg_event", "relay_dack", "notice_cache"}

// RestoreResult is what Restore did.
type RestoreResult struct {
	// Agents is how many agents the restored database registers, all of
	// them in quarantine.
	Agents int
}

// Restore puts the hub database in the file backup into the data directory
// dir as its hub.db, in quarantine (KEL H-20, H-23). The hub must not be
// running: Restore takes the data directory's lock (hubid.Lock), the one the
// hub holds while it serves, and refuses with ErrHubRunning when it cannot.
//
// The backup is checked then (a 0.3.0 hub database, whole: ErrNotABackup,
// ErrBackupTooNew) and nothing in dir changes when it is refused. It is
// copied into a new directory beside hub.db; in the copy, the tables no
// backup holds are emptied (restoreCleared), the quarantine begins at now,
// and the count of key-history changes is raised to kel_hwm's, so the next
// start does not take the restored copy for a second rollback. Then the copy
// replaces hub.db (its write-ahead log goes first: it belongs to the database
// being replaced) and kel_hwm is written.
func Restore(dir, backup string, now time.Time) (RestoreResult, error) {
	lock, err := hubid.Lock(dir)
	if errors.Is(err, hubid.ErrLocked) {
		return RestoreResult{}, ErrHubRunning
	}
	if err != nil {
		return RestoreResult{}, fmt.Errorf("hub: restore: %w", err)
	}
	defer lock.Release()
	if err := checkBackup(backup); err != nil {
		return RestoreResult{}, err
	}
	tmpDir, err := os.MkdirTemp(dir, ".restore-*")
	if err != nil {
		return RestoreResult{}, fmt.Errorf("hub: restore: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	tmp := filepath.Join(tmpDir, dataFile)
	if err := copyDatabase(backup, tmp); err != nil {
		return RestoreResult{}, err
	}
	file, err := readKELHWM(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Unreadable: the count written below replaces it.
		file = 0
	}
	res, count, err := quarantineCopy(tmp, file, now)
	if err != nil {
		return RestoreResult{}, err
	}
	for _, side := range []string{"-wal", "-shm", "-journal"} {
		if err := os.Remove(filepath.Join(dir, dataFile+side)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return RestoreResult{}, fmt.Errorf("hub: restore: %w", err)
		}
	}
	if err := os.Rename(tmp, filepath.Join(dir, dataFile)); err != nil {
		return RestoreResult{}, fmt.Errorf("hub: restore: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return RestoreResult{}, fmt.Errorf("hub: restore: %w", err)
	}
	if err := writeKELHWM(dir, count); err != nil {
		// The quarantine is in the database already; a lagging kel_hwm
		// only means the next rollback is found late.
		log.Printf("hub: restore: writing %s: %v", kelHWMFile, err)
	}
	return res, nil
}

// checkBackup is nil when the file backup is a whole hub database of this
// release. It writes nothing (readOnlyURI).
func checkBackup(backup string) error {
	st, err := os.Stat(backup)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotABackup, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a file", ErrNotABackup, backup)
	}
	db, err := sql.Open("sqlite", readOnlyURI(backup))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotABackup, err)
	}
	defer db.Close()
	version, objects, err := schemaState(db)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotABackup, err)
	}
	if objects == 0 {
		return fmt.Errorf("%w: the file holds no database", ErrNotABackup)
	}
	if err := judgeSchema(version, objects); err != nil {
		if errors.Is(err, ErrHubDataTooNew) {
			return fmt.Errorf("%w (%v)", ErrBackupTooNew, err)
		}
		return fmt.Errorf("%w: %v", ErrNotABackup, err)
	}
	var check string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&check); err != nil {
		return fmt.Errorf("%w: %v", ErrNotABackup, err)
	}
	if check != "ok" {
		return fmt.Errorf("%w: the database is damaged (%s)", ErrNotABackup, check)
	}
	for _, table := range []string{"agent", "restore_state", "kel_hwm"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n); err != nil {
			return fmt.Errorf("%w: %v", ErrNotABackup, err)
		}
		if n != 1 {
			return fmt.Errorf("%w: it has no table %s", ErrNotABackup, table)
		}
	}
	return nil
}

// copyDatabase writes a copy of the database in the file from to the new
// file to (VACUUM INTO), reading from without writing to it.
func copyDatabase(from, to string) error {
	db, err := sql.Open("sqlite", readOnlyURI(from))
	if err != nil {
		return fmt.Errorf("hub: restore: %w", err)
	}
	defer db.Close()
	if _, err := db.Exec(`VACUUM INTO ?`, to); err != nil {
		return fmt.Errorf("hub: restore: copying the backup: %w", err)
	}
	return nil
}

// quarantineCopy is Restore's work in the copy at path: the tables no backup
// holds are emptied, the quarantine begins at now, and the count of
// key-history changes becomes at least file. It returns the result and the
// count.
func quarantineCopy(path string, file uint64, now time.Time) (RestoreResult, uint64, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=secure_delete(ON)&_txlock=immediate")
	if err != nil {
		return RestoreResult{}, 0, fmt.Errorf("hub: restore: %w", err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return RestoreResult{}, 0, fmt.Errorf("hub: restore: %w", err)
	}
	defer tx.Rollback()
	for _, table := range restoreCleared {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n); err != nil {
			return RestoreResult{}, 0, fmt.Errorf("hub: restore: %w", err)
		}
		if n == 0 {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM "` + table + `"`); err != nil {
			return RestoreResult{}, 0, fmt.Errorf("hub: restore: emptying %s: %w", table, err)
		}
	}
	if err := startQuarantineTx(tx, quarantineRestore, now); err != nil {
		return RestoreResult{}, 0, fmt.Errorf("hub: restore: %w", err)
	}
	count, err := kelChanges(tx)
	if err != nil {
		return RestoreResult{}, 0, fmt.Errorf("hub: restore: %w", err)
	}
	if file > count {
		count = file
		if _, err := tx.Exec(`INSERT INTO kel_hwm(id, n) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET n = excluded.n`,
			int64(count)); err != nil {
			return RestoreResult{}, 0, fmt.Errorf("hub: restore: %w", err)
		}
	}
	var res RestoreResult
	if err := tx.QueryRow(`SELECT COUNT(*) FROM agent`).Scan(&res.Agents); err != nil {
		return RestoreResult{}, 0, fmt.Errorf("hub: restore: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RestoreResult{}, 0, fmt.Errorf("hub: restore: %w", err)
	}
	return res, count, nil
}
