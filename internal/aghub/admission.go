package aghub

// Admission (hub-payment-privacy §4.2.4, PAY-A1 to PAY-A8): who may register
// here for the first time, and what a newcomer gets.
//
// There are no invitation secrets any more. A hub knows a newcomer only by
// its AID, and an operator admits AIDs:
//
//   - the admission list (anet-hub admit <AID>, --file, --grant N): an AID on
//     the list registers with no proof of work, no quota and no probation;
//   - a sign-up window (anet-hub admit --window 2h --max 50): while it is
//     open and not full, an unknown AID may register after a proof of work;
//   - open registration (anet-hub admission open; the official public hub):
//     any AID may register after a proof of work, within a daily quota per
//     network.
//
// A new hub is closed: only the list (SI-5). Registration never pays credit.
// An account that came in through a window or open registration is on
// probation for 72 hours; when that ends, the first signed request it makes
// earns it 20 trial credits, as long as today's budget for its network and
// for the hub is not spent.
//
// What lives where: the list, the window, the mode and the per-account
// columns are in hub.db; the proof-of-work key, the per-network counters and
// the trial budgets are only in this process's memory and are keyed by an
// HMAC under a key that changes every UTC day, so no client address is ever
// written to disk or a log (PAY-N7). A restart resets today's counters and
// starts a new proof-of-work key; a client whose challenge it was solving
// just gets a new one.

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/regpow"
)

// The constants of hub-payment-privacy §0.4. None is configurable: the same
// rules hold on every hub, and an operator with a real need (a campus behind
// one address) admits AIDs instead.
const (
	// AdmissionClosed is the mode of a new hub: only the admission list
	// (and an open sign-up window) admits a newcomer.
	AdmissionClosed = "closed"
	// AdmissionOpen admits any AID after a proof of work, within the daily
	// quota of its network.
	AdmissionOpen = "open"

	// ProbationPeriod is how long an account that came in through a window
	// or open registration is on probation.
	ProbationPeriod = 72 * time.Hour
	// TrialCredits is what such an account is given when its probation
	// ends.
	TrialCredits int64 = 20

	// MaxWindowLength and MaxWindowSize bound one sign-up window.
	MaxWindowLength = 7 * 24 * time.Hour
	MaxWindowSize   = 10000

	// InactiveAfter is how long an account may sit registered without ever
	// collecting its mail before the janitor deregisters it (PAY-A6).
	InactiveAfter = 7 * 24 * time.Hour

	// windowKeep is how long a closed window's row is kept.
	windowKeep = 30 * 24 * time.Hour

	// trialBudgetHub is the number of trial grants the whole hub pays per
	// UTC day.
	trialBudgetHub = 100

	// metaAdmissionMode is the hub_meta key of the mode.
	metaAdmissionMode = "admission_mode"
)

// How an account came in (agent.admitted_via), and where its trial credit
// stands (agent.trial).
const (
	viaList   = "list"
	viaWindow = "window"
	viaOpen   = "open"

	trialNone    = "none"
	trialPending = "pending"
	trialGranted = "granted"
)

// Ledger reasons of the two ways admission pays credit.
const (
	reasonAdmissionGrant = "admission grant"
	reasonTrialCredit    = "trial credit"
)

// netLimit is a daily limit on one level of a client's network: the IPv4 or
// IPv6 prefix of the given length.
type netLimit struct {
	v6   bool
	bits int
	max  int
}

// signupQuota is the daily number of open registrations per network level
// (§0.4). An IPv4-mapped IPv6 address counts as IPv4.
var signupQuota = []netLimit{
	{false, 32, 20}, {false, 24, 200},
	{true, 64, 20}, {true, 48, 200}, {true, 32, 1000},
}

// trialBudget is the daily number of trial grants per network level; the
// whole hub pays at most trialBudgetHub.
var trialBudget = []netLimit{
	{false, 24, 3},
	{true, 48, 3}, {true, 32, 10},
}

// Errors of the admission commands, each with one sentence on the operator's
// side (cmd/anet-hub text.go).
var (
	ErrBadAID        = errors.New("hub: not a valid AID")
	ErrNotListed     = errors.New("hub: that AID is not on the admission list and not registered here")
	ErrWindowExists  = errors.New("hub: a sign-up window is already open")
	ErrWindowTooBig  = errors.New("hub: a sign-up window lasts at most 7 days and takes at most 10000")
	ErrNegativeGrant = errors.New("hub: a grant cannot be negative")
	ErrUnknownMode   = errors.New("hub: the admission mode is open or closed")
	errWindowFilled  = errors.New("hub: the sign-up window filled up")
	errNotAdmitted   = errors.New("hub: the admission was revoked during the registration")
)

// BadLineError is an admission file with a line that is not an AID. Nothing
// from the file was imported.
type BadLineError struct{ Line int }

func (e *BadLineError) Error() string {
	return fmt.Sprintf("hub: line %d of the admission file is not a valid AID", e.Line)
}

// aidPrefix is the first bytes of every AID once decoded: CIDv1, dag-cbor,
// sha2-256, 32 bytes (ANetCore anetcid).
var aidPrefix = []byte{0x01, 0x71, 0x12, 0x20}

var aidEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ValidAID reports whether s is a complete AID: "b" and the canonical
// lower-case base32 of a CIDv1 dag-cbor sha2-256 identifier. A prefix, a
// short form or a name is not one, so an operator who pasted half an AID is
// told so instead of admitting nobody in particular.
func ValidAID(s string) bool {
	if len(s) != 59 || s[0] != 'b' {
		return false
	}
	raw, err := aidEncoding.DecodeString(s[1:])
	if err != nil || len(raw) != len(aidPrefix)+32 {
		return false
	}
	for i, b := range aidPrefix {
		if raw[i] != b {
			return false
		}
	}
	return aidEncoding.EncodeToString(raw) == s[1:]
}

// now is the store's clock: time.Now, or a test's.
func (s *Store) now() time.Time {
	if f := s.clock; f != nil {
		return f()
	}
	return time.Now()
}

// migrateAdmission creates the admission tables (hub-payment-privacy §3.2).
func (s *Store) migrateAdmission() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS admitted (
		   aid TEXT PRIMARY KEY,
		   label TEXT NOT NULL DEFAULT '',
		   "grant" INTEGER NOT NULL DEFAULT 0,
		   granted INTEGER NOT NULL DEFAULT 0,
		   created_at INTEGER NOT NULL
		 )`,
		`CREATE TABLE IF NOT EXISTS admission_window (
		   id INTEGER PRIMARY KEY AUTOINCREMENT,
		   opens_at INTEGER NOT NULL,
		   closes_at INTEGER NOT NULL,
		   max INTEGER NOT NULL,
		   used INTEGER NOT NULL DEFAULT 0,
		   label TEXT NOT NULL DEFAULT ''
		 )`,
		// What a deregistration committed by another process leaves for the
		// hub process (PAY-O2, deregister.go). Never backed up.
		`CREATE TABLE IF NOT EXISTS dereg_event (
		   aid TEXT PRIMARY KEY,
		   at INTEGER NOT NULL
		 )`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("hub: migrate admission: %w", err)
		}
	}
	return nil
}

// ---- the mode ----

// AdmissionMode is closed (the default of a new hub) or open.
func (s *Store) AdmissionMode() (string, error) {
	return admissionMode(s.db)
}

func admissionMode(q rowQuerier) (string, error) {
	var v string
	err := q.QueryRow(`SELECT value FROM hub_meta WHERE key=?`, metaAdmissionMode).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return AdmissionClosed, nil
	}
	if err != nil {
		return "", err
	}
	if v != AdmissionOpen {
		return AdmissionClosed, nil
	}
	return AdmissionOpen, nil
}

// SetAdmissionMode switches between open and closed. A hub already serving
// sees the change on its next registration (the database is shared).
func (s *Store) SetAdmissionMode(mode string) error {
	if mode != AdmissionOpen && mode != AdmissionClosed {
		return ErrUnknownMode
	}
	_, err := s.db.Exec(`INSERT INTO hub_meta(key, value) VALUES(?,?)
	    ON CONFLICT(key) DO UPDATE SET value=excluded.value`, metaAdmissionMode, mode)
	return err
}

// ---- the admission list ----

// Admission is one row of the admission list.
type Admission struct {
	AID       string `json:"aid"`
	Label     string `json:"label"`
	Grant     int64  `json:"grant"`
	Granted   bool   `json:"granted"`
	CreatedAt int64  `json:"created_at"` // unix ms
}

// AdmitResult says what Admit did, so the operator is told exactly that.
type AdmitResult struct {
	// Registered: the AID is already registered here; its probation ended
	// now.
	Registered bool
	// Paid is the grant paid by this call (registered AIDs only).
	Paid int64
	// Grant is the grant on the list that is still to be paid when the AID
	// first registers.
	Grant int64
	// AlreadyGranted: a grant was asked for, but this AID's grant was paid
	// before, so nothing was paid now.
	AlreadyGranted bool
}

// Admit puts aid on the admission list (PAY-A7). label replaces the stored
// label when labelSet. grant, when positive, is the credit paid when the AID
// first registers, or now if it is already registered; a grant is paid at
// most once per AID. For an AID already registered here the probation ends
// now and a trial grant not yet paid is cancelled: an operator who admits an
// account vouches for it.
func (s *Store) Admit(aid string, grant int64, label string, labelSet bool) (AdmitResult, error) {
	if !ValidAID(aid) {
		return AdmitResult{}, ErrBadAID
	}
	if grant < 0 {
		return AdmitResult{}, ErrNegativeGrant
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return AdmitResult{}, err
	}
	defer tx.Rollback()
	res, err := s.admitTx(tx, aid, grant, label, labelSet, s.now())
	if err != nil {
		return AdmitResult{}, err
	}
	return res, tx.Commit()
}

// AdmitFile admits every AID in the file at path: one per line, blank lines
// and lines starting with # ignored. The whole file goes in one transaction:
// a line that is not an AID imports nothing. It returns how many distinct
// AIDs were admitted and how many of them are already registered.
func (s *Store) AdmitFile(path string, grant int64, label string, labelSet bool) (admitted, registered int, err error) {
	if grant < 0 {
		return 0, 0, ErrNegativeGrant
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var aids []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !ValidAID(line) {
			return 0, 0, &BadLineError{Line: n}
		}
		if !seen[line] {
			seen[line] = true
			aids = append(aids, line)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	now := s.now()
	for _, aid := range aids {
		res, err := s.admitTx(tx, aid, grant, label, labelSet, now)
		if err != nil {
			return 0, 0, err
		}
		if res.Registered {
			registered++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return len(aids), registered, nil
}

// admitTx is Admit inside tx.
func (s *Store) admitTx(tx *sql.Tx, aid string, grant int64, label string, labelSet bool, now time.Time) (AdmitResult, error) {
	var res AdmitResult
	var stored, granted int64
	var have bool
	switch err := tx.QueryRow(`SELECT "grant", granted FROM admitted WHERE aid=?`, aid).Scan(&stored, &granted); {
	case err == nil:
		have = true
	case errors.Is(err, sql.ErrNoRows):
	default:
		return res, err
	}
	if !have {
		if _, err := tx.Exec(`INSERT INTO admitted(aid, label, "grant", granted, created_at) VALUES(?,?,?,0,?)`,
			aid, label, grant, now.UnixMilli()); err != nil {
			return res, err
		}
		stored = grant
	} else {
		if labelSet {
			if _, err := tx.Exec(`UPDATE admitted SET label=? WHERE aid=?`, label, aid); err != nil {
				return res, err
			}
		}
		if grant > 0 {
			if granted != 0 {
				res.AlreadyGranted = true
			} else {
				if _, err := tx.Exec(`UPDATE admitted SET "grant"=? WHERE aid=?`, grant, aid); err != nil {
					return res, err
				}
				stored = grant
			}
		}
	}
	var one int
	switch err := tx.QueryRow(`SELECT 1 FROM agent WHERE aid=?`, aid).Scan(&one); {
	case err == nil:
		res.Registered = true
	case errors.Is(err, sql.ErrNoRows):
	default:
		return res, err
	}
	if !res.Registered {
		if granted == 0 {
			res.Grant = stored
		}
		return res, nil
	}
	// Registered already: off probation now, and on the list from now on.
	ms := now.UnixMilli()
	if _, err := tx.Exec(`UPDATE agent SET admitted_via=?,
	      probation_until = CASE WHEN probation_until IS NOT NULL AND probation_until > ? THEN ? ELSE probation_until END,
	      trial = CASE WHEN trial = ? THEN ? ELSE trial END
	    WHERE aid=?`, viaList, ms, ms, trialPending, trialNone, aid); err != nil {
		return res, err
	}
	if granted == 0 && stored > 0 {
		paid, err := s.payListGrantTx(tx, aid)
		if err != nil {
			return res, err
		}
		res.Paid = paid
	}
	return res, nil
}

// payListGrantTx pays aid's admission grant once, inside tx: the grant on
// the list when it is positive and not yet paid. It returns what it paid.
func (s *Store) payListGrantTx(tx *sql.Tx, aid string) (int64, error) {
	var grant, granted int64
	err := tx.QueryRow(`SELECT "grant", granted FROM admitted WHERE aid=?`, aid).Scan(&grant, &granted)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (grant <= 0 || granted != 0) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE admitted SET granted=1 WHERE aid=?`, aid); err != nil {
		return 0, err
	}
	if err := s.issueTx(tx, aid, grant, reasonAdmissionGrant); err != nil {
		return 0, err
	}
	return grant, nil
}

// RevokeResult says what RevokeAdmission did.
type RevokeResult struct {
	// Registered: the AID was registered here and is now deregistered.
	Registered bool
	// Balance is its balance, which stays on the ledger.
	Balance int64
}

// RevokeAdmission takes aid off the admission list and, when it is
// registered here (by whatever route it came in), deregisters it in the same
// transaction (PAY-A7, PAY-O1, KEL H-12). Its balance stays on the ledger
// and its key history becomes its tombstone, so it can come back only with
// a key history that extends the one it left with, and only after being
// admitted again. Called from another process (anet-hub admissions revoke),
// it leaves dereg_event for the hub process, which drops the AID's sessions
// within two seconds (PAY-O2).
func (s *Store) RevokeAdmission(aid string) (RevokeResult, error) {
	if !ValidAID(aid) {
		return RevokeResult{}, ErrBadAID
	}
	s.mu.Lock()
	tx, err := s.db.Begin()
	if err != nil {
		s.mu.Unlock()
		return RevokeResult{}, err
	}
	defer tx.Rollback()
	var res RevokeResult
	d, err := DeregisterTx(tx, aid, DeregRevoked)
	switch {
	case err == nil:
		res.Registered, res.Balance = true, d.Balance
	case errors.Is(err, ErrNotRegistered):
		r, derr := tx.Exec(`DELETE FROM admitted WHERE aid=?`, aid)
		if derr != nil {
			s.mu.Unlock()
			return res, derr
		}
		if n, _ := r.RowsAffected(); n == 0 {
			s.mu.Unlock()
			return res, ErrNotListed
		}
	default:
		s.mu.Unlock()
		return res, err
	}
	err = tx.Commit()
	s.mu.Unlock()
	if err != nil {
		return RevokeResult{}, err
	}
	if res.Registered {
		s.afterDereg(aid)
	}
	return res, nil
}

// ---- the sign-up window ----

// Window is a sign-up window.
type Window struct {
	ID       int64  `json:"id"`
	OpensAt  int64  `json:"opens_at"`  // unix ms
	ClosesAt int64  `json:"closes_at"` // unix ms
	Max      int    `json:"max"`
	Used     int    `json:"used"`
	Label    string `json:"label"`
}

// ErrWindowOpen is ErrWindowExists with the window that is open.
type ErrWindowOpen struct{ Window Window }

func (e *ErrWindowOpen) Error() string { return ErrWindowExists.Error() }
func (e *ErrWindowOpen) Unwrap() error { return ErrWindowExists }

// openWindow is the window open at now, if any (at most one is).
func openWindow(q rowQuerier, now time.Time) (Window, bool, error) {
	var w Window
	ms := now.UnixMilli()
	err := q.QueryRow(`SELECT id, opens_at, closes_at, max, used, label FROM admission_window
	    WHERE opens_at <= ? AND closes_at > ? ORDER BY id DESC LIMIT 1`, ms, ms).
		Scan(&w.ID, &w.OpensAt, &w.ClosesAt, &w.Max, &w.Used, &w.Label)
	if errors.Is(err, sql.ErrNoRows) {
		return Window{}, false, nil
	}
	if err != nil {
		return Window{}, false, err
	}
	return w, true, nil
}

// OpenWindow opens a sign-up window for d, admitting at most max newcomers
// (each after a proof of work, each on probation). Only one window is open at
// a time.
func (s *Store) OpenWindow(d time.Duration, max int, label string) (Window, error) {
	if d <= 0 || d > MaxWindowLength || max <= 0 || max > MaxWindowSize {
		return Window{}, ErrWindowTooBig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return Window{}, err
	}
	defer tx.Rollback()
	now := s.now()
	if w, ok, err := openWindow(tx, now); err != nil {
		return Window{}, err
	} else if ok {
		return Window{}, &ErrWindowOpen{Window: w}
	}
	w := Window{OpensAt: now.UnixMilli(), ClosesAt: now.Add(d).UnixMilli(), Max: max, Label: label}
	r, err := tx.Exec(`INSERT INTO admission_window(opens_at, closes_at, max, used, label) VALUES(?,?,?,0,?)`,
		w.OpensAt, w.ClosesAt, w.Max, w.Label)
	if err != nil {
		return Window{}, err
	}
	if w.ID, err = r.LastInsertId(); err != nil {
		return Window{}, err
	}
	return w, tx.Commit()
}

// CloseWindow closes the open window now. ok is false when none was open.
func (s *Store) CloseWindow() (w Window, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return Window{}, false, err
	}
	defer tx.Rollback()
	now := s.now()
	w, ok, err = openWindow(tx, now)
	if err != nil || !ok {
		return Window{}, false, err
	}
	w.ClosesAt = now.UnixMilli()
	if _, err := tx.Exec(`UPDATE admission_window SET closes_at=? WHERE id=?`, w.ClosesAt, w.ID); err != nil {
		return Window{}, false, err
	}
	return w, true, tx.Commit()
}

// Admissions is what anet-hub admissions lists.
type Admissions struct {
	Mode     string      `json:"mode"`
	Window   *Window     `json:"window"`
	Admitted []Admission `json:"admitted"`
}

// ListAdmissions reads the mode, the open window and the list, oldest first.
func (s *Store) ListAdmissions() (Admissions, error) {
	var a Admissions
	var err error
	if a.Mode, err = s.AdmissionMode(); err != nil {
		return a, err
	}
	if w, ok, err := openWindow(s.db, s.now()); err != nil {
		return a, err
	} else if ok {
		a.Window = &w
	}
	rows, err := s.db.Query(`SELECT aid, label, "grant", granted, created_at FROM admitted ORDER BY created_at, aid`)
	if err != nil {
		return a, err
	}
	defer rows.Close()
	a.Admitted = []Admission{}
	for rows.Next() {
		var r Admission
		var granted int64
		if err := rows.Scan(&r.AID, &r.Label, &r.Grant, &granted, &r.CreatedAt); err != nil {
			return a, err
		}
		r.Granted = granted != 0
		a.Admitted = append(a.Admitted, r)
	}
	return a, rows.Err()
}

// ---- per account ----

// ProbationUntil is when aid's probation ends, and whether it is on
// probation now. SS reads it for the first-contact send bucket (PAY-A4).
func (s *Store) ProbationUntil(aid string) (time.Time, bool) {
	var pu sql.NullInt64
	if err := s.db.QueryRow(`SELECT probation_until FROM agent WHERE aid=?`, aid).Scan(&pu); err != nil || !pu.Valid {
		return time.Time{}, false
	}
	until := time.UnixMilli(pu.Int64)
	return until, s.now().Before(until)
}

// trialState is what /register and /agents/{aid}/balance say about an
// account's probation and trial credit: both fields only for an account
// that came in through a window or open registration and whose trial is
// pending or paid; nothing for one an operator admitted.
type trialState struct {
	ProbationUntil *uint64
	Trial          string
}

func (s *Store) trialStateOf(aid string) (trialState, error) {
	return trialStateOf(s.db, aid)
}

func trialStateOf(q rowQuerier, aid string) (trialState, error) {
	var via, trial string
	var pu sql.NullInt64
	err := q.QueryRow(`SELECT admitted_via, probation_until, trial FROM agent WHERE aid=?`, aid).Scan(&via, &pu, &trial)
	if errors.Is(err, sql.ErrNoRows) {
		return trialState{}, nil
	}
	if err != nil {
		return trialState{}, err
	}
	if via == viaList || (trial != trialPending && trial != trialGranted) {
		return trialState{}, nil
	}
	st := trialState{Trial: trial}
	if pu.Valid && pu.Int64 >= 0 {
		v := uint64(pu.Int64)
		st.ProbationUntil = &v
	}
	return st, nil
}

// maybeGrantTrial pays aid's trial credit when its probation is over and the
// credit is still pending, as long as today's budget for the network of ip
// and for the hub allows it (PAY-A5). Called after every signed request that
// authenticated (authRegistered). Otherwise the credit stays pending and the
// next request tries again. It reports whether it paid.
func (s *Store) maybeGrantTrial(aid string, ip net.IP) (bool, error) {
	now := s.now()
	var trial string
	var pu sql.NullInt64
	err := s.db.QueryRow(`SELECT probation_until, trial FROM agent WHERE aid=?`, aid).Scan(&pu, &trial)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if trial != trialPending || !pu.Valid || now.UnixMilli() < pu.Int64 {
		return false, nil
	}
	hold, ok := s.gate().reserveTrial(ip, now)
	if !ok {
		return false, nil
	}
	paid := false
	defer func() {
		if !paid {
			s.gate().release(hold)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	r, err := tx.Exec(`UPDATE agent SET trial=? WHERE aid=? AND trial=? AND probation_until IS NOT NULL AND probation_until <= ?`,
		trialGranted, aid, trialPending, now.UnixMilli())
	if err != nil {
		return false, err
	}
	if n, err := r.RowsAffected(); err != nil || n == 0 {
		return false, err
	}
	if err := s.issueTx(tx, aid, TrialCredits, reasonTrialCredit); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	paid = true
	return true, nil
}

// ---- the inactive sweep (PAY-A6) ----

// SweepInactive deregisters every account that registered at least
// InactiveAfter ago, never collected its mail, holds no credit and has never
// been reviewed. Its admission stays: an admitted AID that comes back
// registers again, with a key history that extends the one it left with.
// It also deletes sign-up windows closed for more than 30 days. It returns
// the number of accounts deregistered.
func (s *Store) SweepInactive() (int, error) {
	now := s.now()
	cutoff := now.Add(-InactiveAfter).UTC().Format(time.RFC3339)
	const inactive = `a.registered_at <= ? AND a.last_seen_at IS NULL
	    AND COALESCE((SELECT credits FROM credit_balance b WHERE b.aid = a.aid), 0) = 0
	    AND NOT EXISTS (SELECT 1 FROM review r WHERE r.subject_aid = a.aid)
	    AND NOT EXISTS (SELECT 1 FROM fed_review f WHERE f.subject_aid = a.aid)`
	rows, err := s.db.Query(`SELECT a.aid FROM agent a WHERE `+inactive+` ORDER BY a.aid`, cutoff)
	if err != nil {
		return 0, err
	}
	var aids []string
	for rows.Next() {
		var aid string
		if err := rows.Scan(&aid); err != nil {
			rows.Close()
			return 0, err
		}
		aids = append(aids, aid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, aid := range aids {
		done, err := s.sweepOne(aid, cutoff, inactive)
		if err != nil {
			return n, err
		}
		if done {
			n++
			s.afterDereg(aid)
		}
	}
	if _, err := s.db.Exec(`DELETE FROM admission_window WHERE closes_at < ?`,
		now.Add(-windowKeep).UnixMilli()); err != nil {
		return n, err
	}
	return n, nil
}

// sweepOne deregisters aid if it is still inactive, checked again in the
// transaction that deregisters it (it may have polled since the scan).
func (s *Store) sweepOne(aid, cutoff, inactive string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var one int
	err = tx.QueryRow(`SELECT 1 FROM agent a WHERE a.aid = ? AND `+inactive, aid, cutoff).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := DeregisterTx(tx, aid, DeregInactive); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// RunAdmissionJanitor runs SweepInactive at start and then every interval
// until ctx ends.
func (s *Store) RunAdmissionJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, err := s.SweepInactive(); err != nil {
			log.Printf("hub: inactive sweep: %v", err)
		} else if n > 0 {
			log.Printf("hub: inactive sweep deregistered %d account(s) that never collected mail in %s", n, InactiveAfter)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---- the gate's process memory ----

// admissionGate is the part of admission that lives only in this process:
// the proof-of-work key, today's per-network counters of open registrations
// and of trial grants, and the window places taken by registrations still
// in progress.
type admissionGate struct {
	mu     sync.Mutex
	powKey []byte
	bits   int // regpow.Bits; lowered only by tests
	day    int64
	dayKey []byte
	signup map[[16]byte]int
	trials map[[16]byte]int
	trialN int
	// window counts the places of each window held by registrations that
	// passed the gate and have not committed or failed yet.
	window map[int64]int
}

func newAdmissionGate() *admissionGate {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(fmt.Sprintf("hub: no randomness for the proof-of-work key: %v", err))
	}
	return &admissionGate{powKey: k, bits: regpow.Bits, day: -1, window: map[int64]int{}}
}

// gate is the store's process memory of admission.
func (s *Store) gate() *admissionGate {
	s.gateOnce.Do(func() { s.admGate = newAdmissionGate() })
	return s.admGate
}

// rollDay starts a new UTC day's counters under a new key. Caller holds mu.
func (g *admissionGate) rollDay(now time.Time) {
	day := now.UnixMilli() / 86_400_000
	if day == g.day {
		return
	}
	g.day = day
	g.dayKey = make([]byte, 32)
	if _, err := rand.Read(g.dayKey); err != nil {
		panic(fmt.Sprintf("hub: no randomness for the day key: %v", err))
	}
	g.signup = map[[16]byte]int{}
	g.trials = map[[16]byte]int{}
	g.trialN = 0
}

// netKey is the counter key of one network level of ip: the first 16 bytes
// of HMAC-SHA256(day key, kind ‖ level ‖ prefix). The address itself is never
// kept.
func (g *admissionGate) netKey(kind string, l netLimit, ip net.IP) ([16]byte, bool) {
	var key [16]byte
	var addr net.IP
	if v4 := ip.To4(); v4 != nil {
		if l.v6 {
			return key, false
		}
		addr = v4.Mask(net.CIDRMask(l.bits, 32))
	} else if v6 := ip.To16(); v6 != nil {
		if !l.v6 {
			return key, false
		}
		addr = v6.Mask(net.CIDRMask(l.bits, 128))
	} else {
		return key, false
	}
	m := hmac.New(sha256.New, g.dayKey)
	var lvl [2]byte
	lvl[0] = byte(l.bits)
	if l.v6 {
		lvl[1] = 6
	} else {
		lvl[1] = 4
	}
	m.Write([]byte(kind))
	m.Write(lvl[:])
	m.Write(addr)
	copy(key[:], m.Sum(nil))
	return key, true
}

// gateHold is what a reservation took, to give back if the registration (or
// the trial grant) does not go through.
type gateHold struct {
	day    int64
	signup [][16]byte
	trials [][16]byte
	trialN bool
	window int64
}

// untilTomorrow is the wait until the next UTC midnight, when the counters
// start again.
func untilTomorrow(now time.Time) time.Duration {
	ms := now.UnixMilli()
	next := (ms/86_400_000 + 1) * 86_400_000
	return time.Duration(next-ms) * time.Millisecond
}

// reserveSignup takes one place of today's open-registration quota at every
// level of ip's network, or none when any level is full.
func (g *admissionGate) reserveSignup(ip net.IP, now time.Time) (*gateHold, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rollDay(now)
	if ip == nil {
		ip = net.IPv4zero
	}
	h := &gateHold{day: g.day}
	for _, l := range signupQuota {
		k, ok := g.netKey("signup", l, ip)
		if !ok {
			continue
		}
		if g.signup[k] >= l.max {
			return nil, false
		}
		h.signup = append(h.signup, k)
	}
	for _, k := range h.signup {
		g.signup[k]++
	}
	return h, true
}

// reserveTrial takes one trial grant of today's budget of ip's network and of
// the hub, or none when any is spent.
func (g *admissionGate) reserveTrial(ip net.IP, now time.Time) (*gateHold, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rollDay(now)
	if ip == nil {
		ip = net.IPv4zero
	}
	if g.trialN >= trialBudgetHub {
		return nil, false
	}
	h := &gateHold{day: g.day, trialN: true}
	for _, l := range trialBudget {
		k, ok := g.netKey("trial", l, ip)
		if !ok {
			continue
		}
		if g.trials[k] >= l.max {
			return nil, false
		}
		h.trials = append(h.trials, k)
	}
	for _, k := range h.trials {
		g.trials[k]++
	}
	g.trialN++
	return h, true
}

// reserveWindow takes one place of window w for a registration in progress,
// or none when the window is full counting the places already taken.
func (g *admissionGate) reserveWindow(w Window) (*gateHold, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if w.Used+g.window[w.ID] >= w.Max {
		return nil, false
	}
	g.window[w.ID]++
	return &gateHold{window: w.ID, day: -1}, true
}

// release gives a hold back: a registration that failed after the gate, a
// trial grant that did not commit. A day's counters are only given back on
// that day; a window place is given back whenever (once the registration
// committed, the window's used column holds it instead).
func (g *admissionGate) release(h *gateHold) {
	if h == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if h.window != 0 {
		if g.window[h.window]--; g.window[h.window] <= 0 {
			delete(g.window, h.window)
		}
	}
	if h.day != g.day {
		return
	}
	for _, k := range h.signup {
		if g.signup[k]--; g.signup[k] <= 0 {
			delete(g.signup, k)
		}
	}
	for _, k := range h.trials {
		if g.trials[k]--; g.trials[k] <= 0 {
			delete(g.trials, k)
		}
	}
	if h.trialN && g.trialN > 0 {
		g.trialN--
	}
}

// committed turns a window hold into nothing to give back: the window's
// used column now holds the place. The per-network counters stay taken.
func (g *admissionGate) committed(h *gateHold) {
	if h == nil || h.window == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.window[h.window]--; g.window[h.window] <= 0 {
		delete(g.window, h.window)
	}
}

// powSeed is the seed of the hour of now.
func (g *admissionGate) powSeed(hour uint64) [32]byte {
	return regpow.Seed(g.powKey, hour)
}

// challenge is the pow_required challenge for now: the seed of this hour,
// the bits, and when the seed stops being accepted.
func (g *admissionGate) challenge(now time.Time) map[string]any {
	h := regpow.Hour(uint64(now.UnixMilli()))
	seed := g.powSeed(h)
	return map[string]any{
		"seed":      base64.RawURLEncoding.EncodeToString(seed[:]),
		"bits":      g.bits,
		"not_after": regpow.NotAfter(h),
	}
}

// checkPow reports whether a proof of work is good: its seed is this hour's
// or the previous hour's, and it hashes (once) to enough leading zero bits
// for this hub and aid (PAY-A2).
func (g *admissionGate) checkPow(hubAID, aid string, seed, nonce []byte, now time.Time) bool {
	if len(seed) != 32 {
		return false
	}
	var s [32]byte
	copy(s[:], seed)
	h := regpow.Hour(uint64(now.UnixMilli()))
	cur := g.powSeed(h)
	ok := hmac.Equal(s[:], cur[:])
	if !ok && h > 0 {
		prev := g.powSeed(h - 1)
		ok = hmac.Equal(s[:], prev[:])
	}
	return ok && regpow.Check(hubAID, aid, s, nonce, g.bits)
}

// writeAdmissionTx writes, beside a new agent row, how it came in (PAY-A1
// step 10): through the list (no probation; the list's grant is paid now,
// once), or through a window or open registration (probation for 72 hours,
// trial credit pending; a window place is taken for good).
func (s *Store) writeAdmissionTx(tx *sql.Tx, aid string, adm *admissionWrite) error {
	switch adm.via {
	case viaList:
		var one int
		err := tx.QueryRow(`SELECT 1 FROM admitted WHERE aid=?`, aid).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			// Revoked while this registration was in progress.
			return errNotAdmitted
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE agent SET admitted_via=?, probation_until=NULL, trial=? WHERE aid=?`,
			viaList, trialNone, aid); err != nil {
			return err
		}
		_, err = s.payListGrantTx(tx, aid)
		return err
	case viaWindow, viaOpen:
		if adm.via == viaWindow {
			r, err := tx.Exec(`UPDATE admission_window SET used = used + 1 WHERE id=? AND used < max`, adm.window)
			if err != nil {
				return err
			}
			if n, err := r.RowsAffected(); err != nil {
				return err
			} else if n == 0 {
				return errWindowFilled
			}
		}
		_, err := tx.Exec(`UPDATE agent SET admitted_via=?, probation_until=?, trial=? WHERE aid=?`,
			adm.via, adm.now.Add(ProbationPeriod).UnixMilli(), trialPending, aid)
		return err
	}
	return fmt.Errorf("hub: unknown admission route %q", adm.via)
}

// isAdmitted reports whether aid is on the admission list.
func (s *Store) isAdmitted(aid string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM admitted WHERE aid=?`, aid).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
