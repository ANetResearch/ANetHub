package aghub_test

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// A hub restored from a backup, or whose database went back to an older copy
// (KEL §4.2 H-20 to H-23): no witness notice for any AID until its node
// sends a newer key history, or signs with the key the hub holds as current
// once RestoreQuarantine has passed since the hub came back; each AID on its
// own.

// backupOf writes a copy of the store's database to path, as
// deploy/hub-db-roll.sh makes one (VACUUM INTO), but without leaving out any
// table: Restore must not count on the copy having been made by the script.
func backupOf(t *testing.T, store *aghub.Store, path string) {
	t.Helper()
	if _, err := store.DBForTest().Exec(`VACUUM INTO ?`, path); err != nil {
		t.Fatal(err)
	}
}

// serveAt starts a hub on the data directory dir, as anet-hub does after a
// restore: the store, the hub identity of the test hubs, and the start of
// serving (BeginServing, which the hub process runs before renewing notices).
func serveAt(t *testing.T, dir string) (*httptest.Server, *aghub.Store) {
	t.Helper()
	srv, store, _ := newHubAt(t, dir)
	serverOf(t, srv).SetKELPushRateForTest(1e9, 1<<30)
	return srv, store
}

// stop closes a test hub before its data directory is restored under it.
func stop(srv *httptest.Server, store *aghub.Store) {
	srv.Close()
	store.Close()
}

// joinWithKeys registers c at srv and publishes a key set, so that it has a
// directory entry and the hub keeps a notice for it.
func joinWithKeys(t *testing.T, srv *httptest.Server, c *identity.Controller, name string) {
	t.Helper()
	register(t, srv, c, name, []string{"work.do"})
	raw, _ := mintKeySet(t, c, uint64(time.Now().UnixMilli()))
	if code, b := publishKeys(t, srv, c, raw); code != http.StatusOK {
		t.Fatalf("keys of %s: %d %s", name, code, b)
	}
}

// noticeAnswerOf is what a poll signed by c answers about c's own notice.
func noticeAnswerOf(t *testing.T, srv *httptest.Server, c *identity.Controller) (notice []byte, why string) {
	t.Helper()
	out := pollAnswer(t, srv, c)
	if out.KeyStateNotice != "" {
		raw, err := base64.RawURLEncoding.DecodeString(out.KeyStateNotice)
		if err != nil {
			t.Fatal(err)
		}
		return raw, ""
	}
	return nil, out.KeyStateNoticeError
}

// listedNotice is the notice /agents lists for aid ("" for none), and
// whether aid is listed at all.
func listedNotice(t *testing.T, srv *httptest.Server, aid string) (string, bool) {
	t.Helper()
	for _, a := range getAgentsList(t, srv) {
		if a.AID == aid {
			return a.KeyStateNotice, true
		}
	}
	return "", false
}

// TestRestoreQuarantinesPerAID (KEL H-20, H-22, M15, J6): a hub whose
// agents A and B have notices is backed up; A rotates (its old key is a
// thief's now); the hub is restored from the backup, so A's old key is the
// tip again here. Then, per AID:
//
//   - nothing restored states a tip: no cached notice, no directory entry
//     carrying one, none in the listings;
//   - the thief, signing with A's old key, which the restored hub holds as
//     current, gets no notice: quarantine;
//   - A's node pushes its newer key history: A is released at once, and its
//     notice states the new tip; the thief's key is retired again;
//   - B, whose history is what the hub holds, stays in quarantine through
//     its requests until RestoreQuarantine has passed since the hub came
//     back, and is released by the first request it signs after that;
//   - C, an AID the restored hub held nothing for, registers in the
//     quarantine and is held like B: a first registration is not a longer
//     history than one held.
func TestRestoreQuarantinesPerAID(t *testing.T) {
	dir := t.TempDir()
	srv, store := serveAt(t, dir)
	a, b := twoAgents(t)
	joinWithKeys(t, srv, a, "A")
	joinWithKeys(t, srv, b, "B")
	for _, c := range []*identity.Controller{a, b} {
		if n, why := noticeAnswerOf(t, srv, c); n == nil {
			t.Fatalf("setup: no notice before the backup (%s)", why)
		}
		if lookUpInBucket(t, srv, c.AID(), "") == nil {
			t.Fatal("setup: no directory entry")
		}
	}
	backup := filepath.Join(t.TempDir(), "hub-backup-20261004.db")
	backupOf(t, store, backup)

	// A's key leaks; A rotates away from it and the hub takes the rotation.
	thief := snapshotOf(t, a)
	if err := identitytest.Rotate(a, tsAfter(a)); err != nil {
		t.Fatal(err)
	}
	if code, body := pushKEL(t, srv, a.AID(), kelURL(t, a)); code != http.StatusOK {
		t.Fatalf("push: %d %s", code, body)
	}
	stop(srv, store)

	res, err := aghub.Restore(dir, backup, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Agents != 2 {
		t.Errorf("restored %d agents, want 2", res.Agents)
	}
	srv, store = serveAt(t, dir)
	clock := time.Now()
	store.SetClockForTest(func() time.Time { return clock })

	// Restored and not yet served: nothing that states a tip is served.
	for _, c := range []*identity.Controller{a, b} {
		if _, _, _, _, ok := store.NoticeRowForTest(c.AID()); ok {
			t.Errorf("a notice of %s came back with the backup", c.AID())
		}
		if e := lookUpInBucket(t, srv, c.AID(), ""); e != nil && len(e.Notice) != 0 {
			t.Errorf("the directory entry of %s carries a notice from the backup", c.AID())
		}
	}
	if err := store.BeginServing(); err != nil {
		t.Fatal(err)
	}
	if st, err := store.Quarantine(); err != nil || !st.Active || st.Held != 2 || st.ServingSince.IsZero() {
		t.Fatalf("quarantine %+v (%v), want active, serving, 2 held", st, err)
	}
	// Filed again, without a notice.
	for _, c := range []*identity.Controller{a, b} {
		e := lookUpInBucket(t, srv, c.AID(), "")
		if e == nil {
			t.Fatalf("%s has no directory entry once the hub serves", c.AID())
		}
		if len(e.Notice) != 0 {
			t.Errorf("the directory entry of %s carries a notice in quarantine", c.AID())
		}
		if n, listed := listedNotice(t, srv, c.AID()); !listed || n != "" {
			t.Errorf("/agents: %s listed %v with notice %q, want listed without one", c.AID(), listed, n)
		}
	}

	// The thief signs with the key the restored hub holds as A's current
	// one: authenticated, and still no notice.
	if n, why := noticeAnswerOf(t, srv, thief); n != nil || why != aghub.NoticeErrQuarantine {
		t.Fatalf("the thief's poll: notice %x, error %q; want none, quarantine", n, why)
	}
	if n, why := noticeAnswerOf(t, srv, b); n != nil || why != aghub.NoticeErrQuarantine {
		t.Fatalf("B's poll: notice %x, error %q; want none, quarantine", n, why)
	}

	// A's node pushes its newer key history: released at once.
	if code, body := pushKEL(t, srv, a.AID(), kelURL(t, a)); code != http.StatusOK {
		t.Fatalf("A's push: %d %s", code, body)
	}
	n, why := noticeAnswerOf(t, srv, a)
	if n == nil {
		t.Fatalf("A after pushing its newer history: no notice (%s)", why)
	}
	if body := checkNoticeAt(t, srv, n, a, clock); body.Seq != uint64(len(a.KEL())-1) {
		t.Errorf("A's notice states seq %d, want the new tip %d", body.Seq, len(a.KEL())-1)
	}
	if code, out := signedDo(t, srv, thief, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{}); code != http.StatusUnauthorized || !reasonIs(out, "key_retired") {
		t.Errorf("the thief after A's push: %d %s, want 401 key_retired", code, out)
	}
	// The rotation took A's key set (KEL H-2); with the one its node signs
	// under the new key, A is filed with the notice again.
	raw, _ := mintKeySet(t, a, uint64(time.Now().UnixMilli()))
	if code, out := publishKeys(t, srv, a, raw); code != http.StatusOK {
		t.Fatalf("A's new key set: %d %s", code, out)
	}
	if e := lookUpInBucket(t, srv, a.AID(), ""); e == nil || len(e.Notice) == 0 {
		t.Errorf("A's directory entry once A is released: %+v, want one with its notice", e)
	}

	// C joins the restored hub in the quarantine.
	c, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	code, body := registerCode(t, srv, c, "C", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"key_state_notice_error":"quarantine"`) {
		t.Fatalf("C's registration in the quarantine: %d %s", code, body)
	}

	// B's requests release it only once the wait is over.
	clock = clock.Add(aghub.RestoreQuarantine - time.Millisecond)
	if n, why := noticeAnswerOf(t, srv, b); n != nil || why != aghub.NoticeErrQuarantine {
		t.Fatalf("B a millisecond before the wait is over: notice %x, error %q", n, why)
	}
	if st, _ := store.Quarantine(); st.Held != 2 {
		t.Errorf("held %d, want B and C", st.Held)
	}
	clock = clock.Add(time.Millisecond)
	// The wait is over, and B and C are still held: the record stays.
	if err := store.EndQuarantineWhenNoneHeld(); err != nil {
		t.Fatal(err)
	}
	if st, _ := store.Quarantine(); !st.Active || st.Held != 2 {
		t.Fatalf("the quarantine record once the wait is over, B and C held: %+v", st)
	}
	if n, why := noticeAnswerOf(t, srv, b); n == nil {
		t.Fatalf("B once the wait is over: no notice (%s)", why)
	} else {
		checkNoticeAt(t, srv, n, b, clock)
	}
	if n, why := noticeAnswerOf(t, srv, c); n == nil {
		t.Fatalf("C once the wait is over: no notice (%s)", why)
	}
	// A release is one registration's: C leaves and joins again, and is
	// released again by its registration, the wait being over.
	if _, err := store.Deregister(c.AID(), aghub.DeregSelf); err != nil {
		t.Fatal(err)
	}
	if code, body := registerCode(t, srv, c, "C", nil); code != http.StatusOK ||
		!strings.Contains(string(body), `"key_state_notice":"`) {
		t.Fatalf("C registering again after the wait: %d %s, want its notice", code, body)
	}
	if st, _ := store.Quarantine(); !st.Active || st.Held != 0 {
		t.Errorf("after every agent was released: %+v; the record stays until closed, holding none", st)
	}
	// Nobody held and the wait over: the record closes, and a newcomer is
	// not held.
	if err := store.EndQuarantineWhenNoneHeld(); err != nil {
		t.Fatal(err)
	}
	if st, _ := store.Quarantine(); st.Active {
		t.Errorf("the record did not close: %+v", st)
	}
	d, err := aghub.NewAgentWitnessedBy(identitytest.Witness, clock) // its witness event on the hub's clock
	if err != nil {
		t.Fatal(err)
	}
	if code, body := registerCode(t, srv, d, "D", nil); code != http.StatusOK ||
		!strings.Contains(string(body), `"key_state_notice":"`) {
		t.Errorf("a newcomer after the quarantine closed: %d %s, want its notice", code, body)
	}
}

// KEL H-20: the hub that comes back starts the clock of the quarantine, not
// the restore: an operator who restores and starts the hub an hour later
// still gives the nodes RestoreQuarantine to send their newer histories.
func TestRestoreQuarantineCountsFromServing(t *testing.T) {
	dir := t.TempDir()
	srv, store := serveAt(t, dir)
	a, _ := twoAgents(t)
	joinWithKeys(t, srv, a, "A")
	backup := filepath.Join(t.TempDir(), "b.db")
	backupOf(t, store, backup)
	stop(srv, store)
	if _, err := aghub.Restore(dir, backup, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	srv, store = serveAt(t, dir)
	if n, why := noticeAnswerOf(t, srv, a); n != nil || why != aghub.NoticeErrQuarantine {
		t.Fatalf("before the hub serves: notice %x, %q", n, why)
	}
	if err := store.BeginServing(); err != nil {
		t.Fatal(err)
	}
	if n, why := noticeAnswerOf(t, srv, a); n != nil || why != aghub.NoticeErrQuarantine {
		t.Fatalf("two hours after the restore, just after the hub came back: notice %x, %q", n, why)
	}
	// A second start does not start the clock again.
	st, _ := store.Quarantine()
	stop(srv, store)
	srv, store = serveAt(t, dir)
	if err := store.BeginServing(); err != nil {
		t.Fatal(err)
	}
	if again, _ := store.Quarantine(); !again.ServingSince.Equal(st.ServingSince) {
		t.Errorf("a restart moved serving_since from %v to %v", st.ServingSince, again.ServingSince)
	}
}

// KEL H-21, M15: every key-history change counts in the database and in
// kel_hwm beside it; a start that finds the database below kel_hwm (an older
// copy put back by hand) begins the same quarantine, once; a database at or
// above it, none.
func TestKELHighWaterDetectsRollbackAtStart(t *testing.T) {
	dir := t.TempDir()
	srv, store := serveAt(t, dir)
	a, b := twoAgents(t)
	joinWithKeys(t, srv, a, "A")
	older := filepath.Join(t.TempDir(), "older.db")
	backupOf(t, store, older)
	thief := snapshotOf(t, a)
	if err := identitytest.Rotate(a, tsAfter(a)); err != nil {
		t.Fatal(err)
	}
	if code, body := pushKEL(t, srv, a.AID(), kelURL(t, a)); code != http.StatusOK {
		t.Fatalf("push: %d %s", code, body)
	}
	joinWithKeys(t, srv, b, "B")
	stop(srv, store)
	hwm, err := os.ReadFile(filepath.Join(dir, "kel_hwm"))
	if err != nil || string(hwm) != "3\n" {
		t.Fatalf("kel_hwm after a registration, a rotation and a registration: %q (%v), want 3", hwm, err)
	}

	// A start on the database as it is: no quarantine.
	srv, store = serveAt(t, dir)
	if st, err := store.Quarantine(); err != nil || st.Active {
		t.Fatalf("an unchanged database: %+v (%v)", st, err)
	}
	stop(srv, store)

	// The older copy, put in place by hand.
	for _, side := range []string{"-wal", "-shm"} {
		os.Remove(filepath.Join(dir, "hub.db"+side))
	}
	copyFile(t, older, filepath.Join(dir, "hub.db"))
	srv, store = serveAt(t, dir)
	st, err := store.Quarantine()
	if err != nil || !st.Active || st.Why != "rollback" {
		t.Fatalf("an older database: %+v (%v), want a rollback quarantine", st, err)
	}
	if err := store.BeginServing(); err != nil {
		t.Fatal(err)
	}
	if n, why := noticeAnswerOf(t, srv, thief); n != nil || why != aghub.NoticeErrQuarantine {
		t.Fatalf("A's old key on the older database: notice %x, %q", n, why)
	}
	stop(srv, store)
	// Found once: the next start does not begin it again.
	srv, store = serveAt(t, dir)
	if again, _ := store.Quarantine(); !again.BeganAt.Equal(st.BeganAt) {
		t.Errorf("a second start began another quarantine (%v, then %v)", st.BeganAt, again.BeganAt)
	}
	stop(srv, store)

	// A kel_hwm that is not a count is not trusted to be low.
	other := t.TempDir()
	s0, err := aghub.Open(other)
	if err != nil {
		t.Fatal(err)
	}
	s0.Close()
	if err := os.WriteFile(filepath.Join(other, "kel_hwm"), []byte("lots\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s1, err := aghub.Open(other)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	if st, _ := s1.Quarantine(); !st.Active {
		t.Error("an unreadable kel_hwm began no quarantine")
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// KEL H-21: what counts as a change of the key histories a hub holds — a
// first registration, a longer history (registered or pushed), a
// deregistration's tombstone — and what does not: registering again with the
// same history.
func TestKELChangesAreCounted(t *testing.T) {
	dir := t.TempDir()
	srv, store := serveAt(t, dir)
	read := func() string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, "kel_hwm"))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	if got := read(); got != "0" {
		t.Fatalf("a new hub: kel_hwm %q, want 0", got)
	}
	a, b := twoAgents(t)
	register(t, srv, a, "A", nil)
	register(t, srv, a, "A", nil) // the same history again
	if got := read(); got != "1" {
		t.Errorf("after one registration and the same again: %q, want 1", got)
	}
	if err := identitytest.Rotate(a, tsAfter(a)); err != nil {
		t.Fatal(err)
	}
	register(t, srv, a, "A", nil)
	register(t, srv, b, "B", nil)
	if err := identitytest.Rotate(b, tsAfter(b)); err != nil {
		t.Fatal(err)
	}
	if code, body := pushKEL(t, srv, b.AID(), kelURL(t, b)); code != http.StatusOK {
		t.Fatalf("push: %d %s", code, body)
	}
	if got := read(); got != "4" {
		t.Errorf("after a rotation registered, a registration and a rotation pushed: %q, want 4", got)
	}
	if _, err := store.Deregister(a.AID(), aghub.DeregSelf); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != "5" {
		t.Errorf("after a deregistration: %q, want 5", got)
	}
}

// KEL H-23: Restore refuses what is not a whole backup of a hub database of
// this release, and changes nothing in the data directory when it does: not
// the database, not kel_hwm, no file left beside them.
func TestRestoreRefusesWhatIsNotABackup(t *testing.T) {
	dir := t.TempDir()
	srv, store := serveAt(t, dir)
	a, _ := twoAgents(t)
	joinWithKeys(t, srv, a, "A")
	good := filepath.Join(t.TempDir(), "good.db")
	backupOf(t, store, good)
	stop(srv, store)
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	damaged := append([]byte(nil), raw...)
	for i := 4096; i < len(damaged) && i < 4096*3; i++ {
		damaged[i] ^= 0x5a
	}
	cases := map[string][]byte{
		"empty":       {},
		"not sqlite":  []byte("hub backup, honest"),
		"damaged":     damaged,
		"truncated":   raw[:len(raw)/2],
		"no database": nil, // a directory, below
	}
	tooNew := filepath.Join(src, "too-new.db")
	copyFile(t, good, tooNew)
	setUserVersion(t, tooNew, aghub.SchemaVersion+1)
	old := filepath.Join(src, "v02.db")
	copyFile(t, good, old)
	setUserVersion(t, old, aghub.SchemaVersion-1)

	before := snapshotDir(t, dir)
	check := func(name, path string, want error) {
		t.Helper()
		_, err := aghub.Restore(dir, path, time.Now())
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
		if after := snapshotDir(t, dir); !sameSnapshot(before, after) {
			t.Errorf("%s: the data directory changed", name)
		}
	}
	for name, b := range cases {
		p := filepath.Join(src, strings.ReplaceAll(name, " ", "-"))
		if b == nil {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		check(name, p, aghub.ErrNotABackup)
	}
	check("missing", filepath.Join(src, "missing.db"), aghub.ErrNotABackup)
	check("0.2", old, aghub.ErrNotABackup)
	check("newer", tooNew, aghub.ErrBackupTooNew)
}

// KEL H-23: a restore needs the hub stopped. While another process holds the
// data directory's lock (the hub serving from it), Restore refuses and
// changes nothing.
func TestRestoreRefusesWhileTheHubRuns(t *testing.T) {
	dir := t.TempDir()
	srv, store := serveAt(t, dir)
	a, _ := twoAgents(t)
	joinWithKeys(t, srv, a, "A")
	backup := filepath.Join(t.TempDir(), "b.db")
	backupOf(t, store, backup)
	stop(srv, store)
	release := aghub.HoldDataDirForTest(t, dir)
	before := snapshotDir(t, dir)
	if _, err := aghub.Restore(dir, backup, time.Now()); !errors.Is(err, aghub.ErrHubRunning) {
		t.Fatalf("restore while the lock is held: %v, want ErrHubRunning", err)
	}
	if !sameSnapshot(before, snapshotDir(t, dir)) {
		t.Error("the data directory changed")
	}
	release()
	if _, err := aghub.Restore(dir, backup, time.Now()); err != nil {
		t.Fatalf("restore once the lock is free: %v", err)
	}
}

// KEL H-23, core §2.16: a restored hub holds what a backup holds, whatever
// copy it came from. The tables no backup holds come back empty (no envelope
// a sender has since been told was delivered, no notice signed before the
// copy), and the rest comes back as it was: the ledger, the revocations, the
// first verifications of payments.
func TestRestoreClearsWhatNoBackupHolds(t *testing.T) {
	dir := t.TempDir()
	srv, store := serveAt(t, dir)
	a, b := twoAgents(t)
	joinWithKeys(t, srv, a, "A")
	joinWithKeys(t, srv, b, "B")
	if code, body, _ := relaySend(t, srv, b, a.AID(), testEnvelope(t, a.AID(), nil)); code != http.StatusOK {
		t.Fatalf("send: %d %s", code, body)
	}
	pollAnswer(t, srv, a) // a notice in the cache
	balA := balanceOf(t, srv, a.AID())
	backup := filepath.Join(t.TempDir(), "raw-copy.db")
	backupOf(t, store, backup)
	stop(srv, store)
	if _, err := aghub.Restore(dir, backup, time.Now()); err != nil {
		t.Fatal(err)
	}
	srv, store = serveAt(t, dir)
	db := store.DBForTest()
	for _, table := range []string{"relay_message", "relay_redelivery", "dereg_event", "notice_cache"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s holds %d rows after the restore", table, n)
		}
	}
	if got := balanceOf(t, srv, a.AID()); got != balA {
		t.Errorf("A's balance %d after the restore, want %d", got, balA)
	}
	if !store.KnowsAgent(a.AID()) || !store.KnowsAgent(b.AID()) {
		t.Error("an agent did not come back")
	}
	// Nothing of the restore is left beside hub.db.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".restore") || strings.Contains(e.Name(), ".tmp") {
			t.Errorf("left behind: %s", e.Name())
		}
	}
}

// setUserVersion makes the database at path say it is of schema v.
func setUserVersion(t *testing.T, path string, v int) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v)); err != nil {
		t.Fatal(err)
	}
}

// snapshotDir is every file in dir with its contents.
func snapshotDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[p] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameSnapshot(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}
