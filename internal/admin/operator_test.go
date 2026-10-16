package admin

// The operator plane of 0.3.0 (hub-payment-privacy §4.2.9 PAY-O3 to PAY-O6, §3.4a): a delete is
// revoking the admission and deregistering through aghub.DeregisterTx; nothing writes an old key
// history back; the views follow the v2 schema and name no reviewer; and a hub data directory or an
// admin.db this release does not open is refused and left as it was.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// openRaw opens dir/hub.db for a test to read, as another process would.
func openRaw(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// count is the number of rows of table where col = v.
func count(t *testing.T, db *sql.DB, table, col, v string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE `+col+` = ?`, v).Scan(&n); err != nil {
		t.Fatalf("%s: %v", table, err)
	}
	return n
}

// admitted registers c at h through its admission list, as an operator's anet-hub admit and the
// agent's own hub-register do.
func (h *testHub) admitted(c *identity.Controller) {
	h.t.Helper()
	if _, err := h.store.Admit(c.AID(), 0, "", false); err != nil {
		h.t.Fatal(err)
	}
	if code, out := h.register(c, nil); code != http.StatusOK {
		h.t.Fatalf("registering %s: %d %s", c.AID(), code, out["_raw"])
	}
}

// TestAdminDeleteWritesDepartedKEL (PAY-O3, M-PAY-43): the operator's delete leaves the agent's
// whole key history as its tombstone and takes away everything it was reachable by: the registry
// row and directory entry, the admission, the capability index, the key set, the mailbox and the
// witness notice; it leaves the hub process the dereg_event that ends its sessions, and the balance
// on the ledger. Another agent is untouched.
func TestAdminDeleteWritesDepartedKEL(t *testing.T) {
	h := newTestHub(t, aghub.AdmissionClosed)
	c := newTestAgent(t)
	rotate(t, c) // icp and two rots
	h.admitted(c)
	kid := publishTestKeys(t, h.store, c)
	if _, err := h.store.QueueEnvelope(c.AID(), sealedForTest(t, c.AID(), kid, "mail for the deleted")); err != nil {
		t.Fatal(err)
	}
	if notice, why, err := h.store.NoticeFor(c.AID()); err != nil || notice == nil {
		t.Fatalf("setup: no witness notice (%q, %v)", why, err)
	}
	if err := h.store.GrantCredit(c.AID(), 7, "test"); err != nil {
		t.Fatal(err)
	}
	other := newTestAgent(t)
	h.admitted(other)
	registered := kelBytes(t, c)

	handler, _, _ := h.admin()
	w, out := doReq(t, handler, "DELETE", "/admin/api/agents/"+c.AID(), "test-token", nil)
	if w.Code != http.StatusOK || out["ok"] != true {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if out["balance"] != float64(7) ||
		out["message"] != Sentence("admin.deleted", map[string]string{"aid": c.AID(), "n": "7"}) {
		t.Errorf("the answer %v, want balance 7 and admin.deleted", out)
	}

	db := openRaw(t, h.dir)
	var tomb []byte
	if err := db.QueryRow(`SELECT kel FROM departed_kel WHERE aid = ?`, c.AID()).Scan(&tomb); err != nil {
		t.Fatalf("no tombstone: %v", err)
	}
	if !bytes.Equal(tomb, registered) {
		t.Errorf("the tombstone is not the whole key history the agent registered with")
	}
	for _, x := range []struct{ table, col string }{
		{"agent", "aid"}, {"admitted", "aid"}, {"notice_cache", "aid"}, {"relay_message", "to_aid"},
		{"agent_keys", "aid"}, {"agent_cap", "aid"},
	} {
		if n := count(t, db, x.table, x.col, c.AID()); n != 0 {
			t.Errorf("%s still has %d row(s) of the deleted agent", x.table, n)
		}
	}
	if n := count(t, db, "dereg_event", "aid", c.AID()); n != 1 {
		t.Errorf("dereg_event has %d row(s) for the hub process, want 1", n)
	}
	if bal, err := h.store.Balance(c.AID()); err != nil || bal != 7 {
		t.Errorf("the balance after the delete: %d %v, want 7 on the ledger", bal, err)
	}
	if !h.store.KnowsAgent(other.AID()) || count(t, db, "admitted", "aid", other.AID()) != 1 {
		t.Error("the delete touched another agent")
	}
	// Deleting it again: it is not registered, and nothing changes.
	if w, _ := doReq(t, handler, "DELETE", "/admin/api/agents/"+c.AID(), "test-token", nil); w.Code != http.StatusNotFound {
		t.Errorf("deleting a deleted agent: %d, want 404", w.Code)
	}
}

// TestAdminForkReregisterRefused (PAY-O3, PAY-O4, J-PAY-14 at the hub, M-PAY-45): after the operator
// deletes an agent whose key history is icp and two rots, whoever holds its data directory (the key
// the last rot revealed) can sign another second rot. Registering with that fork is refused, on a
// closed hub first for want of an admission and, once the operator admits the AID again, as a fork;
// on an open hub, with a good proof of work, as a fork. The hub never signs a witness notice for
// the fork. The agent itself comes back with its own key history. The removed restore route
// answers 404 and puts nothing back.
func TestAdminForkReregisterRefused(t *testing.T) {
	for _, mode := range []string{aghub.AdmissionClosed, aghub.AdmissionOpen} {
		t.Run(mode, func(t *testing.T) {
			h := newTestHub(t, mode)
			c := newTestAgent(t) // icp, and the rot naming the witness
			mid, err := c.Export()
			if err != nil {
				t.Fatal(err)
			}
			rotate(t, c) // the second rot: its key is the one in the data directory
			h.admitted(c)

			handler, _, _ := h.admin()
			w, out := doReq(t, handler, "DELETE", "/admin/api/agents/"+c.AID(), "test-token", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("delete: %d %s", w.Code, w.Body.String())
			}
			key := "admin.deleted"
			if mode == aghub.AdmissionOpen {
				key = "admin.deleted.open" // deleting is not a ban there
			}
			if want := Sentence(key, map[string]string{"aid": c.AID(), "n": "0"}); out["message"] != want {
				t.Errorf("the answer says %q, want %s: %q", out["message"], key, want)
			}

			// Nothing writes the old key history back.
			if w, _ := doReq(t, handler, "POST", "/admin/api/deleted/"+c.AID()+"/restore", "test-token", nil); w.Code != http.StatusNotFound {
				t.Errorf("the restore route answered %d, want 404", w.Code)
			}
			if h.store.KnowsAgent(c.AID()) {
				t.Fatal("the deleted agent is registered again without registering")
			}

			fork, err := identity.Restore(mid)
			if err != nil {
				t.Fatal(err)
			}
			rotate(t, fork)
			if fork.AID() != c.AID() || tipID(fork) == tipID(c) {
				t.Fatal("setup: the fork is not another second rot of the same identity")
			}
			if mode == aghub.AdmissionClosed {
				if code, out := h.register(fork, nil); code != http.StatusForbidden || out["reason"] != "admission_required" {
					t.Fatalf("the fork before the admit: %d %s, want 403 admission_required", code, out["_raw"])
				}
				if _, err := h.store.Admit(c.AID(), 0, "", false); err != nil { // anet-hub admit
					t.Fatal(err)
				}
				if code, out := h.register(fork, nil); code != http.StatusConflict || out["reason"] != "kel_fork" {
					t.Fatalf("the fork after the admit: %d %s, want 409 kel_fork", code, out["_raw"])
				}
			}
			var pow map[string]any
			if mode == aghub.AdmissionOpen {
				pow = h.pow(fork)
				if code, out := h.register(fork, pow); code != http.StatusConflict || out["reason"] != "kel_fork" {
					t.Fatalf("the fork with a proof of work: %d %s, want 409 kel_fork", code, out["_raw"])
				}
			}
			for _, head := range h.noticeHeads() {
				if head == tipID(fork) {
					t.Fatal("the hub signed a witness notice for the fork")
				}
			}

			code, out := h.register(c, pow)
			if code != http.StatusOK {
				t.Fatalf("the agent's own key history: %d %s", code, out["_raw"])
			}
			s, _ := out["key_state_notice"].(string)
			raw, err := wire3.DecodeB64URL("key_state_notice", s)
			if err != nil || s == "" {
				t.Fatalf("the return carries no witness notice: %s", out["_raw"])
			}
			if body, _, err := identity.DecodeNotice(raw); err != nil || body.Head != tipID(c) {
				t.Errorf("the notice the hub signed on the return: %+v %v, want the agent's own tip", body, err)
			}
			for _, head := range h.noticeHeads() {
				if head == tipID(fork) {
					t.Fatal("the hub signed a witness notice for the fork")
				}
			}
		})
	}
}

// TestAdminDeleteReachesTheHubProcess (PAY-O2): the admin plane is another process; the hub process
// learns of its delete from dereg_event within two seconds and drops what it holds in memory for
// the AID (its sessions, SSR-H9).
func TestAdminDeleteReachesTheHubProcess(t *testing.T) {
	h := newTestHub(t, aghub.AdmissionClosed)
	c := newTestAgent(t)
	h.admitted(c)
	got := make(chan string, 8)
	h.store.OnDeregistered(func(aid string) { got <- aid })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.store.StartDeregWatcher(ctx); err != nil {
		t.Fatal(err)
	}
	handler, _, _ := h.admin()
	start := time.Now()
	if w, _ := doReq(t, handler, "DELETE", "/admin/api/agents/"+c.AID(), "test-token", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	select {
	case aid := <-got:
		if aid != c.AID() {
			t.Errorf("the hub process dropped %s, want %s", aid, c.AID())
		}
	case <-time.After(2*time.Second - time.Since(start)):
		t.Fatal("the hub process did not learn of the delete within 2 seconds")
	}
}

// The operator's delete overwrites the mail it drops (secure_delete on the admin plane's handle, as
// on the hub's): once the log is checkpointed, neither hub.db nor its log holds the envelope.
func TestAdminDeleteLeavesNoMailInTheFile(t *testing.T) {
	const canary = "canary-pay16-deleted-mail-7c1e"
	h := newTestHub(t, aghub.AdmissionClosed)
	c := newTestAgent(t)
	h.admitted(c)
	kid := publishTestKeys(t, h.store, c)
	if _, err := h.store.QueueEnvelope(c.AID(), sealedForTest(t, c.AID(), kid, canary)); err != nil {
		t.Fatal(err)
	}
	handler, _, _ := h.admin()
	if w, _ := doReq(t, handler, "DELETE", "/admin/api/agents/"+c.AID(), "test-token", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	db := openRaw(t, h.dir)
	var busy, logged, moved int
	if err := db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logged, &moved); err != nil || busy != 0 {
		t.Fatalf("checkpoint: busy %d, %v", busy, err)
	}
	for _, f := range []string{"hub.db", "hub.db-wal"} {
		b, _ := os.ReadFile(filepath.Join(h.dir, f))
		if bytes.Contains(b, []byte(canary)) {
			t.Errorf("%s still holds the dropped envelope", f)
		}
	}
}

// TestAdminReviewViewFields (PAY-O5, SI-48): a review as the operator sees it is exactly {ix_commit,
// subject_aid, rating, comment, receipt_cid, created_day}: no reviewer, no interaction id, no time
// finer than a day; an agent's page lists the reviews it received and nothing about reviews it
// wrote; the registry rows carry no price, no reviews written and no per-agent mailbox figure, and
// state the registration to the day.
func TestAdminReviewViewFields(t *testing.T) {
	srv, _, _, provAID, reqAID := newTestServer(t)
	h := srv.Handler()
	wantKeys := "comment,created_day,ix_commit,rating,receipt_cid,subject_aid"
	keysOf := func(m map[string]any) string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return strings.Join(ks, ",")
	}
	_, out := doReq(t, h, "GET", "/admin/api/reviews", "test-token", nil)
	revs, _ := out["reviews"].([]any)
	if len(revs) != 1 {
		t.Fatalf("reviews: %v", out)
	}
	rv := revs[0].(map[string]any)
	if got := keysOf(rv); got != wantKeys {
		t.Errorf("a review has the members %s, want %s", got, wantKeys)
	}
	if rv["ix_commit"] != base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x1c}, 32)) ||
		rv["created_day"] != float64(20001) || rv["subject_aid"] != provAID || rv["rating"] != float64(4) {
		t.Errorf("the review %v", rv)
	}

	_, out = doReq(t, h, "GET", "/admin/api/agents/"+provAID, "test-token", nil)
	if own, _ := out["reviews"].([]any); len(own) != 1 || keysOf(own[0].(map[string]any)) != wantKeys {
		t.Errorf("the subject's page lists %v", out["reviews"])
	}
	ag, _ := out["agent"].(map[string]any)
	for _, k := range []string{"pricing", "reviews_written", "mailbox_backlog", "reviewer_aid", "interaction_id"} {
		if _, ok := ag[k]; ok {
			t.Errorf("the agent view still has %q", k)
		}
	}
	if s, _ := ag["registered_at"].(string); !strings.HasSuffix(s, "T00:00:00Z") {
		t.Errorf("registered_at %q is not a day", s)
	}
	// The requester wrote the review; its page lists none.
	if _, out = doReq(t, h, "GET", "/admin/api/agents/"+reqAID, "test-token", nil); len(out["reviews"].([]any)) != 0 {
		t.Errorf("the reviewer's page lists %v", out["reviews"])
	}
	w, _ := doReq(t, h, "GET", "/admin/api/agents", "test-token", nil)
	for _, k := range []string{`"reviews_written"`, `"mailbox_backlog"`, `"pricing"`} {
		if strings.Contains(w.Body.String(), k) {
			t.Errorf("the agent list has %s", k)
		}
	}
}

// An agent is listed by the registry's rule (SSR-H18): a capability or profile text, and a key set.
func TestAdminListsByTheRegistryRule(t *testing.T) {
	h := newTestHub(t, aghub.AdmissionClosed)
	c := newTestAgent(t)
	h.admitted(c) // registered with a capability, no key set yet
	_, _, hub := h.admin()
	v, err := hub.Agent(c.AID())
	if err != nil || v.Listed {
		t.Fatalf("an agent without a key set: %+v %v, want not listed", v, err)
	}
	if tot, err := hub.Totals(); err != nil || tot.Agents != 1 || tot.Listed != 0 {
		t.Errorf("totals without a key set %+v %v, want 1 agent and none listed", tot, err)
	}
	publishTestKeys(t, h.store, c)
	if v, err = hub.Agent(c.AID()); err != nil || !v.Listed {
		t.Fatalf("with a key set: %+v %v, want listed", v, err)
	}
	if tot, err := hub.Totals(); err != nil || tot.Agents != 1 || tot.Listed != 1 {
		t.Errorf("totals %+v %v", tot, err)
	}
	if _, err := hub.Agent("bafyunknown"); !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("an unknown agent: %v", err)
	}
}

// TestDeletedAsAnAdmitFile (PAY-O4): ?format=admit is the deleted AIDs, each once, newest first, one
// per line, and anet-hub admit --file takes it as it is; the agents then come back by registering
// with their own key histories. The JSON listing has only {aid, deleted_at, actor}.
func TestDeletedAsAnAdmitFile(t *testing.T) {
	h := newTestHub(t, aghub.AdmissionClosed)
	a, b := newTestAgent(t), newTestAgent(t)
	h.admitted(a)
	h.admitted(b)
	handler, _, _ := h.admin()
	del := func(c *identity.Controller) {
		t.Helper()
		if w, _ := doReq(t, handler, "DELETE", "/admin/api/agents/"+c.AID(), "test-token", nil); w.Code != http.StatusOK {
			t.Fatalf("delete: %d %s", w.Code, w.Body.String())
		}
	}
	del(a)
	del(b)
	h.admitted(a) // back, and deleted again: listed once
	del(a)

	r := doRaw(t, handler, "GET", "/admin/api/deleted?format=admit")
	if r.Code != http.StatusOK || !strings.HasPrefix(r.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("format=admit: %d %s", r.Code, r.Header().Get("Content-Type"))
	}
	if want := a.AID() + "\n" + b.AID() + "\n"; r.Body.String() != want {
		t.Errorf("format=admit:\n%s\nwant\n%s", r.Body.String(), want)
	}
	path := filepath.Join(t.TempDir(), "deleted.txt")
	if err := os.WriteFile(path, r.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, reg, err := h.store.AdmitFile(path, 0, "", false); err != nil || n != 2 || reg != 0 {
		t.Fatalf("anet-hub admit --file: %d admitted, %d registered, %v", n, reg, err)
	}
	for _, c := range []*identity.Controller{a, b} {
		if code, out := h.register(c, nil); code != http.StatusOK {
			t.Errorf("%s did not come back: %d %s", c.AID(), code, out["_raw"])
		}
	}
	if r := doRaw(t, handler, "GET", "/admin/api/deleted?format=csv"); r.Code != http.StatusBadRequest {
		t.Errorf("an unknown format: %d", r.Code)
	}
}

// doRaw is an authenticated request whose answer is not read as JSON.
func doRaw(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	w, _ := doReq(t, h, method, path, "test-token", nil)
	return w
}

// TestAdminRefusesOldHubData (core CORE-V4, PAY-3 handoff): a hub data directory of 0.2 (tables and
// no version, or a version below 3) is aghub.ErrHubDataV02, one a newer anet-hub wrote
// aghub.ErrHubDataTooNew; either way OpenHubDB leaves every file of the directory as it was (no
// -wal, no -shm, not a byte changed). An empty hub.db is not hub data.
func TestAdminRefusesOldHubData(t *testing.T) {
	for _, c := range []struct {
		name    string
		version int
		want    error
	}{
		{"no version", 0, aghub.ErrHubDataV02}, {"version 1", 1, aghub.ErrHubDataV02},
		{"version 2", 2, aghub.ErrHubDataV02},
		{"version 4", aghub.SchemaVersion + 1, aghub.ErrHubDataTooNew}, {"version 99", 99, aghub.ErrHubDataTooNew},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeOldHubDB(t, dir, c.version)
			before := snapshotDir(t, dir)
			hub, err := OpenHubDB(dir)
			if hub != nil {
				hub.Close()
			}
			if !errors.Is(err, c.want) {
				t.Errorf("OpenHubDB: %v, want %v", err, c.want)
			}
			if after := snapshotDir(t, dir); after != before {
				t.Errorf("the refused directory changed:\n%s\n%s", before, after)
			}
		})
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hub.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHubDB(dir); !errors.Is(err, ErrNoHubData) {
		t.Errorf("an empty hub.db: %v, want ErrNoHubData", err)
	}
}

// writeOldHubDB makes dir/hub.db with an agent table at user_version version, as a hub of another
// release left it.
func writeOldHubDB(t *testing.T, dir string, version int) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE agent (aid TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', caps TEXT NOT NULL DEFAULT '[]',
		   pricing TEXT NOT NULL DEFAULT '', kel BLOB NOT NULL, registered_at TEXT NOT NULL)`,
		`INSERT INTO agent(aid, kel, registered_at) VALUES('bafyold', x'00', '2026-07-19T00:00:00Z')`,
		`PRAGMA user_version = ` + strconv.Itoa(version),
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

// snapshotDir is every file in dir with its size and hash.
func snapshotDir(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, fmt.Sprintf("%s %d %x", e.Name(), len(b), sha256.Sum256(b)))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// TestAdminRefusesAnOldAdminDB (§3.4a): an admin.db whose deleted_agent still has the row column of
// the removed restore path is ErrAdminDBTooOld, and the file is left as it was; a new directory
// opens.
func TestAdminRefusesAnOldAdminDB(t *testing.T) {
	dir := t.TempDir()
	writeOldAdminDB(t, dir)
	before := snapshotDir(t, dir)
	if s, err := OpenStore(dir); !errors.Is(err, ErrAdminDBTooOld) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("an old admin.db: %v, want ErrAdminDBTooOld", err)
	}
	if after := snapshotDir(t, dir); after != before {
		t.Errorf("the refused admin.db changed:\n%s\n%s", before, after)
	}
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

// writeOldAdminDB makes dir/admin.db as the earlier release left it: deleted_agent with the archived
// row (and its key history) of a deleted agent.
func writeOldAdminDB(t *testing.T, dir string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE deleted_agent (aid TEXT NOT NULL, row TEXT NOT NULL, deleted_at TEXT NOT NULL,
		   actor TEXT NOT NULL DEFAULT 'admin')`,
		`INSERT INTO deleted_agent VALUES('bafyold', '{"aid":"bafyold","kel_b64":"AA=="}', '2026-07-20T00:00:00Z', 'admin')`,
		`CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL DEFAULT 'admin',
		   action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTheOperatorSurfaceNamesNoReviewer (SI-48 at the operator plane; J-PAY-10's admin scan, PAY-O6):
// after a reviewer uploads a review of a provider, the operator reads the reviews, the overview and
// the provider's page, takes a snapshot and moderates the provider. None of those answers, and
// neither admin.db nor its log, holds the reviewer's AID, the interaction id or a millisecond time
// from the upload.
func TestTheOperatorSurfaceNamesNoReviewer(t *testing.T) {
	h := newTestHub(t, aghub.AdmissionClosed)
	prov, reviewer := newTestAgent(t), newTestAgent(t)
	h.admitted(prov)
	h.admitted(reviewer)
	publishTestKeys(t, h.store, prov)
	ix := "ix-pay16-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	start := time.Now().UnixMilli()
	uploadTestReview(t, h, prov, reviewer, ix)
	end := time.Now().UnixMilli()

	adminDir := t.TempDir()
	store, err := OpenStore(adminDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	hub, err := OpenHubDB(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	srv := NewServer(store, hub, nil, NewVecClient(""), "test-token", "/admin")
	handler := srv.Handler()
	srv.takeSnapshot()
	if w, _ := doReq(t, handler, "POST", "/admin/api/agents/"+prov.AID()+"/moderate", "test-token",
		map[string]string{"status": "flagged", "note": "checked"}); w.Code != http.StatusOK {
		t.Fatalf("moderate: %d", w.Code)
	}
	ms := regexp.MustCompile(`\d{13}`)
	check := func(what string, b []byte) {
		t.Helper()
		if bytes.Contains(b, []byte(reviewer.AID())) {
			t.Errorf("%s names the reviewer", what)
		}
		if bytes.Contains(b, []byte(ix)) {
			t.Errorf("%s holds the interaction id", what)
		}
		for _, m := range ms.FindAll(b, -1) {
			if v, err := strconv.ParseInt(string(m), 10, 64); err == nil && v >= start-1000 && v <= end+1000 {
				t.Errorf("%s states the millisecond time %s", what, m)
			}
		}
	}
	reviewed := false
	for _, path := range []string{"/admin/api/reviews", "/admin/api/overview", "/admin/api/agents/" + prov.AID()} {
		w, _ := doReq(t, handler, "GET", path, "test-token", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", path, w.Code)
		}
		reviewed = reviewed || strings.Contains(w.Body.String(), `"rating":5`)
		check("GET "+path, w.Body.Bytes())
	}
	if !reviewed {
		t.Fatal("no answer shows the review: nothing was checked")
	}
	for _, f := range []string{"admin.db", "admin.db-wal"} {
		b, _ := os.ReadFile(filepath.Join(adminDir, f))
		check(f, b)
	}
}

// uploadTestReview has reviewer upload its review (rating 5) of the task prov completed today for
// the interaction ix, as its daemon does: evidence v2, POST /reviews signed by the reviewer.
func uploadTestReview(t *testing.T, h *testHub, prov, reviewer *identity.Controller, ix string) {
	t.Helper()
	rsalt := make([]byte, evidence.RSaltSize)
	if _, err := rand.Read(rsalt); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ixCommit, err := evidence.IXCommit(ix, "nonce-"+ix)
	if err != nil {
		t.Fatal(err)
	}
	reqCommit, err := evidence.RequesterCommit(reviewer.AID(), rsalt)
	if err != nil {
		t.Fatal(err)
	}
	reqCID, _ := anetcid.Sum([]byte("the request of " + ix))
	resCID, _ := anetcid.Sum([]byte("the result of " + ix))
	today := uint64(time.Now().UTC().Unix() / 86400)
	rb := evidence.ReceiptBody{IXCommit: ixCommit, RequesterCommit: reqCommit, ReviewKey: pub,
		Provider: prov.AID(), RequestCID: reqCID, ResultCID: resCID, CompletedDay: today}
	rw, err := rb.Sign(prov)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := rw.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	receiptCID, err := rw.CID()
	if err != nil {
		t.Fatal(err)
	}
	vb := evidence.ReviewBody{Subject: prov.AID(), Rating: 5, CreatedDay: today, ReceiptCID: receiptCID,
		Comment: "fine work"}
	vw, err := vb.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	review, err := vw.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"receipt": wire3.EncodeB64URL(receipt), "review": wire3.EncodeB64URL(review), "rsalt": wire3.EncodeB64URL(rsalt)})
	if code, out := h.signed(reviewer, relayauth.ActionReview, http.MethodPost, "/reviews", body); code != http.StatusOK {
		t.Fatalf("uploading the review: %d %s", code, out["_raw"])
	}
}

// A registered key history that does not extend the tombstone this hub keeps for the AID cannot
// become its tombstone (PAY-O1 step 2): the operator's delete answers 409 and changes nothing. The
// agent is still registered and admitted, the tombstone is the one it was, the hub process has no
// deregistration to act on, and the console records no delete and no moderation mark.
func TestAdminDeleteRefusesAShrinkingTombstone(t *testing.T) {
	h := newTestHub(t, aghub.AdmissionClosed)
	c := newTestAgent(t) // icp and one rot
	h.admitted(c)
	exported, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	longer, err := identity.Restore(exported)
	if err != nil {
		t.Fatal(err)
	}
	rotate(t, longer) // icp and two rots: what the registered history does not extend
	tomb := kelBytes(t, longer)
	db := openRaw(t, h.dir)
	if _, err := db.Exec(`INSERT INTO departed_kel(aid, kel, at) VALUES(?,?,?)`,
		c.AID(), tomb, "2026-10-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	handler, store, _ := h.admin()
	w, _ := doReq(t, handler, "DELETE", "/admin/api/agents/"+c.AID(), "test-token", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("delete: %d %s, want 409", w.Code, w.Body.String())
	}
	for _, x := range []struct {
		table string
		want  int
	}{{"agent", 1}, {"admitted", 1}, {"dereg_event", 0}} {
		if n := count(t, db, x.table, "aid", c.AID()); n != x.want {
			t.Errorf("%s has %d row(s) of the agent after the refused delete, want %d", x.table, n, x.want)
		}
	}
	var held []byte
	if err := db.QueryRow(`SELECT kel FROM departed_kel WHERE aid = ?`, c.AID()).Scan(&held); err != nil ||
		!bytes.Equal(held, tomb) {
		t.Errorf("the tombstone changed (%v)", err)
	}
	if d, err := store.DeletedAgents(10); err != nil || len(d) != 0 {
		t.Errorf("the refused delete is recorded: %v %v", d, err)
	}
	if mods, err := store.Moderations(); err != nil || mods[c.AID()].Status != "" {
		t.Errorf("the refused delete left a moderation mark: %+v %v", mods[c.AID()], err)
	}
}

// A hub.db whose schema is still only in its write-ahead log (a hub that is writing it now, with no
// checkpoint yet) looks empty to aghub.CheckData, which reads the file alone. OpenHubDB reads it
// again through the log and refuses another release's data all the same.
func TestAdminRefusesOldHubDataSeenThroughTheLog(t *testing.T) {
	for _, c := range []struct {
		name    string
		version int
		want    error
	}{{"version 2", 2, aghub.ErrHubDataV02}, {"version 4", aghub.SchemaVersion + 1, aghub.ErrHubDataTooNew}} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writer, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+
				"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { writer.Close() })
			writer.SetMaxOpenConns(1) // the one connection stays open, so the log is not checkpointed
			for _, q := range []string{
				`CREATE TABLE agent (aid TEXT PRIMARY KEY, kel BLOB NOT NULL)`,
				`PRAGMA user_version = ` + strconv.Itoa(c.version),
			} {
				if _, err := writer.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			if err := aghub.CheckData(dir); err != nil {
				t.Fatalf("setup: the file alone already shows the version (%v)", err)
			}
			hub, err := OpenHubDB(dir)
			if hub != nil {
				hub.Close()
			}
			if !errors.Is(err, c.want) {
				t.Errorf("OpenHubDB: %v, want %v", err, c.want)
			}
		})
	}
}

// Reviews are listed newest day first and, within a day, by ix_commit (PAY-O5), not in the order
// they were stored: that order would tell the operator more than the day (SI-48).
func TestAdminReviewsNewestDayFirst(t *testing.T) {
	dir, provAID, _ := buildHubDB(t) // one review: ix_commit 1c…, day 20001
	hs, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range []struct {
		ix  byte
		day uint64
	}{{0x2b, 20001}, {0x0a, 20001}, {0x05, 19999}, {0x3f, 20003}} {
		if err := hs.StoreReview(aghub.StoredReview{IXCommit: bytes.Repeat([]byte{r.ix}, 32), Subject: provAID,
			Tag: bytes.Repeat([]byte{byte(0x40 + i)}, 16), TagKeyID: 1, Rating: 3,
			ReceiptCID: fmt.Sprintf("bafy-receipt-order-%d", i), CompletedDay: r.day, CreatedDay: r.day, StoredDay: r.day},
			[]byte{0xa0}, []byte{0xa0}, []byte{0xa0}); err != nil {
			t.Fatal(err)
		}
	}
	hs.Close()
	hub, err := OpenHubDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	want := []byte{0x3f, 0x0a, 0x1c, 0x2b, 0x05}
	order := func(rs []HubReview) []byte {
		var out []byte
		for _, r := range rs {
			ix, _ := base64.RawURLEncoding.DecodeString(r.IXCommit)
			if len(ix) > 0 {
				out = append(out, ix[0])
			}
		}
		return out
	}
	recent, err := hub.RecentReviews(0)
	if err != nil || !bytes.Equal(order(recent), want) {
		t.Errorf("RecentReviews in the order %x (%v), want %x", order(recent), err, want)
	}
	of, err := hub.ReviewsOf(provAID, 0)
	if err != nil || !bytes.Equal(order(of), want) {
		t.Errorf("ReviewsOf in the order %x (%v), want %x", order(of), err, want)
	}
}

// The operator's delete takes the write lock when its transaction begins (BEGIN IMMEDIATE, PAY-O3),
// as the hub's own transactions do. Begun deferred, it reads first and then has to become a writer;
// when the hub process writes in between (it writes on every poll), SQLite refuses the upgrade at
// once, without waiting, and the delete fails with "database is locked".
func TestAdminDeleteBesideABusyHub(t *testing.T) {
	dir := t.TempDir()
	hs, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var aids []string
	for i := 0; i < 100; i++ {
		c, err := identitytest.Hub()
		if err != nil {
			t.Fatal(err)
		}
		kel, err := identity.MarshalKEL(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		if err := hs.PutAgent(c.AID(), "busy", []string{"x.y"}, kel); err != nil {
			t.Fatal(err)
		}
		aids = append(aids, c.AID())
	}
	hs.Close()
	hub, err := OpenHubDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	busy, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busy.SetMaxOpenConns(1)
	stop, done, writing := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_, err := busy.Exec(`INSERT INTO hub_meta(key, value) VALUES('test-busy', ?)
			    ON CONFLICT(key) DO UPDATE SET value = excluded.value`, strconv.Itoa(i))
			if i == 0 {
				if err != nil {
					t.Errorf("the hub's writes: %v", err)
				}
				close(writing)
			}
			// SQLite does not queue writers fairly: a writer that never pauses can keep another out for
			// longer than any busy timeout on a machine with few cores. A hub pauses between writes.
			time.Sleep(time.Millisecond)
		}
	}()
	<-writing
	for _, aid := range aids {
		if _, err := hub.DeleteAgent(aid); err != nil {
			t.Errorf("deleting %s beside a busy hub: %v", aid, err)
		}
	}
	close(stop)
	<-done
}
