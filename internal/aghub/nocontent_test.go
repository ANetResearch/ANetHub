package aghub_test

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	_ "modernc.org/sqlite"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// Tests for A2A-DESIGN §9: the hub holds no interaction content. Reviews
// carry no goal or deliverable, the review tables have no content columns,
// guest mode and completed_task are gone, and a store from before the
// change loses its content when it is opened.

// hubInDir is a hub whose data directory the test can search.
func hubInDir(t *testing.T) (*httptest.Server, *aghub.Store, *aghub.Server, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	s := aghub.NewServer(store)
	s.SetHubAID(id.AID)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); store.Close() })
	testHubAID.Store(srv.URL, id.AID)
	testHubStores.Store(srv.URL, store)
	testHubCtrl.Store(srv.URL, id.Ctrl)
	testHubServers.Store(srv.URL, s)
	return srv, store, s, dir
}

// filesContaining reports every file under dir whose bytes contain needle.
func filesContaining(t *testing.T, dir string, needle []byte) []string {
	t.Helper()
	var hits []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(b, needle) {
			hits = append(hits, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

// A review is served with the receipt's anchors, a content binding stated
// as UNVERIFIED, and no content fields at all.
func TestAReviewIsServedWithoutContent(t *testing.T) {
	srv, store, _, _ := hubInDir(t)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	code, b := post(t, srv.URL+"/reviews", makeEvidence(t, prov, req, "ix-nocontent-1", 4, ""))
	if code != 200 {
		t.Fatalf("upload: %d %s", code, b)
	}
	if !strings.Contains(string(b), `"content_binding":"UNVERIFIED"`) {
		t.Errorf("the upload answer does not state the content binding: %s", b)
	}
	code, body := getJSON(t, srv.URL+"/agents/"+prov.AID())
	if code != 200 {
		t.Fatalf("agent: %d %s", code, body)
	}
	var got struct {
		Reviews []map[string]any `json:"reviews"`
	}
	if err := json.Unmarshal(body, &got); err != nil || len(got.Reviews) != 1 {
		t.Fatalf("reviews: %v %s", err, body)
	}
	r := got.Reviews[0]
	for _, k := range []string{"goal", "deliverable", "request_doc"} {
		if _, ok := r[k]; ok {
			t.Errorf("the review carries %q: %s", k, body)
		}
	}
	if r["content_binding"] != aghub.ContentBindingUnverified {
		t.Errorf("content_binding = %v, want %q", r["content_binding"], aghub.ContentBindingUnverified)
	}
	if r["request_cid"] == "" || r["result_cid"] == "" {
		t.Errorf("the receipt anchors are missing: %s", body)
	}

	// The federation stream carries the two signed objects and the KELs,
	// nothing else. The provider is hub-local by default and is opted in
	// so that its review is streamed.
	setVisibility(t, srv, prov, aghub.VisibilityFederated)
	revs, _, err := store.ReviewsSince(0, 0)
	if err != nil || len(revs) != 1 {
		t.Fatalf("stream: %v %d", err, len(revs))
	}
	raw, err := json.Marshal(revs[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"request_doc", "deliverable"} {
		if _, ok := fields[k]; ok {
			t.Errorf("the federation stream carries %q: %s", k, raw)
		}
	}
}

// A client that still sends the content with its review is refused, and
// nothing is stored for that review.
func TestAReviewUploadCarryingContentIsRefused(t *testing.T) {
	srv, _, _, dir := hubInDir(t)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	canary := []byte("canary-review-content-7f3a9c")
	for _, field := range []string{"request_doc", "deliverable"} {
		body := makeEvidence(t, prov, req, "ix-carrying-"+field, 5, "")
		body[field] = base64.StdEncoding.EncodeToString(canary)
		code, b := post(t, srv.URL+"/reviews", body)
		if code != http.StatusBadRequest || !strings.Contains(string(b), "does not accept interaction content") {
			t.Errorf("a review carrying %s: %d %s, want 400 naming the refusal", field, code, b)
		}
	}
	code, body := getJSON(t, srv.URL+"/agents/"+prov.AID())
	if code != 200 {
		t.Fatalf("agent: %d %s", code, body)
	}
	if strings.Contains(string(body), `"interaction_id"`) {
		t.Errorf("a refused review was stored: %s", body)
	}
	if hits := filesContaining(t, dir, canary); len(hits) > 0 {
		t.Errorf("content sent with a refused review is on disk in %v", hits)
	}
}

// A comment is at most MaxReviewCommentRunes code points, counted as
// characters rather than bytes, on a local upload and on a federated
// review alike.
func TestAReviewCommentIsBounded(t *testing.T) {
	srv, store, _, _ := hubInDir(t)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	setVisibility(t, srv, prov, aghub.VisibilityFederated)

	// 280 three-byte characters: 840 bytes, 280 characters. Accepted.
	atLimit := strings.Repeat("评", aghub.MaxReviewCommentRunes)
	if code, b := post(t, srv.URL+"/reviews",
		makeEvidenceWithComment(t, prov, req, "ix-comment-280", 5, "", atLimit)); code != 200 {
		t.Fatalf("a %d-character comment was refused: %d %s", aghub.MaxReviewCommentRunes, code, b)
	}
	over := atLimit + "x"
	code, b := post(t, srv.URL+"/reviews", makeEvidenceWithComment(t, prov, req, "ix-comment-281", 5, "", over))
	if code != http.StatusBadRequest || !strings.Contains(string(b), "at most 280") {
		t.Errorf("a %d-character comment: %d %s, want 400", aghub.MaxReviewCommentRunes+1, code, b)
	}

	// The federated path applies the same bound. A review with an
	// over-long comment is built on a second hub, where uploads are bounded
	// too, by admitting it directly into that hub's store.
	revs, _, err := store.ReviewsSince(0, 0)
	if err != nil || len(revs) != 1 {
		t.Fatalf("stream: %v %d", err, len(revs))
	}
	_, peer, _, _ := hubInDir(t)
	if err := peer.AdmitFedReview("did:anet:home", revs[0]); err != nil {
		t.Fatalf("a federated review with a %d-character comment was refused: %v",
			aghub.MaxReviewCommentRunes, err)
	}
	long := federatedReview(t, "ix-fed-comment-281", over)
	if err := peer.AdmitFedReview("did:anet:home", long); err == nil ||
		!strings.Contains(err.Error(), "at most 280") {
		t.Errorf("a federated review with a %d-character comment: %v, want refused",
			aghub.MaxReviewCommentRunes+1, err)
	}
}

// federatedReview is a genuine FedReview between two fresh identities,
// as a peer hub would stream it, with the given comment.
func federatedReview(t *testing.T, ix, comment string) aghub.FedReview {
	t.Helper()
	prov, req := twoAgents(t)
	ev := makeEvidenceWithComment(t, prov, req, ix, 4, "", comment)
	return aghub.FedReview{
		Receipt: ev["receipt"], Review: ev["review"],
		ProviderKEL: kelB64(t, prov), ReviewerKEL: kelB64(t, req), FedSeq: 1,
	}
}

func kelB64(t *testing.T, c *identity.Controller) string {
	t.Helper()
	b, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// A peer on an earlier version still sends request_doc and deliverable in
// its review stream. The receiving hub decodes into a FedReview that has no
// such fields and verifies the interlock with nil content.
//
// Before this change the empty strings a transitional peer sends decoded to
// non-nil empty byte slices, VerifyInterlock hashed them, the hash of zero
// bytes matched no receipt, and every such review was refused (R09 §5 item
// 9). A peer that sends real content has it ignored: not verified, not
// stored.
func TestAFederatedReviewIsAdmittedWhateverContentFieldsItCarries(t *testing.T) {
	_, peer, _, dir := hubInDir(t)
	dirSeam := aghub.FedDirectory{S: peer}
	canary := []byte("canary-federated-content-41b2")
	for i, tc := range []struct {
		name        string
		requestDoc  string
		deliverable string
	}{
		{"empty strings", "", ""},
		{"content that matches no anchor", base64.StdEncoding.EncodeToString(canary),
			base64.StdEncoding.EncodeToString(canary)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fr := federatedReview(t, "ix-fed-legacy-"+string(rune('a'+i)), "fine")
			raw, err := json.Marshal(map[string]any{
				"receipt": fr.Receipt, "review": fr.Review,
				"request_doc": tc.requestDoc, "deliverable": tc.deliverable,
				"provider_kel": fr.ProviderKEL, "reviewer_kel": fr.ReviewerKEL, "fed_seq": 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := dirSeam.AdmitFedReview("did:anet:old-peer", raw); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
	if hits := filesContaining(t, dir, canary); len(hits) > 0 {
		t.Errorf("content a peer sent with a review is on disk in %v", hits)
	}
}

// tasks_completed counts distinct valid receipts published through
// reviews, and /stats names the modules the application wired in.
func TestStatsCountPublishedReceiptsAndNameModules(t *testing.T) {
	srv, _, s, _ := hubInDir(t)
	stats := func() aghub.HubStats {
		t.Helper()
		code, b := getJSON(t, srv.URL+"/stats")
		if code != 200 {
			t.Fatalf("stats: %d %s", code, b)
		}
		var st aghub.HubStats
		if err := json.Unmarshal(b, &st); err != nil {
			t.Fatal(err)
		}
		if st.Modules == nil {
			t.Fatalf("modules is absent or null rather than a list: %s", b)
		}
		return st
	}
	if st := stats(); st.TasksCompleted != 0 || len(st.Modules) != 0 {
		t.Fatalf("empty hub: %+v", st)
	}
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	for _, ix := range []string{"ix-stat-1", "ix-stat-2"} {
		if code, b := post(t, srv.URL+"/reviews", makeEvidence(t, prov, req, ix, 5, "")); code != 200 {
			t.Fatalf("upload %s: %d %s", ix, code, b)
		}
	}
	// A refused upload publishes no receipt.
	bad := makeEvidence(t, prov, req, "ix-stat-bad", 5, "")
	bad["deliverable"] = base64.StdEncoding.EncodeToString([]byte("x"))
	if code, _ := post(t, srv.URL+"/reviews", bad); code == 200 {
		t.Fatal("a review carrying content was accepted")
	}
	if st := stats(); st.TasksCompleted != 2 || st.Reviews != 2 {
		t.Errorf("after two published receipts: tasks_completed=%d reviews=%d, want 2/2",
			st.TasksCompleted, st.Reviews)
	}
	s.SetModules([]string{"federation", "taskboard"})
	if st := stats(); strings.Join(st.Modules, ",") != "federation,taskboard" {
		t.Errorf("modules = %v", st.Modules)
	}
}

// Guest mode is removed: the routes are gone and the agent view has no
// quota. A POST to a former guest route reaches only the static-file
// route, which answers GET, so the mux refuses it with 405; 404 would do
// as well. What must not come back is a guest handler's JSON answer.
func TestThereIsNoGuestMode(t *testing.T) {
	srv, _, _, _ := hubInDir(t)
	for _, p := range []string{"/guest/start", "/guest/send", "/guest/poll", "/guest/end"} {
		code, b := post(t, srv.URL+p, map[string]string{"aid": "x"})
		if (code != http.StatusNotFound && code != http.StatusMethodNotAllowed) ||
			strings.Contains(string(b), "enabled") {
			t.Errorf("POST %s: %d %s, want 404 or 405 from the mux", p, code, b)
		}
	}
	prov, _ := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	_, body := getJSON(t, srv.URL+"/agents")
	if strings.Contains(string(body), "guest_quota") {
		t.Errorf("the directory still carries a guest quota: %s", body)
	}
	// The page the hub serves does not offer a guest chat anywhere,
	// including its <meta name="description">, which is what a search
	// engine or a link preview shows.
	code, page := getJSON(t, srv.URL+"/")
	if code != http.StatusOK || !strings.Contains(string(page), "<html") {
		t.Fatalf("GET /: %d, not the web UI", code)
	}
	for _, s := range []string{"访客", "试聊", "/guest/"} {
		if strings.Contains(string(page), s) {
			t.Errorf("the web UI served at / still contains %q", s)
		}
	}
}

// oldSchema is the hub store as it was before this change: guest_quota on
// agent, goal and deliverable on review, the raw content in review_blob,
// and completed_task.
var oldSchema = []string{
	`CREATE TABLE agent (
	   aid TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', caps TEXT NOT NULL DEFAULT '[]',
	   summary TEXT NOT NULL DEFAULT '', readme TEXT NOT NULL DEFAULT '', pricing TEXT NOT NULL DEFAULT '',
	   guest_quota INTEGER NOT NULL DEFAULT 5, kel BLOB NOT NULL, registered_at TEXT NOT NULL)`,
	`CREATE TABLE review (
	   interaction_id TEXT PRIMARY KEY, subject_aid TEXT NOT NULL, reviewer_aid TEXT NOT NULL,
	   rating INTEGER NOT NULL, comment TEXT NOT NULL DEFAULT '', receipt_cid TEXT NOT NULL,
	   goal TEXT NOT NULL DEFAULT '', deliverable TEXT NOT NULL DEFAULT '',
	   request_cid TEXT NOT NULL DEFAULT '', result_cid TEXT NOT NULL DEFAULT '',
	   completed_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, stored_at TEXT NOT NULL)`,
	`CREATE INDEX idx_review_subject ON review(subject_aid)`,
	`CREATE TABLE review_blob (
	   interaction_id TEXT PRIMARY KEY, receipt_raw BLOB NOT NULL, review_raw BLOB NOT NULL,
	   request_doc_raw BLOB NOT NULL, deliverable_raw BLOB NOT NULL)`,
	`CREATE TABLE completed_task (
	   interaction_id TEXT PRIMARY KEY, provider_aid TEXT NOT NULL DEFAULT '',
	   requester_aid TEXT NOT NULL DEFAULT '', completed_at TEXT NOT NULL)`,
}

// Opening a store written before this change removes the content columns,
// the completed_task table and the guest quota, keeps every review and
// agent, and leaves none of the removed bytes in hub.db or hub.db-wal.
// The search runs while the store is still open, because closing the last
// connection checkpoints the WAL by itself and would hide a missing
// checkpoint in the migration.
func TestOpeningAnOldStoreRemovesItsContent(t *testing.T) {
	dir := t.TempDir()
	goal := []byte("canary-old-goal-5d61e0")
	deliv := []byte("canary-old-deliverable-a8c3f2")
	doc := []byte("canary-old-request-doc-0b7e19")
	func() {
		db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=journal_mode(WAL)")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		for _, q := range oldSchema {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		prov, req := twoAgents(t)
		for _, c := range []*identity.Controller{prov, req} {
			kel, err := identity.MarshalKEL(c.KEL())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO agent(aid,name,caps,guest_quota,kel,registered_at)
			     VALUES(?,?,?,?,?,?)`, c.AID(), "old", `["work.do"]`, 5, kel, "2026-08-01T00:00:00Z"); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 50; i++ {
			ix := "ix-old-" + string(rune('A'+i%26)) + string(rune('a'+i/26))
			if _, err := db.Exec(`INSERT INTO review(interaction_id,subject_aid,reviewer_aid,rating,comment,
			     receipt_cid,goal,deliverable,request_cid,result_cid,completed_at,created_at,stored_at)
			     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				ix, prov.AID(), req.AID(), 4, "ok", "bafy-receipt-"+ix, string(goal), string(deliv),
				"bafy-req", "bafy-res", 1000, 2000+i, "2026-08-01T00:00:00Z"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO review_blob VALUES(?,?,?,?,?)`,
				ix, []byte("receipt"), []byte("review"), doc, deliv); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO completed_task VALUES(?,?,?,?)`,
				ix, prov.AID(), req.AID(), "2026-08-01T00:00:00Z"); err != nil {
				t.Fatal(err)
			}
		}
	}()
	for _, c := range [][]byte{goal, deliv, doc} {
		if len(filesContaining(t, dir, c)) == 0 {
			t.Fatalf("the old store does not hold %q; the test would pass for the wrong reason", c)
		}
	}

	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatalf("open an old store: %v", err)
	}
	defer store.Close()

	for _, c := range [][]byte{goal, deliv, doc} {
		if hits := filesContaining(t, dir, c); len(hits) > 0 {
			t.Errorf("%q is still on disk after the migration, in %v", c, hits)
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// VACUUM rebuilt the file: the pages the dropped tables occupied are
	// not kept on the freelist. (secure_delete zeroes them either way; the
	// design asks for the rebuild so the file does not keep their space.)
	var free int
	if err := db.QueryRow(`PRAGMA freelist_count`).Scan(&free); err != nil {
		t.Fatal(err)
	}
	if free != 0 {
		t.Errorf("hub.db has %d free pages after the migration; VACUUM did not run", free)
	}
	columns := func(table string) map[string]bool {
		rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			out[n] = true
		}
		return out
	}
	for table, gone := range map[string][]string{
		"review":      {"goal", "deliverable"},
		"review_blob": {"request_doc_raw", "deliverable_raw"},
		"agent":       {"guest_quota"},
	} {
		cols := columns(table)
		for _, c := range gone {
			if cols[c] {
				t.Errorf("%s.%s survived the migration", table, c)
			}
		}
	}
	if len(columns("completed_task")) != 0 {
		t.Error("completed_task survived the migration")
	}
	var reviews, blobs, agents int
	_ = db.QueryRow(`SELECT COUNT(*) FROM review`).Scan(&reviews)
	_ = db.QueryRow(`SELECT COUNT(*) FROM review_blob`).Scan(&blobs)
	_ = db.QueryRow(`SELECT COUNT(*) FROM agent`).Scan(&agents)
	if reviews != 50 || blobs != 50 || agents != 2 {
		t.Errorf("rows lost: reviews=%d blobs=%d agents=%d, want 50/50/2", reviews, blobs, agents)
	}
	// The migrated store serves the old reviews through the new shape.
	st, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Reviews != 50 || st.TasksCompleted != 50 {
		t.Errorf("stats after migration: %+v", st)
	}
}
