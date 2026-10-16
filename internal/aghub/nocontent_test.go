package aghub_test

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	_ "modernc.org/sqlite"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// Tests for A2A-DESIGN §9: the hub holds no interaction content. Reviews
// carry no goal or deliverable, the review tables have no content columns,
// guest mode and completed_task are gone, and a store from before the
// change is refused, not converted.

// hubInDir is a hub whose data directory the test can search.
func hubInDir(t *testing.T) (*httptest.Server, *aghub.Store, *aghub.Server, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := aghub.HubIdentityForTest(t)
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

// A review is served with its receipt, its rating and comment and two days,
// and nothing else: no content, no reviewer, no interaction id.
func TestAReviewIsServedWithoutContent(t *testing.T) {
	srv, store, _, _ := hubInDir(t)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	code, b := uploadReview(t, srv, makeEvidence(t, prov, req, "ix-nocontent-1", 4, ""))
	if code != 200 {
		t.Fatalf("upload: %d %s", code, b)
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
	var members []string
	for k := range got.Reviews[0] {
		members = append(members, k)
	}
	sort.Strings(members)
	if want := "completed_day,created_day,rating,receipt_cid,subject_aid"; strings.Join(members, ",") != want {
		t.Errorf("a served review has the members %v, want %s", members, want)
	}

	// The federation stream carries the two signed objects, the
	// attestation and the provider's KEL, nothing else. The provider is
	// hub-local by default and is opted in so that its review is streamed.
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
	members = members[:0]
	for k := range fields {
		members = append(members, k)
	}
	sort.Strings(members)
	if want := "attestation,fed_seq,format,provider_kel,receipt,review"; strings.Join(members, ",") != want {
		t.Errorf("a stream entry has the members %v, want %s", members, want)
	}
}

// A client that still sends the content with its review is refused (the
// body is decoded strictly), and nothing is stored for that review.
func TestAReviewUploadCarryingContentIsRefused(t *testing.T) {
	srv, store, _, dir := hubInDir(t)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	canary := []byte("canary-review-content-7f3a9c")
	for _, field := range []string{"request_doc", "deliverable"} {
		k := makeEvidence(t, prov, req, "ix-carrying-"+field, 5, "")
		body := k.Body(t)
		body[field] = base64.RawURLEncoding.EncodeToString(canary)
		code, b := signedDo(t, srv, req, relayauth.ActionReview, http.MethodPost, "/reviews", body)
		if code != http.StatusBadRequest || !strings.Contains(string(b), `"bad_request"`) ||
			!strings.Contains(string(b), field) {
			t.Errorf("a review carrying %s: %d %s, want 400 bad_request naming it", field, code, b)
		}
		if reviewStored(t, store, k) {
			t.Errorf("the review carrying %s was stored", field)
		}
	}
	if hits := filesContaining(t, dir, canary); len(hits) > 0 {
		t.Errorf("content sent with a refused review is on disk in %v", hits)
	}
}

// reviewStored reports whether the hub holds a review of k's interaction.
func reviewStored(t *testing.T, store *aghub.Store, k *aghub.ReviewKit) bool {
	t.Helper()
	var n int
	if err := store.DBForTest().QueryRow(`SELECT COUNT(*) FROM review WHERE ix_commit=?`, k.IXCommit()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// A comment is at most 280 code points, counted as characters rather than
// bytes, on a local upload and on a federated review alike.
func TestAReviewCommentIsBounded(t *testing.T) {
	srv, store, _, _ := hubInDir(t)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)

	// 280 three-byte characters: 840 bytes, 280 characters. Accepted.
	atLimit := strings.Repeat("评", evidence.MaxCommentChars)
	if code, b := uploadReview(t, srv, makeEvidenceWithComment(t, prov, req, "ix-comment-280", 5, "", atLimit)); code != 200 {
		t.Fatalf("a %d-character comment was refused: %d %s", evidence.MaxCommentChars, code, b)
	}
	over := makeEvidenceWithComment(t, prov, req, "ix-comment-281", 5, "", atLimit+"x")
	over.Unchecked = true
	code, b := uploadReview(t, srv, over)
	if code != http.StatusBadRequest || !strings.Contains(string(b), "longer than 280") {
		t.Errorf("a %d-character comment: %d %s, want 400", evidence.MaxCommentChars+1, code, b)
	}
	if reviewStored(t, store, over) {
		t.Error("the review with the over-long comment was stored")
	}

	// The federated path applies the same bound.
	peer := aghub.HubIdentityForTest(t)
	_, other, _, _ := hubInDir(t)
	ok := makeEvidenceWithComment(t, prov, req, "ix-fed-comment-280", 5, "", atLimit)
	if err := other.AdmitFedReview(peer.AID, peer.Ctrl.KEL(), aghub.FedEntryForTest(t, peer.Ctrl, ok, aghub.TodayForTest(), 1)); err != nil {
		t.Fatalf("a federated review with a %d-character comment was refused: %v", evidence.MaxCommentChars, err)
	}
	if err := other.AdmitFedReview(peer.AID, peer.Ctrl.KEL(), aghub.FedEntryForTest(t, peer.Ctrl, over, aghub.TodayForTest(), 2)); err == nil ||
		!errors.Is(err, evidence.ErrComment) {
		t.Errorf("a federated review with a %d-character comment: %v, want refused", evidence.MaxCommentChars+1, err)
	}
}

// A peer may send members the review/2 entry does not have (an earlier
// peer's request_doc, deliverable, reviewer_kel). They are not read and not
// stored; the entry is checked and admitted on what it has to carry.
func TestAFederatedReviewIsAdmittedWhateverContentFieldsItCarries(t *testing.T) {
	_, other, _, dir := hubInDir(t)
	peer := aghub.HubIdentityForTest(t)
	dirSeam := aghub.FedDirectory{S: other, PeerKEL: func(string) ([]identity.SignedEvent, error) { return peer.Ctrl.KEL(), nil }}
	canary := []byte("canary-federated-content-41b2")
	for i, tc := range []struct {
		name        string
		requestDoc  string
		deliverable string
	}{
		{"empty strings", "", ""},
		{"content that matches no anchor", base64.RawURLEncoding.EncodeToString(canary),
			base64.RawURLEncoding.EncodeToString(canary)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prov, req := twoAgents(t)
			e := aghub.FedEntryForTest(t, peer.Ctrl, makeEvidence(t, prov, req, "ix-fed-legacy-"+string(rune('a'+i)), 4, ""),
				aghub.TodayForTest(), uint64(i+1))
			var m map[string]any
			b, _ := json.Marshal(e)
			_ = json.Unmarshal(b, &m)
			m["request_doc"], m["deliverable"], m["reviewer_kel"] = tc.requestDoc, tc.deliverable, kelB64(t, req)
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := dirSeam.AdmitFedReview(peer.AID, raw); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
	if hits := filesContaining(t, dir, canary); len(hits) > 0 {
		t.Errorf("content a peer sent with a review is on disk in %v", hits)
	}
}

func kelB64(t *testing.T, c *identity.Controller) string {
	t.Helper()
	b, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
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
		if code, b := uploadReview(t, srv, makeEvidence(t, prov, req, ix, 5, "")); code != 200 {
			t.Fatalf("upload %s: %d %s", ix, code, b)
		}
	}
	// A refused upload publishes no receipt.
	bad := makeEvidence(t, prov, req, "ix-stat-bad", 5, "").Body(t)
	bad["deliverable"] = base64.RawURLEncoding.EncodeToString([]byte("x"))
	if code, _ := signedDo(t, srv, req, relayauth.ActionReview, http.MethodPost, "/reviews", bad); code == 200 {
		t.Fatal("a review carrying content was accepted")
	}
	if st := stats(); st.TasksCompleted != 2 || st.Reviews != 2 {
		t.Errorf("after two published receipts: tasks_completed=%d reviews=%d, want 2/2",
			st.TasksCompleted, st.Reviews)
	}
	s.SetModules([]string{"federation", "example"})
	if st := stats(); strings.Join(st.Modules, ",") != "federation,example" {
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

// A store written before this change, content and all, is not opened: 0.3.0
// converts no hub.db (core CORE-V4), so it is refused as anet-hub 0.2's data
// (hub_identity_v02) and the file is left byte for byte as it was. Nothing
// of it is served. Removing the old content from disk is the operator's
// step of moving the directory away, not something a start does.
func TestAnOldStoreWithContentIsRefusedUntouched(t *testing.T) {
	dir := t.TempDir()
	goal := []byte("canary-old-goal-5d61e0")
	func() {
		db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
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
		if _, err := db.Exec(`INSERT INTO review(interaction_id,subject_aid,reviewer_aid,rating,comment,
		     receipt_cid,goal,deliverable,request_cid,result_cid,completed_at,created_at,stored_at)
		     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			"ix-old", prov.AID(), req.AID(), 4, "ok", "bafy-receipt", string(goal), "d",
			"bafy-req", "bafy-res", 1000, 2000, "2026-08-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}()
	before := dirSnapshot(t, dir)
	store, err := aghub.Open(dir)
	if !errors.Is(err, aghub.ErrHubDataV02) {
		if store != nil {
			store.Close()
		}
		t.Fatalf("open an old store: %v, want ErrHubDataV02", err)
	}
	if after := dirSnapshot(t, dir); after != before {
		t.Errorf("refusing the old store changed the directory:\n%s\n%s", before, after)
	}
}
