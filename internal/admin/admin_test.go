package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/version"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// buildHubDB seeds a hub store with two agents and one full delegate→message→result interaction, then
// returns the hub data dir.
func buildHubDB(t *testing.T) (dir string, providerAID, requesterAID string) {
	t.Helper()
	dir = t.TempDir()
	hs, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()

	prov, _ := identity.Incept()
	req, _ := identity.Incept()
	provKEL, _ := identity.MarshalKEL(prov.KEL())
	reqKEL, _ := identity.MarshalKEL(req.KEL())
	if err := hs.PutAgent(prov.AID(), "测试供给方", []string{"echo", "translate"}, 5, provKEL); err != nil {
		t.Fatal(err)
	}
	if err := hs.PutAgent(req.AID(), "测试需求方", nil, 0, reqKEL); err != nil {
		t.Fatal(err)
	}

	// delegate: a signed TaskDoc, exactly as a real daemon relays it.
	td := &tsir.TaskDoc{Version: tsir.VersionPair{Major: 1},
		Tasks: []tsir.Task{{Intent: tsir.Intent{Summary: "把这句话翻译成英文", Body: "把这句话翻译成英文：你好世界"}}}}
	if err := td.Sign(req); err != nil {
		t.Fatal(err)
	}
	doc, _ := coredet.Marshal(td)
	dr := &delegation.DelegateReq{TaskDoc: doc, Envelope: td.Envelope, KEL: reqKEL, InteractionID: "ix-test-1",
		Attachments: []delegation.Attachment{{Name: "ref.png", Mime: "image/png", Size: 5, CID: "bafyfake", Data: []byte("12345")}}}
	drb, _ := dr.Marshal()
	if _, err := hs.RelayEnqueue(prov.AID(), req.AID(), aghub.RelayKindDelegate, "ix-test-1", drb); err != nil {
		t.Fatal(err)
	}
	// message: provider chats back.
	cm := &delegation.ChatMsg{Kind: delegation.ChatText, Body: "收到，马上翻译。"}
	cmb, _ := cm.Marshal()
	if _, err := hs.RelayEnqueue(req.AID(), prov.AID(), aghub.RelayKindMessage, "ix-test-1", cmb); err != nil {
		t.Fatal(err)
	}
	// result: done with a text deliverable.
	rr := &delegation.ResultResp{Status: delegation.StatusDone, Deliverable: []byte("Hello, world")}
	rrb, _ := rr.Marshal()
	if _, err := hs.RelayEnqueue(req.AID(), prov.AID(), aghub.RelayKindResult, "ix-test-1", rrb); err != nil {
		t.Fatal(err)
	}
	return dir, prov.AID(), req.AID()
}

func newTestServer(t *testing.T) (*Server, *Store, *Harvester, string, string) {
	t.Helper()
	hubDir, provAID, reqAID := buildHubDB(t)
	adminDir := t.TempDir()
	store, err := OpenStore(adminDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	hub, err := OpenHubDB(hubDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	proxy := NewMonitorProxy("tok")
	hv := NewHarvester(store, hub, proxy, filepath.Join(adminDir, "datasets"))
	srv := NewServer(store, hub, NewOps(0), proxy, hv, NewVecClient(""), "test-token", "/admin")
	return srv, store, hv, provAID, reqAID
}

func TestHarvestRelayInteraction(t *testing.T) {
	_, store, hv, provAID, reqAID := newTestServer(t)
	results := hv.RunAll(context.Background())
	if len(results) == 0 || results[0].Source != "hub-relay" {
		t.Fatalf("unexpected results: %+v", results)
	}
	if results[0].Err != "" {
		t.Fatalf("harvest error: %s", results[0].Err)
	}
	if results[0].Events != 3 {
		t.Fatalf("want 3 events, got %d", results[0].Events)
	}
	row, err := store.GetSession("hub-relay", "ix-test-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.ProviderAID != provAID || row.RequesterAID != reqAID {
		t.Fatalf("participants wrong: %+v", row)
	}
	if row.Status != delegation.StatusDone {
		t.Fatalf("want status done, got %q", row.Status)
	}
	if !strings.Contains(row.Goal, "翻译") {
		t.Fatalf("goal not extracted: %q", row.Goal)
	}
	// Data file: 3 event lines; attachment bytes must be dropped (metadata kept).
	events, err := hv.ReadSessionData("hub-relay", "ix-test-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("want 3 event lines, got %d", len(events))
	}
	var first relayEvent
	if err := json.Unmarshal(events[0], &first); err != nil {
		t.Fatal(err)
	}
	if first.Goal == "" || len(first.Attachments) != 1 || first.Attachments[0].Name != "ref.png" {
		t.Fatalf("delegate event malformed: %+v", first)
	}
	if bytes.Contains(events[0], []byte("12345")) {
		t.Fatal("attachment bytes leaked into dataset")
	}
	// Card must exist and carry OKF frontmatter.
	card, err := hv.ReadSessionCard("hub-relay", "ix-test-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"type: Agent Session", "resource:", "hub:", "status: \"done\""} {
		if !strings.Contains(card, want) {
			t.Fatalf("card missing %q:\n%s", want, card)
		}
	}
	// Re-run must be a no-op (cursor advanced).
	again := hv.RunAll(context.Background())
	if again[0].Events != 0 {
		t.Fatalf("second run should harvest 0, got %d", again[0].Events)
	}
	// Bundle index regenerated at the root.
	if _, err := os.Stat(filepath.Join(hv.Root(), "hub-relay", "index.md")); err != nil {
		t.Fatal("bundle root index.md missing")
	}
}

func doReq(t *testing.T, h http.Handler, method, path, token string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rd)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func TestServerAuthAndAgents(t *testing.T) {
	srv, _, hv, provAID, _ := newTestServer(t)
	hv.RunAll(context.Background())
	h := srv.Handler()

	// Unauthenticated API access is rejected; login gate works.
	if w, _ := doReq(t, h, "GET", "/admin/api/agents", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if w, _ := doReq(t, h, "POST", "/admin/api/login", "", map[string]string{"token": "wrong"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: want 401, got %d", w.Code)
	}
	if w, _ := doReq(t, h, "POST", "/admin/api/login", "", map[string]string{"token": "test-token"}); w.Code != http.StatusOK {
		t.Fatalf("login: want 200, got %d", w.Code)
	}

	// Agents view includes the UNLISTED requester (public API hides it).
	w, out := doReq(t, h, "GET", "/admin/api/agents", "test-token", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("agents: %d %s", w.Code, w.Body.String())
	}
	agents := out["agents"].([]any)
	if len(agents) != 2 {
		t.Fatalf("want 2 agents (incl. unlisted), got %d", len(agents))
	}

	// Moderation + quota round-trip and are audited.
	if w, _ := doReq(t, h, "POST", "/admin/api/agents/"+provAID+"/quota", "test-token", map[string]int{"guest_quota": 0}); w.Code != http.StatusOK {
		t.Fatalf("quota: %d %s", w.Code, w.Body.String())
	}
	if w, _ := doReq(t, h, "POST", "/admin/api/agents/"+provAID+"/moderate", "test-token", map[string]string{"status": "flagged", "note": "试运行"}); w.Code != http.StatusOK {
		t.Fatalf("moderate: %d", w.Code)
	}
	_, out = doReq(t, h, "GET", "/admin/api/agents/"+provAID, "test-token", nil)
	ag := out["agent"].(map[string]any)
	if int(ag["guest_quota"].(float64)) != 0 {
		t.Fatalf("quota not applied: %+v", ag)
	}
	if out["moderation"].(map[string]any)["status"] != "flagged" {
		t.Fatal("moderation not applied")
	}
	_, out = doReq(t, h, "GET", "/admin/api/audit", "test-token", nil)
	if len(out["audit"].([]any)) < 2 {
		t.Fatal("audit entries missing")
	}

	// Overview + sessions + store respond coherently.
	w, out = doReq(t, h, "GET", "/admin/api/overview", "test-token", nil)
	if w.Code != http.StatusOK || out["totals"] == nil {
		t.Fatalf("overview: %d", w.Code)
	}
	_, out = doReq(t, h, "GET", "/admin/api/sessions?source=hub-relay", "test-token", nil)
	if len(out["sessions"].([]any)) != 1 {
		t.Fatal("harvested session not listed")
	}
	w, _ = doReq(t, h, "GET", "/admin/api/sessions/hub-relay/ix-test-1", "test-token", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("session detail: %d", w.Code)
	}
	w, out = doReq(t, h, "GET", "/admin/api/store", "test-token", nil)
	if w.Code != http.StatusOK || out["product_lines"] == nil {
		t.Fatalf("store: %d", w.Code)
	}

	// The SPA is served at the base path without auth (its own token gate is client-side).
	if w, _ := doReq(t, h, "GET", "/admin/", "", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ANetHub Admin") {
		t.Fatalf("SPA not served: %d", w.Code)
	}
}

func TestManifestValidation(t *testing.T) {
	if _, err := ParseManifest([]byte(`{"id":"Bad_ID","name":"x","tier":"official","product_line":"anetos"}`)); err == nil {
		t.Fatal("bad id accepted")
	}
	if _, err := ParseManifest([]byte(`{"id":"ok","name":"x","tier":"boss","product_line":"anetos"}`)); err == nil {
		t.Fatal("bad tier accepted")
	}
	m, err := ParseManifest([]byte(`{"id":"ok","name":"x","tier":"official","product_line":"anetos","runtime":{"host":"h"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Runtime.SSHUser != "root" {
		t.Fatal("ssh_user default not applied")
	}
}

func TestOpsWhitelist(t *testing.T) {
	m, _ := ParseManifest([]byte(`{"id":"x","name":"x","tier":"official","product_line":"anetos",
	  "runtime":{"host":"nohost.invalid","units":["a.service"]}, "ops":{"allowed":["status"]}}`))
	o := NewOps(0)
	// An op outside the manifest's allowed list is refused before any ssh happens.
	if res := o.Run(context.Background(), m, "restart", ""); res.Err == "" {
		t.Fatal("disallowed op executed")
	}
	// Logs arg validation: an undeclared unit is refused.
	if _, err := buildCommand(m, "logs", "evil.service 100"); err == nil {
		t.Fatal("undeclared unit accepted")
	}
	if cmd, err := buildCommand(m, "logs", "a.service 100"); err != nil || !strings.Contains(cmd, "journalctl -u 'a.service' -n 100") {
		t.Fatalf("logs command wrong: %q %v", cmd, err)
	}
	// Update without a manifest command is refused.
	if _, err := buildCommand(m, "update", ""); err == nil {
		t.Fatal("empty update accepted")
	}
}

func TestDestructiveLimiter(t *testing.T) {
	d := newDestructiveLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		if !d.allow() {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if d.allow() {
		t.Fatal("6th destructive op should be throttled")
	}
}

func TestDeleteArchivesAndLimits(t *testing.T) {
	srv, store, _, provAID, _ := newTestServer(t)
	h := srv.Handler()
	// A single delete archives the full row (recoverable) and applies moderation.
	if w, _ := doReq(t, h, "DELETE", "/admin/api/agents/"+provAID, "test-token", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM deleted_agent WHERE aid=?`, provAID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("delete not archived: n=%d err=%v", n, err)
	}
	// Exhaust the limiter (5/min) → further deletes are throttled, not executed.
	throttled := false
	for i := 0; i < 8; i++ {
		w, _ := doReq(t, h, "DELETE", "/admin/api/agents/fakeaid"+string(rune('a'+i)), "test-token", nil)
		if w.Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatal("destructive rate limit never engaged")
	}
}

// A credential this software published must be recognisable as one.
//
// Making ADMIN_TOKEN mandatory closed the hole for new deployments and
// did nothing for existing ones: the old default was copied into a
// systemd unit at install time and stays there. The production hub was
// running with it, reachable from the public internet, guarding a surface
// that can delete agents and run operations.
func TestAPublishedCredentialIsRecognised(t *testing.T) {
	for _, tok := range []string{"anetpw2077", "admin", "changeme"} {
		if !WeakToken(tok) {
			t.Errorf("%q is in this repository and was not recognised as published", tok)
		}
	}
	// A real credential must not be flagged, or the check becomes noise
	// an operator learns to ignore.
	for _, tok := range []string{"", "k7Qw2mZr9TfLpX4v", "anetpw2078"} {
		if WeakToken(tok) {
			t.Errorf("%q was flagged as published", tok)
		}
	}
}

// Every API route must refuse an unauthenticated call.
//
// Authentication is the one defence all twenty-three share, and it is
// applied per route by wrapping each handler: a route registered without
// the wrapper is a public write endpoint on an internet-facing surface,
// and nothing but a reader noticing would catch it. One route was tested;
// the rest were assumed.
//
// Enumerated from the mux rather than hand-listed, so a route added
// tomorrow is covered the day it appears. A hand-written list would go
// stale in exactly the direction that matters — the new route is the one
// most likely to be missing its wrapper.
func TestEveryAPIRouteRefusesAnUnauthenticatedCall(t *testing.T) {
	srv, _, _, provAID, _ := newTestServer(t)
	h := srv.Handler()

	// method, path. Path parameters are filled with something real where
	// the handler needs one to get far enough to matter.
	routes := []struct{ method, path string }{
		{"GET", "/admin/api/overview"},
		{"GET", "/admin/api/agents"},
		{"GET", "/admin/api/agents/" + provAID},
		{"POST", "/admin/api/agents/" + provAID + "/quota"},
		{"POST", "/admin/api/agents/" + provAID + "/moderate"},
		{"DELETE", "/admin/api/agents/" + provAID},
		{"GET", "/admin/api/official"},
		{"POST", "/admin/api/official"},
		{"DELETE", "/admin/api/official/anet-hub"},
		{"POST", "/admin/api/official/anet-hub/ops"},
		{"GET", "/admin/api/official/anet-hub/monitor/logs"},
		{"GET", "/admin/api/official/anet-hub/insights"},
		{"POST", "/admin/api/official/anet-hub/acl"},
		{"GET", "/admin/api/capabilities"},
		{"GET", "/admin/api/discover"},
		{"GET", "/admin/api/vision"},
		{"GET", "/admin/api/store"},
		{"GET", "/admin/api/sessions"},
		{"GET", "/admin/api/sessions/relay/x"},
		{"POST", "/admin/api/harvest"},
		{"GET", "/admin/api/reviews"},
		{"GET", "/admin/api/tasks"},
		{"GET", "/admin/api/audit"},
		{"GET", "/admin/api/deleted"},
		{"POST", "/admin/api/deleted/" + provAID + "/restore"},
	}
	// The count is asserted so a route added without a line here fails
	// loudly. A new route is the one most likely to be missing its auth
	// wrapper, and a list that quietly falls behind covers everything
	// except the thing that needs covering.
	if len(routes) != 25 {
		t.Fatalf("this check lists %d routes; the surface has 25. "+
			"A route missing from this list is a route nobody checks.", len(routes))
	}
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			// No credential at all.
			if w, _ := doReq(t, h, rt.method, rt.path, "", nil); w.Code != http.StatusUnauthorized {
				t.Errorf("no credential returned %d, want 401 — this route is open", w.Code)
			}
			// A wrong one.
			if w, _ := doReq(t, h, rt.method, rt.path, "not-the-token", nil); w.Code != http.StatusUnauthorized {
				t.Errorf("a wrong credential returned %d, want 401", w.Code)
			}
		})
	}
}

// Deleting an agent archives it first, and the archive is enough to
// restore from.
//
// A delete that cannot be undone is a delete an operator will hesitate to
// use and will eventually use wrongly. The archive has to carry the KEL:
// an agent restored without its key history is a row, not an identity,
// and every receipt it ever signed stays uncheckable.
func TestDeletingAnAgentIsReversible(t *testing.T) {
	srv, store, _, provAID, _ := newTestServer(t)
	h := srv.Handler()

	if w, _ := doReq(t, h, "DELETE", "/admin/api/agents/"+provAID, "test-token", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	// Gone from the registry.
	_, out := doReq(t, h, "GET", "/admin/api/agents", "test-token", nil)
	for _, a := range out["agents"].([]any) {
		if m, ok := a.(map[string]any); ok && m["aid"] == provAID {
			t.Error("the agent is still listed after being deleted")
		}
	}
	// And archived, with its key history.
	rows, err := store.DeletedAgents(10)
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, r := range rows {
		if r.AID == provAID {
			found = r.RowJSON
		}
	}
	if found == "" {
		t.Fatal("the delete was not archived — it cannot be undone")
	}
	if !strings.Contains(found, "kel") {
		t.Error("the archive carries no key history; restoring it would " +
			"produce a row, not an identity")
	}
}

// A destructive operation is rate-limited, and the throttle is recorded.
//
// The limiter exists because of a scripted loop that wiped a registry.
// What makes it useful is not only that it stops, but that an operator
// afterwards can see it stopped: a burst that vanished without a trace is
// indistinguishable from a burst that succeeded.
func TestDestructiveOpsAreLimitedAndAudited(t *testing.T) {
	srv, store, _, provAID, reqAID := newTestServer(t)
	h := srv.Handler()

	var throttled bool
	for i := 0; i < 12; i++ {
		aid := provAID
		if i%2 == 1 {
			aid = reqAID
		}
		w, _ := doReq(t, h, "DELETE", "/admin/api/agents/"+aid, "test-token", nil)
		if w.Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatal("twelve deletions in a row were all allowed")
	}
	tail, err := store.AuditTail(50)
	if err != nil {
		t.Fatal(err)
	}
	var sawThrottle bool
	for _, e := range tail {
		if strings.Contains(e.Action, "throttled") {
			sawThrottle = true
		}
	}
	if !sawThrottle {
		t.Error("the throttle left no audit entry — an operator cannot tell " +
			"a blocked burst from a successful one")
	}
}

// Quota and moderation changes take effect and are attributable.
//
// Both are operator judgements about somebody else's agent, so both have
// to leave a record naming what was done to whom.
func TestQuotaAndModerationAreRecorded(t *testing.T) {
	srv, store, _, provAID, _ := newTestServer(t)
	h := srv.Handler()

	if w, _ := doReq(t, h, "POST", "/admin/api/agents/"+provAID+"/quota",
		"test-token", map[string]int{"guest_quota": 7}); w.Code != http.StatusOK {
		t.Fatalf("quota: %d", w.Code)
	}
	if w, _ := doReq(t, h, "POST", "/admin/api/agents/"+provAID+"/moderate",
		"test-token", map[string]string{"status": "flagged", "note": "under review"}); w.Code != http.StatusOK {
		t.Fatalf("moderate: %d", w.Code)
	}
	_, out := doReq(t, h, "GET", "/admin/api/agents/"+provAID, "test-token", nil)
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), "flagged") {
		t.Errorf("the moderation status did not survive: %s", raw)
	}
	tail, err := store.AuditTail(50)
	if err != nil {
		t.Fatal(err)
	}
	var sawQuota, sawModerate bool
	for _, e := range tail {
		if strings.Contains(e.Action, "quota") && e.Target == provAID {
			sawQuota = true
		}
		if strings.Contains(e.Action, "moderat") && e.Target == provAID {
			sawModerate = true
		}
	}
	if !sawQuota || !sawModerate {
		t.Errorf("audit is missing quota=%v moderate=%v — a judgement about "+
			"somebody else's agent with no record of who made it", sawQuota, sawModerate)
	}
}

// An archived delete can actually be undone, from the surface.
//
// The archive had a writer and no reader: "any delete is reversible" was
// true of the bytes and false of the operator, who could only reverse one
// by opening the SQLite file by hand. A recovery path only an author can
// walk is not a recovery path — and the moment it is needed is the moment
// nobody wants to be reading source.
func TestADeletedAgentCanBeRestored(t *testing.T) {
	srv, _, _, provAID, _ := newTestServer(t)
	h := srv.Handler()

	if w, _ := doReq(t, h, "DELETE", "/admin/api/agents/"+provAID, "test-token", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	// The operator can see what was removed.
	w, out := doReq(t, h, "GET", "/admin/api/deleted", "test-token", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list deleted: %d", w.Code)
	}
	list, _ := out["deleted"].([]any)
	if len(list) == 0 {
		t.Fatal("the archive lists nothing after a delete")
	}

	if w, _ := doReq(t, h, "POST", "/admin/api/deleted/"+provAID+"/restore",
		"test-token", nil); w.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	// Back in the registry.
	_, out = doReq(t, h, "GET", "/admin/api/agents", "test-token", nil)
	var back bool
	for _, a := range out["agents"].([]any) {
		if m, ok := a.(map[string]any); ok && m["aid"] == provAID {
			back = true
		}
	}
	if !back {
		t.Error("the agent did not come back")
	}
	// And restoring one that was never archived says so rather than
	// reporting success.
	if w, _ := doReq(t, h, "POST", "/admin/api/deleted/did:anet:never/restore",
		"test-token", nil); w.Code != http.StatusNotFound {
		t.Errorf("restoring an unarchived agent returned %d, want 404", w.Code)
	}
}

// The operator surface has to say which build is answering.
//
// It is a separate binary from the hub, and healthz reported only
// {"status":"ok"} — so a deploy that shipped anet-hub and forgot
// anet-hub-admin left this surface on an old build with nothing anywhere
// saying so. That is not hypothetical: the recovery endpoints were absent
// from production for a release while every check reported the surface
// healthy. A component with no version on the wire cannot be seen to be
// stale, which is the same reason the embedded webui once sat five
// deployments behind.
func TestHealthzNamesTheBuild(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	h := srv.Handler()

	// No credential: an operator diagnosing a bad deploy should not need
	// one to find out what is running.
	w, out := doReq(t, h, "GET", "/admin/healthz", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz = %d", w.Code)
	}
	if out["status"] != "ok" {
		t.Errorf("status = %v", out["status"])
	}
	for _, k := range []string{"version", "commit", "built_at"} {
		if _, ok := out[k]; !ok {
			t.Errorf("healthz does not report %q — this surface cannot be "+
				"seen to be stale", k)
		}
	}
	// The version is the real one, not a placeholder.
	if out["version"] != version.V {
		t.Errorf("version = %v, want %q", out["version"], version.V)
	}
}
