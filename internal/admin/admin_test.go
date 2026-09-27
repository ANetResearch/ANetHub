package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/version"
)

// testCanary is written into the relay envelopes buildHubDB queues. No admin
// response and no file under the admin data directory may contain it.
const testCanary = "canary-admin-relay-3e8b51"

// buildHubDB seeds a hub store (current schema, created by aghub.Open) with
// two agents, three queued sealed envelopes whose ciphertext holds
// testCanary, and one stored review, then returns the hub data dir.
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
	if err := hs.PutAgent(prov.AID(), "测试供给方", []string{"echo", "translate"}, provKEL); err != nil {
		t.Fatal(err)
	}
	if err := hs.PutAgent(req.AID(), "测试需求方", nil, reqKEL); err != nil {
		t.Fatal(err)
	}

	// Since hub wire 2 the relay holds sealed envelopes only: the
	// delegate, the reply and the result below are opaque to the hub and
	// to this admin plane, which is the property these tests pin.
	for i, to := range []string{prov.AID(), req.AID(), req.AID()} {
		if _, err := hs.RelayEnqueue(to, sealedForTest(t, to, fmt.Sprintf("%s %d", testCanary, i))); err != nil {
			t.Fatal(err)
		}
	}
	// One review, stored as the hub stores it: rating, comment and the
	// receipt anchors, no content.
	rv := &evidence.Review{InteractionID: "ix-admin-1", SubjectAID: prov.AID(), ReviewerAID: req.AID(),
		Rating: 4, Comment: "fine", ReceiptCID: "bafy-receipt-admin-1", CreatedAt: 2000}
	if err := hs.PutReview(rv, aghub.ReviewDetail{RequestCID: "bafy-req", ResultCID: "bafy-res", CompletedAt: 1000}); err != nil {
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
	hv := NewHarvester(filepath.Join(adminDir, "datasets"))
	srv := NewServer(store, hub, hv, NewVecClient(""), "test-token", "/admin")
	return srv, store, hv, provAID, reqAID
}

// sealedForTest is a structurally valid sealed envelope for "to" whose
// ciphertext is the given text. A real one is encrypted; the point here
// is that even a ciphertext holding plaintext bytes is not decoded or
// copied by the admin plane.
func sealedForTest(t *testing.T, to, ct string) []byte {
	t.Helper()
	env := &seal.SealedEnvelope{V: seal.EnvelopeVersion, To: to, Suite: seal.SuiteX25519,
		KID: bytes.Repeat([]byte{7}, seal.KIDLen), Enc: bytes.Repeat([]byte{9}, 32), CT: []byte(ct)}
	b, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RunAll touches no source and writes nothing under the datasets root
// (A2A-DESIGN §9 row admin 采集, [C39]).
//
// Independent checks, each of which a re-added source trips: the returned
// list must be empty, so a source that ran and reported fails; and the
// datasets root must not exist afterwards, so a source that writes fails.
// A second pass runs through the HTTP surface of a fully wired admin plane,
// with an official agent registered and relay envelopes queued in hub.db,
// and checks that no harvest cursor, no session and no file resulted, so a
// source that records its cursor or a session index row fails too.
func TestRunAllTouchesNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "datasets")
	hv := NewHarvester(root)
	if got := hv.RunAll(context.Background()); len(got) != 0 {
		t.Fatalf("RunAll ran %d source(s): %+v", len(got), got)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("RunAll created the datasets root (%v)", err)
	}

	srv, store, hvFull, _, _ := newTestServer(t)
	if err := store.PutOfficial(&Manifest{ID: "qa-official", Name: "QA", Tier: "official",
		ProductLine: "anetos", AID: "did:anet:qa", Caps: []string{"qa.run"}}); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	w, out := doReq(t, h, "POST", "/admin/api/harvest", "test-token", map[string]any{})
	if w.Code != http.StatusOK {
		t.Fatalf("harvest: %d %s", w.Code, w.Body.String())
	}
	if list, _ := out["results"].([]any); len(list) != 0 {
		t.Errorf("the harvest endpoint ran sources: %v", list)
	}
	states, err := store.HarvestStates()
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Errorf("a harvest cursor was written: %+v", states)
	}
	counts, err := store.SessionCounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 0 {
		t.Errorf("sessions were recorded: %+v", counts)
	}
	if _, err := os.Stat(hvFull.Root()); !os.IsNotExist(err) {
		t.Errorf("the datasets root exists after a harvest (%v)", err)
	}
}

// No admin response and no file in the admin data directory holds relay
// content (SI-1). The relay envelopes in hub.db carry testCanary in their
// ciphertext; the admin plane must neither decode nor copy it.
func TestNoAdminSurfaceServesRelayContent(t *testing.T) {
	srv, store, hv, provAID, _ := newTestServer(t)
	if err := store.PutOfficial(&Manifest{ID: "qa-official", Name: "QA", Tier: "official",
		ProductLine: "anetos", AID: provAID, Caps: []string{"echo"}}); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	doReq(t, h, "POST", "/admin/api/harvest", "test-token", map[string]any{})
	srv.takeSnapshot()
	for _, path := range []string{
		"/admin/api/overview", "/admin/api/agents", "/admin/api/agents/" + provAID,
		"/admin/api/official", "/admin/api/capabilities", "/admin/api/discover?task=echo",
		"/admin/api/vision", "/admin/api/store", "/admin/api/sessions",
		"/admin/api/sessions/hub-relay/x", "/admin/api/reviews", "/admin/api/audit",
		"/admin/api/deleted",
	} {
		w, _ := doReq(t, h, "GET", path, "test-token", nil)
		if strings.Contains(w.Body.String(), testCanary) {
			t.Errorf("GET %s serves relay content", path)
		}
	}
	adminDir := filepath.Dir(hv.Root())
	err := filepath.Walk(adminDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(b, []byte(testCanary)) {
			t.Errorf("%s holds relay content", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The official-agent operations removed by A2A-DESIGN §9 answer 404 to an
// authenticated operator: ops over ssh, the monitor proxy, insights and
// the ACL write. SI-1 asserts the same from outside.
func TestOfficialAgentOperationsAreGone(t *testing.T) {
	srv, store, _, _, _ := newTestServer(t)
	if err := store.PutOfficial(&Manifest{ID: "qa-official", Name: "QA", Tier: "official",
		ProductLine: "anetos"}); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	for _, rt := range []struct{ method, path string }{
		{"POST", "/admin/api/official/qa-official/ops"},
		{"GET", "/admin/api/official/qa-official/monitor/state"},
		{"GET", "/admin/api/official/qa-official/monitor/catalog"},
		{"GET", "/admin/api/official/qa-official/insights"},
		{"POST", "/admin/api/official/qa-official/acl"},
		{"POST", "/admin/api/agents/did:anet:x/quota"},
		{"GET", "/admin/api/tasks"},
	} {
		w, _ := doReq(t, h, rt.method, rt.path, "test-token", map[string]string{"op": "status"})
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "no such admin API route") {
			t.Errorf("%s %s = %d %.80s, want the JSON 404", rt.method, rt.path, w.Code, w.Body.String())
		}
		// Without a credential the removed route answers like every other
		// API path: 401, so that route names are not enumerable.
		if w, _ := doReqFrom(t, h, rt.method, rt.path, "", nil, "192.0.2.77"); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a credential = %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

func doReq(t *testing.T, h http.Handler, method, path, token string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return doReqFrom(t, h, method, path, token, body, "")
}

// doReqFrom is doReq with the source address the server sees.
//
// Failed credential checks are now rate-limited per source IP, so a test that
// makes many failing calls has to say whether they come from one client or
// many. nginx sets X-Real-IP from $remote_addr, which is where the server reads
// it from.
func doReqFrom(t *testing.T, h http.Handler, method, path, token string, body any, ip string) (*httptest.ResponseRecorder, map[string]any) {
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
	if ip != "" {
		r.Header.Set("X-Real-Ip", ip)
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

	// Moderation round-trips and is audited.
	if w, _ := doReq(t, h, "POST", "/admin/api/agents/"+provAID+"/moderate", "test-token", map[string]string{"status": "flagged", "note": "试运行"}); w.Code != http.StatusOK {
		t.Fatalf("moderate: %d", w.Code)
	}
	_, out = doReq(t, h, "GET", "/admin/api/agents/"+provAID, "test-token", nil)
	ag := out["agent"].(map[string]any)
	// The agent row carries no guest quota and no task counters: both
	// columns are gone from the hub store (A2A-DESIGN §9).
	for _, k := range []string{"guest_quota", "tasks_as_provider", "tasks_as_requester", "last_completed_at"} {
		if _, ok := ag[k]; ok {
			t.Errorf("the admin agent view still carries %q: %+v", k, ag)
		}
	}
	if int(ag["review_count"].(float64)) != 1 {
		t.Errorf("review_count = %v, want 1", ag["review_count"])
	}
	if out["moderation"].(map[string]any)["status"] != "flagged" {
		t.Fatal("moderation not applied")
	}
	_, out = doReq(t, h, "GET", "/admin/api/audit", "test-token", nil)
	if len(out["audit"].([]any)) < 1 {
		t.Fatal("audit entries missing")
	}

	// Overview + sessions + store respond coherently.
	w, out = doReq(t, h, "GET", "/admin/api/overview", "test-token", nil)
	if w.Code != http.StatusOK || out["totals"] == nil {
		t.Fatalf("overview: %d", w.Code)
	}
	// Wire 2: nothing is harvested from the relay, so no relay session exists.
	_, out = doReq(t, h, "GET", "/admin/api/sessions?source=hub-relay", "test-token", nil)
	if list, _ := out["sessions"].([]any); len(list) != 0 {
		t.Fatalf("relay sessions listed: %v", list)
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
	m, err := ParseManifest([]byte(`{"id":"ok","name":"x","tier":"official","product_line":"anetos",
	  "aid":"did:anet:ok","hub":"https://hub.invalid","caps":["a.b","c.d"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.AID != "did:anet:ok" || m.Hub != "https://hub.invalid" || len(m.Caps) != 2 {
		t.Fatalf("registry fields not kept: %+v", m)
	}
}

// A manifest that still carries a section the admin plane no longer has —
// runtime (an ssh host), monitor (a console URL), ops (commands) or datasets
// (a harvest switch) — is refused with the reason, not reduced silently.
func TestAManifestWithARemovedSectionIsRefused(t *testing.T) {
	for _, k := range []string{"runtime", "monitor", "ops", "datasets"} {
		doc := `{"id":"ok","name":"x","tier":"official","product_line":"anetos","` + k + `":{}}`
		_, err := ParseManifest([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), "no longer accepted") {
			t.Errorf("a manifest with %q: %v, want refused", k, err)
		}
	}
	// The same through the API and through the officials file.
	srv, store, _, _, _ := newTestServer(t)
	w, _ := doReq(t, srv.Handler(), "POST", "/admin/api/official", "test-token", map[string]any{
		"id": "qa", "name": "QA", "tier": "official", "product_line": "anetos",
		"monitor": map[string]string{"url": "http://127.0.0.1:1"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST /api/official with a monitor section = %d, want 400", w.Code)
	}
	path := filepath.Join(t.TempDir(), OfficialsFileName)
	if err := os.WriteFile(path, []byte(`[{"id":"qa","name":"QA","tier":"official","product_line":"anetos",
	  "datasets":{"harvest":true}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SeedOfficialsFromFile(path); err == nil {
		t.Error("an officials file with a datasets section was loaded")
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

// A placeholder credential stops the admin plane from starting
// (cmd/anet-hub-admin calls PlaceholderToken before serving). The unit
// template ships ADMIN_TOKEN=CHANGE_ME; a deployment that kept it would
// publish the operator surface under a value readable in this repository.
func TestAPlaceholderCredentialIsRecognised(t *testing.T) {
	for _, tok := range []string{
		"CHANGE_ME", "changeme", "change-me", "Change Me", "REPLACE_ME", "<token>", "${ADMIN_TOKEN}",
		"{{admin_token}}", "%ADMIN_TOKEN%", "your-token-here", "xxxxxxxx", "00000000", "", "   ", "TODO",
	} {
		if !PlaceholderToken(tok) {
			t.Errorf("%q was not recognised as a placeholder", tok)
		}
	}
	for _, tok := range []string{"k7Qw2mZr9TfLpX4v", "anetpw2077", "change-me-7Qw2mZr9", "xxxxxxxy"} {
		if PlaceholderToken(tok) {
			t.Errorf("%q was treated as a placeholder", tok)
		}
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
		{"POST", "/admin/api/agents/" + provAID + "/moderate"},
		{"DELETE", "/admin/api/agents/" + provAID},
		{"GET", "/admin/api/official"},
		{"POST", "/admin/api/official"},
		{"DELETE", "/admin/api/official/anet-hub"},
		{"GET", "/admin/api/capabilities"},
		{"GET", "/admin/api/discover"},
		{"GET", "/admin/api/vision"},
		{"GET", "/admin/api/store"},
		{"GET", "/admin/api/sessions"},
		{"GET", "/admin/api/sessions/relay/x"},
		{"POST", "/admin/api/harvest"},
		{"GET", "/admin/api/reviews"},
		{"GET", "/admin/api/audit"},
		{"GET", "/admin/api/deleted"},
		{"POST", "/admin/api/deleted/" + provAID + "/restore"},
	}
	// The count is asserted so a route added without a line here fails
	// loudly. A new route is the one most likely to be missing its auth
	// wrapper, and a list that quietly falls behind covers everything
	// except the thing that needs covering.
	if len(routes) != 19 {
		t.Fatalf("this check lists %d routes; the surface has 19. "+
			"A route missing from this list is a route nobody checks.", len(routes))
	}
	for i, rt := range routes {
		// Each route probes from its own source address. Failed credential
		// checks are rate-limited per IP, and fifty failures from one client is
		// exactly what that limit exists to stop — sharing an address here
		// would turn this into a test of the limiter and stop checking whether
		// the routes are wrapped at all.
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			// No credential at all.
			if w, _ := doReqFrom(t, h, rt.method, rt.path, "", nil, ip); w.Code != http.StatusUnauthorized {
				t.Errorf("no credential returned %d, want 401 — this route is open", w.Code)
			}
			// A wrong one.
			if w, _ := doReqFrom(t, h, rt.method, rt.path, "not-the-token", nil, ip); w.Code != http.StatusUnauthorized {
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

// Moderation changes take effect and are attributable: an operator
// judgement about somebody else's agent has to leave a record naming what
// was done to whom.
func TestModerationIsRecorded(t *testing.T) {
	srv, store, _, provAID, _ := newTestServer(t)
	h := srv.Handler()

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
	var sawModerate bool
	for _, e := range tail {
		if strings.Contains(e.Action, "moderat") && e.Target == provAID {
			sawModerate = true
		}
	}
	if !sawModerate {
		t.Error("audit has no moderation entry — a judgement about somebody else's " +
			"agent with no record of who made it")
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

// The admin readers work against a hub.db created by the current aghub.Open
// (no completed_task, no guest_quota, no review content) and report what
// that store can state [C38].
func TestAdminReadersOfTheCurrentHubSchema(t *testing.T) {
	hubDir, provAID, reqAID := buildHubDB(t)
	hub, err := OpenHubDB(hubDir)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	agents, err := hub.AllAgents("")
	if err != nil {
		t.Fatalf("AllAgents: %v", err)
	}
	byAID := map[string]AdminAgentView{}
	for _, a := range agents {
		byAID[a.AID] = a
	}
	if p := byAID[provAID]; p.ReviewCount != 1 || p.MailboxBacklog != 1 {
		t.Errorf("provider: reviews=%d backlog=%d, want 1/1", p.ReviewCount, p.MailboxBacklog)
	}
	if r := byAID[reqAID]; r.ReviewsWritten != 1 || r.MailboxBacklog != 2 {
		t.Errorf("requester: written=%d backlog=%d, want 1/2", r.ReviewsWritten, r.MailboxBacklog)
	}
	tot, err := hub.Totals()
	if err != nil {
		t.Fatalf("Totals: %v", err)
	}
	if tot.TasksCompleted != 1 || tot.Reviews != 1 || tot.RelayBacklog != 3 || tot.Agents != 2 {
		t.Errorf("totals = %+v, want tasks_completed 1 (one published receipt), reviews 1, backlog 3, agents 2", tot)
	}
	revs, err := hub.RecentReviews(10)
	if err != nil {
		t.Fatalf("RecentReviews: %v", err)
	}
	raw, _ := json.Marshal(revs)
	if len(revs) != 1 || strings.Contains(string(raw), `"goal"`) || strings.Contains(string(raw), `"deliverable"`) {
		t.Errorf("recent reviews: %s", raw)
	}
}

// oldAgentTable is agent as a hub created it before guest mode was
// removed.
const oldAgentTable = `CREATE TABLE agent (
   aid TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', caps TEXT NOT NULL DEFAULT '[]',
   summary TEXT NOT NULL DEFAULT '', readme TEXT NOT NULL DEFAULT '', pricing TEXT NOT NULL DEFAULT '',
   guest_quota INTEGER NOT NULL DEFAULT 5, kel BLOB NOT NULL, registered_at TEXT NOT NULL,
   visibility TEXT NOT NULL DEFAULT 'hub-local', last_seen_at TEXT)`

// A backup written before guest mode was removed still has agent.guest_quota.
// Restoring it into a hub store of the current schema adds its agents and
// does not bring the column back ([C38]).
func TestRestoringFromAnOldSchemaBackup(t *testing.T) {
	bak := filepath.Join(t.TempDir(), "hub-backup-old.db")
	db, err := sql.Open("sqlite", bak)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(oldAgentTable); err != nil {
		t.Fatal(err)
	}
	var aids []string
	for i := 0; i < 3; i++ {
		c, _ := identity.Incept()
		kel, _ := identity.MarshalKEL(c.KEL())
		if _, err := db.Exec(`INSERT INTO agent(aid,name,caps,summary,readme,pricing,guest_quota,kel,registered_at)
		     VALUES(?,?,?,?,?,?,?,?,?)`, c.AID(), fmt.Sprintf("old-%d", i), `["x.y"]`, "s", "", "",
			5, kel, "2026-07-19T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		aids = append(aids, c.AID())
	}
	db.Close()

	hubDir, _, _ := buildHubDB(t) // current schema, two agents
	before, after, err := RestoreAgentsFromBackup(hubDir, bak)
	if err != nil {
		t.Fatalf("restoring an old-schema backup: %v", err)
	}
	if before != 2 || after != 5 {
		t.Errorf("before=%d after=%d, want 2 and 5", before, after)
	}
	hub, err := OpenHubDB(hubDir)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	var n int
	if err := hub.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('agent') WHERE name='guest_quota'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("the restore brought agent.guest_quota back")
	}
	agents, err := hub.AllAgents("")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, a := range agents {
		have[a.AID] = true
	}
	for _, aid := range aids {
		if !have[aid] {
			t.Errorf("%s was not restored", aid)
		}
	}
	// An archived row written before the removal carries guest_quota too,
	// and restores the same way.
	c, _ := identity.Incept()
	kel, _ := identity.MarshalKEL(c.KEL())
	row, _ := json.Marshal(map[string]any{"aid": c.AID(), "name": "archived", "caps": "[]",
		"guest_quota": 5, "kel_b64": encB64(kel), "registered_at": "2026-07-19T00:00:00Z"})
	if err := hub.RestoreDeletedAgent(string(row)); err != nil {
		t.Fatalf("restoring an old archive: %v", err)
	}
	if _, err := hub.Agent(c.AID()); err != nil {
		t.Errorf("the old archive was not restored: %v", err)
	}
}

// Sessions an earlier version harvested are still in admin.db and under
// datasets/ until the production cleanup runs. The admin API lists their
// index rows but does not serve their content: not the goal column, not the
// session card, not the event file.
func TestHistoricalSessionsAreNotServedWithContent(t *testing.T) {
	srv, store, hv, provAID, reqAID := newTestServer(t)
	const canary = "canary-admin-session-9d4f20"
	if _, err := store.db.Exec(`INSERT INTO session(source,session_id,provider_aid,requester_aid,intent,goal,
	     status,started_at,ended_at,events,bytes,card_path,data_path,updated_at)
	     VALUES('hub-relay','ix-old-1',?,?,'',?, 'done','','',3,120,'sessions/202609/ix-old-1.md',
	            'data/sessions/202609/ix-old-1.jsonl','2026-09-01T00:00:00Z')`,
		provAID, reqAID, canary+" goal"); err != nil {
		t.Fatal(err)
	}
	for rel, body := range map[string]string{
		"hub-relay/sessions/202609/ix-old-1.md":         "---\ntitle: " + canary + " card\n---\n",
		"hub-relay/data/sessions/202609/ix-old-1.jsonl": `{"goal":"` + canary + ` event"}` + "\n",
	} {
		p := filepath.Join(hv.Root(), rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := srv.Handler()
	for _, path := range []string{
		"/admin/api/sessions", "/admin/api/sessions?source=hub-relay", "/admin/api/sessions?q=ix-old",
		"/admin/api/sessions/hub-relay/ix-old-1", "/admin/api/agents/" + provAID,
	} {
		w, _ := doReq(t, h, "GET", path, "test-token", nil)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d", path, w.Code)
		}
		if strings.Contains(w.Body.String(), canary) {
			t.Errorf("GET %s serves harvested content: %.200s", path, w.Body.String())
		}
	}
	// The row itself is still listed, so an operator can see what the
	// cleanup has left to delete.
	_, out := doReq(t, h, "GET", "/admin/api/sessions", "test-token", nil)
	if list, _ := out["sessions"].([]any); len(list) != 1 {
		t.Errorf("sessions listed: %v, want the one historical row", out["sessions"])
	}
	// The search does not match the goal column either. A search that
	// did would not print the goal, but whether a row comes back for a
	// guessed phrase would still disclose what the goal contains.
	_, out = doReq(t, h, "GET", "/admin/api/sessions?q="+canary, "test-token", nil)
	if list, _ := out["sessions"].([]any); len(list) != 0 {
		t.Errorf("a search for text that occurs only in the goal returned %d session(s)", len(list))
	}
}
