package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// auditCount returns how many audit rows carry action.
func auditCount(t *testing.T, store *Store, action string) int {
	t.Helper()
	rows, err := store.AuditTail(1000)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range rows {
		if e.Action == action {
			n++
		}
	}
	return n
}

// captureLog redirects the standard logger for the duration of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(os.Stderr); log.SetFlags(flags) })
	return &buf
}

// Guessing the token against a protected endpoint is rate-limited, not only
// guessing it at /api/login.
//
// /api/login counted failures and answered 429 past twenty a minute. The Bearer
// path did one constant-time comparison and returned 401, unmetered — so an
// attacker who never called /api/login could try the token against any of the
// twenty-five protected endpoints as fast as the network allowed. The limit
// applied to the single path an attacker is not obliged to use, and the token
// is the only thing standing between the internet and a surface that deletes
// agents, changes quotas and runs commands on other hosts over ssh.
func TestGuessingTheTokenIsRateLimitedOnEveryPath(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	h := srv.Handler()
	captureLog(t)

	const attacker = "203.0.113.9"
	for i := 0; i < authMaxFailures; i++ {
		w, _ := doReqFrom(t, h, "GET", "/admin/api/agents", "wrong-token", nil, attacker)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, w.Code)
		}
	}
	if w, _ := doReqFrom(t, h, "GET", "/admin/api/agents", "wrong-token", nil, attacker); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d against a Bearer route returned %d, want 429 — "+
			"the credential can be guessed at full speed", authMaxFailures+1, w.Code)
	}
	// One budget covers both credential paths, or the attacker just switches.
	if w, _ := doReqFrom(t, h, "POST", "/admin/api/login", "",
		map[string]string{"token": "wrong-token"}, attacker); w.Code != http.StatusTooManyRequests {
		t.Errorf("login from a throttled address returned %d, want 429 — "+
			"the two credential paths do not share a budget", w.Code)
	}
	// Deliberate: a throttled address is refused even with the right token.
	// Checking the credential first would make the limit cosmetic — every guess
	// would still be evaluated, and the correct one would still answer 200.
	if w, _ := doReqFrom(t, h, "GET", "/admin/api/agents", "test-token", nil, attacker); w.Code != http.StatusTooManyRequests {
		t.Errorf("a throttled address got %d with the right token, want 429", w.Code)
	}
	// Another operator is unaffected: the budget is per source address.
	if w, _ := doReqFrom(t, h, "GET", "/admin/api/agents", "test-token", nil, "203.0.113.10"); w.Code != http.StatusOK {
		t.Errorf("an unrelated address got %d, want 200", w.Code)
	}
}

// Successful requests are never counted toward the failure budget.
//
// A limiter that counts every request throttles the operator it is supposed to
// protect: the console polls /api/overview and fans out to several endpoints per
// view.
func TestSuccessfulRequestsAreNotRateLimited(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	h := srv.Handler()
	captureLog(t)

	const operator = "203.0.113.11"
	for i := 0; i < authMaxFailures*3; i++ {
		w, _ := doReqFrom(t, h, "GET", "/admin/api/agents", "test-token", nil, operator)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d from a working operator returned %d, want 200", i+1, w.Code)
		}
	}
}

// A rejected credential check leaves a record.
//
// The plane audited what operators did and nothing about who tried to get in:
// a wrong login and a Bearer probe wrote no log line and no audit_log row, so a
// guessing run against the surface was invisible afterwards — the operator
// could see the deletes an attacker made and not the attempts that preceded
// them.
func TestRejectedCredentialsLeaveARecord(t *testing.T) {
	srv, store, _, _, _ := newTestServer(t)
	h := srv.Handler()
	logs := captureLog(t)

	doReqFrom(t, h, "GET", "/admin/api/agents", "wrong-token", nil, "198.18.0.7")
	doReqFrom(t, h, "POST", "/admin/api/login", "", map[string]string{"token": "wrong"}, "198.18.0.8")

	rows, err := store.AuditTail(50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, e := range rows {
		if e.Action == "auth.failed" {
			seen[e.Target] = e.Detail
		}
	}
	if d, ok := seen["198.18.0.7"]; !ok || !strings.Contains(d, "/admin/api/agents") {
		t.Errorf("the Bearer rejection was not audited (rows: %+v)", seen)
	}
	if d, ok := seen["198.18.0.8"]; !ok || !strings.Contains(d, "/admin/api/login") {
		t.Errorf("the login rejection was not audited (rows: %+v)", seen)
	}
	for _, want := range []string{"198.18.0.7", "198.18.0.8", "/admin/api/agents", "/admin/api/login"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the process log does not mention %q:\n%s", want, logs.String())
		}
	}
}

// A flood past the budget is recorded once, not once per request.
//
// The record has to be bounded by the same limit as the traffic. Writing a log
// line and an audit row for every blocked request would let an attacker fill
// admin.db and the journal by continuing to send requests that are already
// being refused.
func TestAThrottledFloodIsRecordedOnce(t *testing.T) {
	srv, store, _, _, _ := newTestServer(t)
	h := srv.Handler()
	captureLog(t)

	const attacker = "198.18.0.9"
	for i := 0; i < authMaxFailures+40; i++ {
		doReqFrom(t, h, "GET", "/admin/api/agents", "wrong-token", nil, attacker)
	}
	if n := auditCount(t, store, "auth.failed"); n != authMaxFailures {
		t.Errorf("auth.failed rows = %d, want %d (one per attempt inside the budget)", n, authMaxFailures)
	}
	if n := auditCount(t, store, "auth.throttled"); n != 1 {
		t.Errorf("auth.throttled rows = %d, want 1 — forty blocked requests wrote %d records", n, n)
	}
}

// The Authorization header is parsed, not trimmed.
//
// It was read with strings.TrimPrefix(header, "Bearer "), which returns its
// input unchanged when the prefix is absent. A bare token with no scheme
// therefore authenticated, and "bearer <tok>" — valid per RFC 7235, whose
// scheme names are case-insensitive — did not. Both directions are wrong, and
// the accepting one is looser than the specification.
func TestAuthorizationHeaderIsParsedNotTrimmed(t *testing.T) {
	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer test-token", "test-token", true},
		{"bearer test-token", "test-token", true},
		{"BEARER test-token", "test-token", true},
		{"Bearer  test-token", "test-token", true}, // RFC 7235 allows 1*SP
		{"test-token", "", false},                  // no scheme at all
		{"Basic test-token", "", false},
		{"Bearertest-token", "", false},
		{"Bearer ", "", false},
		{"Bearer", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := bearerToken(c.header)
		if ok != c.ok || got != c.want {
			t.Errorf("bearerToken(%q) = (%q,%v), want (%q,%v)", c.header, got, ok, c.want, c.ok)
		}
	}

	// The same three shapes end to end. Each gets its own source address so a
	// rejection does not spend the next case's failure budget.
	srv, _, _, _, _ := newTestServer(t)
	h := srv.Handler()
	captureLog(t)
	e2e := []struct {
		header string
		want   int
	}{
		{"Bearer test-token", http.StatusOK},
		{"bearer test-token", http.StatusOK},
		{"test-token", http.StatusUnauthorized}, // a bare token is not a credential
	}
	for i, c := range e2e {
		r := httptest.NewRequest("GET", "/admin/api/agents", nil)
		r.Header.Set("Authorization", c.header)
		r.Header.Set("X-Real-Ip", "198.18.1."+string(rune('1'+i)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("Authorization: %q → %d, want %d", c.header, w.Code, c.want)
		}
	}
}

// Restoring an agent puts its governance state back too.
//
// The delete records a "delisted" moderation intent. The restore called
// SetModeration(aid, "", ...) — an empty status, which SetModeration rejects —
// and discarded the returned error, so the reset never ran and never said so.
// The agent came back into the registry still displayed as removed by an
// operator, in the risk queue and the enforcement view alike.
func TestRestoringAnAgentClearsTheDelistedFlag(t *testing.T) {
	srv, store, _, provAID, _ := newTestServer(t)
	h := srv.Handler()

	if w, _ := doReq(t, h, "DELETE", "/admin/api/agents/"+provAID, "test-token", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	mods, err := store.Moderations()
	if err != nil {
		t.Fatal(err)
	}
	if mods[provAID].Status != "delisted" {
		t.Fatalf("precondition: delete did not record delisted, got %q", mods[provAID].Status)
	}

	if w, _ := doReq(t, h, "POST", "/admin/api/deleted/"+provAID+"/restore", "test-token", nil); w.Code != http.StatusOK {
		t.Fatalf("restore: %d", w.Code)
	}
	mods, err = store.Moderations()
	if err != nil {
		t.Fatal(err)
	}
	if got := mods[provAID].Status; got != "ok" {
		t.Errorf("moderation after restore = %q, want %q — the agent is back in "+
			"the registry and still shown as removed by an operator", got, "ok")
	}
	// And the operator's view agrees: the governance columns are what an
	// operator actually reads, not the table.
	_, out := doReq(t, h, "GET", "/admin/api/agents", "test-token", nil)
	for _, a := range out["agents"].([]any) {
		m, _ := a.(map[string]any)
		if m["aid"] != provAID {
			continue
		}
		if s, ok := m["moderation"]; ok {
			t.Errorf("the agents view still reports moderation %v after a restore", s)
		}
	}
	_, out = doReq(t, h, "GET", "/admin/api/agents/"+provAID, "test-token", nil)
	if md, ok := out["moderation"].(map[string]any); ok && md["status"] != "ok" {
		t.Errorf("agent detail reports moderation %v after a restore", md["status"])
	}
}

// Deleting an official agent that was never registered is not recorded as a
// delete.
//
// It answered 200 {"ok":true} and wrote an action=official.delete row identical
// in shape to a real one. An audit trail that contains events which did not
// happen cannot be used to establish what did, which is the only thing it is
// for.
func TestDeletingAnAbsentOfficialIsNotAudited(t *testing.T) {
	srv, store, _, _, _ := newTestServer(t)
	h := srv.Handler()

	before := auditCount(t, store, "official.delete")
	w, _ := doReq(t, h, "DELETE", "/admin/api/official/never-registered", "test-token", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("deleting an unregistered id returned %d, want 404", w.Code)
	}
	if after := auditCount(t, store, "official.delete"); after != before {
		t.Errorf("the audit log grew by %d for a delete that removed nothing", after-before)
	}

	// A real delete still works and still leaves exactly one row.
	if w, _ := doReq(t, h, "POST", "/admin/api/official", "test-token", map[string]any{
		"id": "qa-official", "name": "QA", "tier": "community", "product_line": "community",
	}); w.Code != http.StatusOK {
		t.Fatalf("put official: %d %s", w.Code, w.Body.String())
	}
	if w, _ := doReq(t, h, "DELETE", "/admin/api/official/qa-official", "test-token", nil); w.Code != http.StatusOK {
		t.Fatalf("delete official: %d", w.Code)
	}
	if after := auditCount(t, store, "official.delete"); after != before+1 {
		t.Errorf("official.delete rows = %d, want %d — a real delete must be recorded", after, before+1)
	}
	// And deleting it a second time is now the absent case.
	if w, _ := doReq(t, h, "DELETE", "/admin/api/official/qa-official", "test-token", nil); w.Code != http.StatusNotFound {
		t.Errorf("second delete returned %d, want 404", w.Code)
	}
	if after := auditCount(t, store, "official.delete"); after != before+1 {
		t.Errorf("official.delete rows = %d after a repeated delete, want %d", after, before+1)
	}
}

// The official-agent directory is configuration, not something compiled in.
//
// The list used to be a Go literal naming a production host, its ssh user, its
// workdir, its systemd units and its monitor URL. Every fresh admin.db was
// seeded with it, so a single authenticated read (/api/official/{id}/monitor,
// or the probe behind /api/overview) opened an ssh connection to that machine
// from a deployment that had never been configured for it — and the binary
// carried the topology wherever it was distributed.
func TestTheOfficialDirectoryIsNotCompiledIn(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	// No config file: no official agents, and not an error.
	path := OfficialsConfigPath(dir)
	added, err := store.SeedOfficialsFromFile(path)
	if err != nil {
		t.Fatalf("a missing officials file must not be an error: %v", err)
	}
	if added != 0 {
		t.Errorf("a missing officials file added %d manifests", added)
	}
	offs, err := store.Officials()
	if err != nil {
		t.Fatal(err)
	}
	if len(offs) != 0 {
		t.Fatalf("a default deployment knows %d official agents; it must know none: %+v", len(offs), offs)
	}

	// The API says the same thing to an operator.
	hubDir, _, _ := buildHubDB(t)
	hub, err := OpenHubDB(hubDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	srv := NewServer(store, hub, NewOps(0), NewMonitorProxy("tok"), nil, NewVecClient(""), "test-token", "/admin")
	_, out := doReq(t, srv.Handler(), "GET", "/admin/api/official", "test-token", nil)
	if list, _ := out["officials"].([]any); len(list) != 0 {
		t.Errorf("/api/official returned %d entries with no config file: %v", len(list), list)
	}

	// With a config file the operator's own fleet loads, once.
	cfg := `[{"id":"qa-agent","name":"QA Agent","tier":"official","product_line":"anetos",
	          "runtime":{"host":"qa.invalid","units":["qa.service"]},
	          "ops":{"allowed":["status"]}}]`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if added, err = store.SeedOfficialsFromFile(path); err != nil || added != 1 {
		t.Fatalf("loading the config: added=%d err=%v", added, err)
	}
	if added, err = store.SeedOfficialsFromFile(path); err != nil || added != 0 {
		t.Fatalf("a second load must add nothing: added=%d err=%v", added, err)
	}
	m, err := store.Official("qa-agent")
	if err != nil || m.Runtime.Host != "qa.invalid" {
		t.Fatalf("the configured manifest did not load: %+v %v", m, err)
	}

	// A malformed file is reported, not silently treated as "no agents" — that
	// is the shape in which an operator loses their whole ops plane quietly.
	if err := os.WriteFile(path, []byte(`{"id":"not-an-array"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SeedOfficialsFromFile(path); err == nil {
		t.Error("a malformed officials file was accepted")
	}
}

// No production host is compiled into this package.
//
// The seed list is gone; this is what keeps it gone. A hostname in a shipped
// binary is both an infrastructure disclosure and, in this package, a machine
// that a read-only endpoint will ssh into.
func TestNoProductionHostIsCompiledIn(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range []string{"chatchat.space", "agentnetwork.org.cn"} {
			if bytes.Contains(b, []byte(host)) {
				t.Errorf("%s names %q — the fleet topology must live in the operator's "+
					"data directory (%s), not in the binary", n, host, OfficialsFileName)
			}
		}
	}
}

// The operator surface exposes its recovery path in the console.
//
// GET /api/deleted and POST /api/deleted/{aid}/restore existed and worked, and
// the single-file console called neither: the two delete buttons had no
// counterpart, so undoing a mis-click meant curl. An endpoint no page calls is
// reachable only by the person who wrote it.
func TestTheConsoleReachesTheRecoveryEndpoints(t *testing.T) {
	page := string(AdminHTML())
	for _, want := range []string{
		"api('/deleted')", // the archive listing
		"'/deleted/'+encodeURIComponent(aid)+'/restore'", // the restore call
		"'operations/recycle': vRecycle",                 // routed
		"id:'recycle'",                                   // and reachable from the sidebar
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the console does not contain %q — the archive has a writer, "+
				"an API and no way in from the page", want)
		}
	}
	// The delete confirmation says where the agent goes, since that is what an
	// operator reads at the moment they hesitate.
	if !strings.Contains(page, "回收站") {
		t.Error("the console never mentions the recycle bin")
	}
}

// The restore path the console calls is a real route with the shape the page
// assumes: a JSON object, not a bare list, and an aid in the path.
func TestRestoreEndpointShapeMatchesTheConsole(t *testing.T) {
	srv, _, _, provAID, _ := newTestServer(t)
	h := srv.Handler()
	if w, _ := doReq(t, h, "DELETE", "/admin/api/agents/"+provAID, "test-token", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	_, out := doReq(t, h, "GET", "/admin/api/deleted", "test-token", nil)
	list, _ := out["deleted"].([]any)
	if len(list) != 1 {
		t.Fatalf("archive listing has %d entries, want 1", len(list))
	}
	row, _ := list[0].(map[string]any)
	for _, k := range []string{"aid", "row", "deleted_at", "actor"} {
		if _, ok := row[k]; !ok {
			t.Errorf("archive entry has no %q; the console renders it", k)
		}
	}
	// The console parses "row" as JSON to show the name and caps.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(row["row"].(string)), &parsed); err != nil {
		t.Fatalf("the archived row is not JSON: %v", err)
	}
	if _, ok := parsed["name"]; !ok {
		t.Error("the archived row carries no name; the recycle bin would show only an AID")
	}
}

// SetModeration rejects a status it does not model.
//
// This is the validation the old restore path violated: it passed "" as the
// status, meaning "no longer under moderation", and the store rejected the call
// because "" is not one of ok|flagged|delisted. The restore discarded the
// error, so the rejection was silent. Pinned here because the reset in hRestore
// depends on "ok" being the value that means "not moderated" — if that ever
// changes, this fails next to the restore test rather than three releases later
// in a governance view.
func TestSetModerationRejectsAStatusItDoesNotModel(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.SetModeration("did:anet:x", "", "cleared"); err == nil {
		t.Error("an empty moderation status was accepted; a caller meaning " +
			"\"not moderated\" has to say \"ok\"")
	}
	for _, st := range []string{"ok", "flagged", "delisted"} {
		if err := store.SetModeration("did:anet:x", st, ""); err != nil {
			t.Errorf("SetModeration(%q) = %v", st, err)
		}
	}
	mods, err := store.Moderations()
	if err != nil {
		t.Fatal(err)
	}
	if mods["did:anet:x"].Status != "delisted" {
		t.Errorf("last write did not stick: %+v", mods["did:anet:x"])
	}
}

// The failure table cannot be grown without bound by a guesser who changes
// source address.
//
// Entries are pruned when an address is seen again, so an address that fails
// once and never returns would otherwise stay forever: one map entry per
// request is a memory leak an attacker controls.
func TestTheFailureTableIsBounded(t *testing.T) {
	l := newAuthLimiter(authMaxFailures, time.Hour) // nothing expires on its own
	for i := 0; i < maxTrackedIPs+50; i++ {
		l.record(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	l.mu.Lock()
	n := len(l.fails)
	l.mu.Unlock()
	if n >= maxTrackedIPs {
		t.Errorf("the failure table holds %d addresses with a bound of %d", n, maxTrackedIPs)
	}
	// It still limits after the sweep.
	const ip = "10.9.9.9"
	for i := 0; i < authMaxFailures; i++ {
		l.record(ip)
	}
	if blocked, _ := l.blocked(ip); !blocked {
		t.Error("the limiter stopped limiting after its table was swept")
	}
}

// A request with no credential is refused, but it is not a guess at the
// credential — guessing requires sending one. So it neither feeds the
// guess limiter nor is blocked by it. Counting or throttling these slows
// no attacker down; what it does do is make an address that once tripped
// the limiter — a browser opening the page, a health probe, a link
// somebody followed — unable to get an honest 401 for anything.
//
// Found by scripts/prodtest.sh against production: it does a rate-limit
// check and then asserts an unauthenticated call is refused with 401, and
// saw 429.
//
// Order matters here and the first version of this test got it wrong: it
// ran the credential-less loop BEFORE tripping the limiter, so the
// address was never blocked while those requests were made and the test
// could not tell "not counted" from "not blocked". The limiter is tripped
// first now.
func TestCredentiallessRequestsDoNotFeedTheGuessLimiter(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	h := srv.Handler()
	captureLog(t)

	const caller = "203.0.113.7"

	// Trip the limiter with real guesses, so the address IS blocked for the
	// rest of the test.
	throttled := false
	for i := 0; i < authMaxFailures*2; i++ {
		if w, _ := doReqFrom(t, h, "GET", "/admin/api/agents", "wrong-token", nil, caller); w.Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatal("setup: wrong tokens are not rate limited at all")
	}

	// From that same blocked address, a request with no credential must
	// still be answered 401 — refused, but told why.
	for i := 0; i < authMaxFailures*3; i++ {
		w, _ := doReqFrom(t, h, "GET", "/admin/api/agents", "", nil, caller)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("request %d with no credential from a throttled address: got %d, want 401",
				i+1, w.Code)
		}
	}

	// And those never lift or extend the block: a guess from the same
	// address is still throttled afterwards.
	if w, _ := doReqFrom(t, h, "GET", "/admin/api/agents", "wrong-token", nil, caller); w.Code != http.StatusTooManyRequests {
		t.Errorf("after the credential-less requests a guess got %d, want 429 — the block was lifted", w.Code)
	}
}
