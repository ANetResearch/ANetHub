package aghub_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// The hub as a witness (KEL §4.2, H-1 to H-5, H-10 to H-14): which key
// histories it registers and takes pushed, the times of new key events,
// relayauth only under the current key, and the witness notices it signs.

// newWitnessHub is a test hub whose /agents/kel:push limit does not get in
// the way of a test that pushes more than its burst (the limit has its own
// test).
func newWitnessHub(t *testing.T) (*httptest.Server, *aghub.Store) {
	t.Helper()
	srv, store := newHubWithStore(t)
	serverOf(t, srv).SetKELPushRateForTest(1e9, 1<<30)
	return srv, store
}

// kelURL is c's KEL as a request carries it: base64url (core CORE-E5).
func kelURL(t *testing.T, c *identity.Controller) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(kelBytes(t, c))
}

func kelBytes(t *testing.T, c *identity.Controller) []byte {
	t.Helper()
	b, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// registerAsIs posts body to /register signed as c, after the operator
// admitted c, and nothing else: no witness is named for it (registerFunded
// moves an agent to the hub it registers at).
func registerAsIs(t *testing.T, srv *httptest.Server, c *identity.Controller, body map[string]any) (int, []byte) {
	t.Helper()
	admitForTest(t, srv, c.AID())
	return signedDo(t, srv, c, relayauth.ActionRegister, http.MethodPost, "/register", body)
}

// pushKEL posts {aid, kel} to /agents/kel:push.
func pushKEL(t *testing.T, srv *httptest.Server, aid, kel string) (int, []byte) {
	t.Helper()
	return post(t, srv.URL+aghub.KELPushPath, map[string]any{"aid": aid, "kel": kel})
}

// reasonIs reports whether b is a wire-3 refusal with reason.
func reasonIs(b []byte, reason string) bool {
	var r struct {
		Reason string `json:"reason"`
	}
	return json.Unmarshal(b, &r) == nil && r.Reason == reason
}

// snapshotOf is a second controller of c's identity as it is now: a copy to
// sign with a key c then rotates away from, or to fork its history from.
func snapshotOf(t *testing.T, c *identity.Controller) *identity.Controller {
	t.Helper()
	blob, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	s, err := identity.Restore(blob)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// tsAfter is a time for c's next key event: a millisecond after its last
// one, or now when that is later.
func tsAfter(c *identity.Controller) uint64 {
	kel := c.KEL()
	return max(kel[len(kel)-1].Event.Timestamp+1, uint64(time.Now().UnixMilli()))
}

// storedKELOf is the key history GET /agents/{aid}/kel serves, and whether
// it says the AID is registered.
func storedKELOf(t *testing.T, srv *httptest.Server, aid string) ([]identity.SignedEvent, bool) {
	t.Helper()
	code, b := getJSON(t, srv.URL+"/agents/"+aid+"/kel")
	if code != http.StatusOK {
		t.Fatalf("GET /agents/%s/kel: %d %s", aid, code, b)
	}
	var v aghub.AgentKELView
	if err := json.Unmarshal(b, &v); err != nil || v.AID != aid {
		t.Fatalf("GET /agents/%s/kel: %s", aid, b)
	}
	raw, err := base64.RawURLEncoding.DecodeString(v.KEL)
	if err != nil {
		t.Fatalf("the served kel is not base64url: %v", err)
	}
	kel, err := identity.UnmarshalKEL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return kel, v.Registered
}

// checkNotice verifies a notice this hub signed about c's KEL tip, for a
// message arriving now.
func checkNotice(t *testing.T, srv *httptest.Server, notice []byte, c *identity.Controller) identity.NoticeBody {
	t.Helper()
	return checkNoticeAt(t, srv, notice, c, time.Now())
}

// checkNoticeAt is checkNotice for a message arriving at arrival.
func checkNoticeAt(t *testing.T, srv *httptest.Server, notice []byte, c *identity.Controller, arrival time.Time) identity.NoticeBody {
	t.Helper()
	if err := identity.VerifyNotice(notice, c.KEL(), hubKELsOf(t, srv), uint64(arrival.UnixMilli())); err != nil {
		t.Fatalf("the notice does not confirm the KEL's tip: %v", err)
	}
	body, _, err := identity.DecodeNotice(notice)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// pollAnswer polls as c and returns the answer.
func pollAnswer(t *testing.T, srv *httptest.Server, c *identity.Controller) aghub.RelayPollResponse {
	t.Helper()
	code, b := signedDo(t, srv, c, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("poll: %d %s", code, b)
	}
	var out aghub.RelayPollResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// KEL H-1 1: a hub registers an agent only when the tip of its key history
// names this hub as its witness. Neither an agent that names no witness
// yet, nor one that names another hub, nor a hub's own identity (toad 0)
// is registered, and nothing is written; the agent that names it is, and
// the answer carries the notice it signed (H-5, H-11).
func TestRegisterRequiresWitnessIsThisHub(t *testing.T) {
	srv, store := newWitnessHub(t)
	hubAID := hubAIDOf(t, srv)
	other, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := identitytest.Agent()
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := aghub.NewAgentWitnessedBy(other.AID(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	aHub, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*identity.Controller{
		"an agent that names no witness yet": pending,
		"an agent that names another hub":    elsewhere,
		"a hub's identity":                   aHub,
	} {
		code, b := registerAsIs(t, srv, c, registerBody(t, c, "n", []string{"work.do"}))
		if code != http.StatusBadRequest || !reasonIs(b, "witness_not_this_hub") {
			t.Errorf("%s: %d %s, want 400 witness_not_this_hub", name, code, b)
		}
		if store.KnowsAgent(c.AID()) {
			t.Errorf("%s: registered", name)
		}
	}
	here, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	code, b := registerAsIs(t, srv, here, registerBody(t, here, "n", []string{"work.do"}))
	var out aghub.RegisterResponse
	if code != http.StatusOK || json.Unmarshal(b, &out) != nil || out.KeyStateNotice == "" || out.KeyStateNoticeError != "" {
		t.Fatalf("an agent that names this hub: %d %s, want 200 with its notice", code, b)
	}
	notice, err := base64.RawURLEncoding.DecodeString(out.KeyStateNotice)
	if err != nil {
		t.Fatalf("key_state_notice is not base64url: %v", err)
	}
	body := checkNotice(t, srv, notice, here)
	if body.Witness != hubAID || body.AID != here.AID() || body.Seq != here.CurrentSeq() {
		t.Errorf("the notice states %+v", body)
	}
}

// KEL H-1, core §2.12.2: check_only is asked before an agent names its
// witness, so the witness condition is not checked for it; the rest of
// H-1 is (a dip, the time of a new event), and the full registration still
// needs the witness.
func TestCheckOnlySkipsWitnessCondition(t *testing.T) {
	srv, _ := newWitnessHub(t)
	hubAID := hubAIDOf(t, srv)
	c, err := identitytest.Agent() // only its icp: it has not joined anything
	if err != nil {
		t.Fatal(err)
	}
	checkOnly := func(c, signer *identity.Controller) (int, []byte) {
		t.Helper()
		body := registerBody(t, c, "n", nil)
		body["check_only"] = true
		admitForTest(t, srv, c.AID())
		return signedDo(t, srv, signer, relayauth.ActionRegister, http.MethodPost, "/register", body)
	}
	if code, b := checkOnly(c, c); code != http.StatusOK || !strings.Contains(string(b), `"status":"admitted"`) {
		t.Fatalf("check_only before naming a witness: %d %s, want 200 admitted", code, b)
	}
	if code, b := registerAsIs(t, srv, c, registerBody(t, c, "n", nil)); code != http.StatusBadRequest || !reasonIs(b, "witness_not_this_hub") {
		t.Fatalf("the registration before naming a witness: %d %s, want 400 witness_not_this_hub", code, b)
	}
	if err := identitytest.SwitchWitness(c, hubAID, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if code, b := registerAsIs(t, srv, c, registerBody(t, c, "n", nil)); code != http.StatusOK {
		t.Fatalf("the registration once it names this hub: %d %s", code, b)
	}
	// An icp dated 10 minutes ahead of the hub's clock (R-9).
	future, err := identity.InceptAgent(uint64(time.Now().Add(10 * time.Minute).UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	if code, b := checkOnly(future, future); code != http.StatusBadRequest || !reasonIs(b, "kel_ts_out_of_window") {
		t.Errorf("check_only with an event from the future: %d %s, want 400 kel_ts_out_of_window", code, b)
	}
	// A deactivated identity (H-1 2), signed with the key it had.
	gone, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	signer := snapshotOf(t, gone)
	if err := identitytest.Deactivate(gone, tsAfter(gone)); err != nil {
		t.Fatal(err)
	}
	if code, b := checkOnly(gone, signer); code != http.StatusGone || !reasonIs(b, "aid_deactivated") {
		t.Errorf("check_only of a deactivated identity: %d %s, want 410 aid_deactivated", code, b)
	}
}

// KEL H-1 3, R-9, R-10: the events a registration adds are taken within 5
// minutes of the hub's clock (both bounds inclusive) when they name this
// hub; an earlier event naming another hub is held to R-9 only; and a key
// history the hub already holds is not checked again.
func TestRegisterChecksTheTimesOfNewEvents(t *testing.T) {
	srv, store := newWitnessHub(t)
	hubAID := hubAIDOf(t, srv)
	base := time.UnixMilli(time.Now().UnixMilli())
	store.SetClockForTest(func() time.Time { return base })
	for _, tc := range []struct {
		name string
		at   time.Duration
		want string
	}{
		{"5 minutes before the hub's clock", -5 * time.Minute, ""},
		{"5 minutes and 1 ms before", -5*time.Minute - time.Millisecond, "dated more than 5 minutes before"},
		{"5 minutes after", 5 * time.Minute, ""},
		{"5 minutes and 1 ms after", 5*time.Minute + time.Millisecond, "dated more than 5 minutes after"},
	} {
		c, err := aghub.NewAgentWitnessedBy(hubAID, base.Add(tc.at))
		if err != nil {
			t.Fatal(err)
		}
		code, b := registerAsIs(t, srv, c, registerBody(t, c, "n", nil))
		switch {
		case tc.want == "" && code != http.StatusOK:
			t.Errorf("%s: %d %s, want 200", tc.name, code, b)
		case tc.want != "" && (code != http.StatusBadRequest || !reasonIs(b, "kel_ts_out_of_window") || !strings.Contains(string(b), tc.want)):
			t.Errorf("%s: %d %s, want 400 kel_ts_out_of_window saying %q", tc.name, code, b, tc.want)
		}
	}
	// A hub switch: the rot that named the old hub an hour ago is new here
	// but not this hub's to judge (R-9 only); the one naming this hub is.
	other, _ := identitytest.Hub()
	mover, err := aghub.NewAgentWitnessedBy(other.AID(), base.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := identitytest.SwitchWitness(mover, hubAID, uint64(base.UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if code, b := registerAsIs(t, srv, mover, registerBody(t, mover, "n", nil)); code != http.StatusOK {
		t.Fatalf("an agent moving here: %d %s", code, b)
	}
	// The same history an hour later adds nothing, so nothing is late.
	later := base.Add(time.Hour)
	store.SetClockForTest(func() time.Time { return later })
	if code, b := registerAsIs(t, srv, mover, registerBody(t, mover, "n", nil)); code != http.StatusOK {
		t.Fatalf("registering again an hour later: %d %s", code, b)
	}
}

// KEL H-4, §2.7: a push is taken when the key history extends the one held,
// or is the same; the same one again changes nothing (unchanged: true), so
// a push repeated is idempotent; an older, forked, invalid or foreign
// history is refused, and so is a push for an AID the hub holds no history
// of. A push for an agent that left extends its tombstone.
func TestKELPushExtendsOnlyAndIsIdempotent(t *testing.T) {
	srv, store := newWitnessHub(t)
	c, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, c, "Agent", nil)
	answer := func(code int, b []byte) aghub.KELPushResponse {
		t.Helper()
		var out aghub.KELPushResponse
		if code != http.StatusOK || json.Unmarshal(b, &out) != nil {
			t.Fatalf("push: %d %s", code, b)
		}
		return out
	}
	tip := func(c *identity.Controller) (uint64, string) {
		kel := c.KEL()
		return kel[len(kel)-1].Event.Seq, kel[len(kel)-1].EventID
	}
	// The history held, pushed: unchanged.
	if out := answer(pushKEL(t, srv, c.AID(), kelURL(t, c))); !out.Unchanged || out.AID != c.AID() {
		t.Fatalf("the same history: %+v", out)
	} else if seq, head := tip(c); out.Seq != seq || out.Head != head {
		t.Fatalf("the same history answers %d %s, want the tip %d %s", out.Seq, out.Head, seq, head)
	}
	before := snapshotOf(t, c)
	fork := snapshotOf(t, c)
	if err := identitytest.Rotate(c, tsAfter(c)); err != nil {
		t.Fatal(err)
	}
	out := answer(pushKEL(t, srv, c.AID(), kelURL(t, c)))
	if seq, head := tip(c); out.Unchanged || out.Seq != seq || out.Head != head {
		t.Fatalf("an extension: %+v, want the new tip %d %s", out, seq, head)
	}
	if kel, registered := storedKELOf(t, srv, c.AID()); len(kel) != len(c.KEL()) || !registered {
		t.Fatalf("the hub holds %d events (registered %v), want %d", len(kel), registered, len(c.KEL()))
	}
	if out := answer(pushKEL(t, srv, c.AID(), kelURL(t, c))); !out.Unchanged {
		t.Fatalf("the extension pushed again: %+v", out)
	}
	if code, b := pushKEL(t, srv, c.AID(), kelURL(t, before)); code != http.StatusConflict || !reasonIs(b, "kel_rollback") {
		t.Errorf("an older history: %d %s, want 409 kel_rollback", code, b)
	}
	if err := identitytest.Rotate(fork, tsAfter(c)+7); err != nil {
		t.Fatal(err)
	}
	if code, b := pushKEL(t, srv, c.AID(), kelURL(t, fork)); code != http.StatusConflict || !reasonIs(b, "kel_fork") {
		t.Errorf("a forked history: %d %s, want 409 kel_fork", code, b)
	}
	stranger, _ := aghub.NewAgentForTest()
	for name, tc := range map[string]struct {
		aid, kel string
		status   int
		reason   string
	}{
		"an AID the hub holds nothing of": {stranger.AID(), kelURL(t, stranger), http.StatusNotFound, "unknown_aid"},
		"another identity's history":      {c.AID(), kelURL(t, stranger), http.StatusBadRequest, "kel_invalid"},
		"not a key history":               {c.AID(), base64.RawURLEncoding.EncodeToString([]byte("no kel")), http.StatusBadRequest, "kel_invalid"},
		"standard base64":                 {c.AID(), base64.StdEncoding.EncodeToString(kelBytes(t, c)) + "=", http.StatusBadRequest, "kel_invalid"},
		"an aid that is not an AID":       {"bafy-not-an-aid", kelURL(t, c), http.StatusBadRequest, "bad_request"},
	} {
		if code, b := pushKEL(t, srv, tc.aid, tc.kel); code != tc.status || !reasonIs(b, tc.reason) {
			t.Errorf("%s: %d %s, want %d %s", name, code, b, tc.status, tc.reason)
		}
	}
	if code, b := post(t, srv.URL+aghub.KELPushPath, map[string]any{"aid": c.AID(), "kel": kelURL(t, c), "extra": 1}); code != http.StatusBadRequest || !reasonIs(b, "bad_request") {
		t.Errorf("an unknown member: %d %s, want 400 bad_request (CORE-E7)", code, b)
	}
	if store.KnowsAgent(stranger.AID()) {
		t.Error("a push registered an unknown AID")
	}
	// R-9 holds for a push: an event an hour ahead is refused.
	ahead := snapshotOf(t, c)
	if err := identitytest.Rotate(ahead, uint64(time.Now().Add(time.Hour).UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if code, b := pushKEL(t, srv, c.AID(), kelURL(t, ahead)); code != http.StatusBadRequest || !reasonIs(b, "kel_ts_out_of_window") {
		t.Errorf("an event an hour ahead: %d %s, want 400 kel_ts_out_of_window", code, b)
	}
	// An agent that left: its tombstone grows with what it pushes.
	if code, b := leave(t, srv, c); code != http.StatusOK {
		t.Fatalf("leave: %d %s", code, b)
	}
	if err := identitytest.Rotate(c, tsAfter(c)); err != nil {
		t.Fatal(err)
	}
	if out := answer(pushKEL(t, srv, c.AID(), kelURL(t, c))); out.Unchanged {
		t.Fatalf("an extension of a tombstone: %+v", out)
	}
	if kel, registered := storedKELOf(t, srv, c.AID()); len(kel) != len(c.KEL()) || registered {
		t.Fatalf("the tombstone holds %d events (registered %v), want %d, not registered", len(kel), registered, len(c.KEL()))
	}
	if store.KnowsAgent(c.AID()) {
		t.Error("a push registered an agent that had left")
	}
}

// KEL R-10 at a push: an event this hub is the first to take as its witness
// (a rot that names it) is held to its clock from below as well; one that
// names another hub, pushed to the old witness, only from above (R-9). The
// old witness takes a late push of the agent's move (M27).
func TestKELPushTimesOnlyTheWitnessesOwnEvents(t *testing.T) {
	srv, store := newWitnessHub(t)
	hubAID := hubAIDOf(t, srv)
	// An agent that joined two hours ago.
	joined := time.Now().Add(-2 * time.Hour)
	c, err := aghub.NewAgentWitnessedBy(hubAID, joined)
	if err != nil {
		t.Fatal(err)
	}
	store.SetClockForTest(func() time.Time { return joined })
	register(t, srv, c, "Agent", nil)
	store.SetClockForTest(nil)
	anHourAgo := uint64(time.Now().Add(-time.Hour).UnixMilli())
	stale := snapshotOf(t, c)
	if err := identitytest.Rotate(stale, anHourAgo); err != nil {
		t.Fatal(err)
	}
	if code, b := pushKEL(t, srv, c.AID(), kelURL(t, stale)); code != http.StatusBadRequest || !reasonIs(b, "kel_ts_out_of_window") {
		t.Errorf("a rot naming this hub, an hour old: %d %s, want 400 kel_ts_out_of_window", code, b)
	}
	other, _ := identitytest.Hub()
	if err := identitytest.SwitchWitness(c, other.AID(), anHourAgo); err != nil {
		t.Fatal(err)
	}
	if code, b := pushKEL(t, srv, c.AID(), kelURL(t, c)); code != http.StatusOK {
		t.Errorf("a move to another hub, pushed an hour late to the old one: %d %s, want 200", code, b)
	}
}

// KEL H-4: a pushed history that ends in a dip deregisters the agent
// through the one deregistration path (DeregisterTx): the tombstone holds
// the dip, the directory entry and the notice go, and the identity cannot
// register again.
func TestKELPushDipDeregisters(t *testing.T) {
	srv, store := newWitnessHub(t)
	c, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	registerWithKeys(t, srv, c, "Agent", []string{"work.do"})
	if lookUpInBucket(t, srv, c.AID(), "") == nil {
		t.Fatal("setup: no directory entry")
	}
	if _, _, _, _, ok := store.NoticeRowForTest(c.AID()); !ok {
		t.Fatal("setup: no notice")
	}
	signer := snapshotOf(t, c)
	if err := identitytest.Deactivate(c, tsAfter(c)); err != nil {
		t.Fatal(err)
	}
	code, b := pushKEL(t, srv, c.AID(), kelURL(t, c))
	var out aghub.KELPushResponse
	if code != http.StatusOK || json.Unmarshal(b, &out) != nil || out.Unchanged || out.Seq != uint64(len(c.KEL())-1) {
		t.Fatalf("push the dip: %d %s", code, b)
	}
	if store.KnowsAgent(c.AID()) {
		t.Fatal("still registered after its dip")
	}
	if kel, registered := storedKELOf(t, srv, c.AID()); registered || kel[len(kel)-1].Event.Type != identity.Deactivation {
		t.Fatalf("the tombstone: registered %v, last event %s", registered, kel[len(kel)-1].Event.Type)
	}
	if lookUpInBucket(t, srv, c.AID(), "") != nil {
		t.Error("the directory still serves its entry")
	}
	if _, _, _, _, ok := store.NoticeRowForTest(c.AID()); ok {
		t.Error("its notice is still cached")
	}
	if code, b := registerAsIs(t, srv, signer, map[string]any{"aid": c.AID(), "kel": kelURL(t, c)}); code != http.StatusGone || !reasonIs(b, "aid_deactivated") {
		t.Errorf("registering the deactivated identity: %d %s, want 410 aid_deactivated", code, b)
	}
	if code, b := pushKEL(t, srv, c.AID(), kelURL(t, c)); code != http.StatusOK || !strings.Contains(string(b), `"unchanged":true`) {
		t.Errorf("the dip pushed again: %d %s, want 200 unchanged", code, b)
	}
}

// KEL H-4, H-10 3, M17: an agent that moved to another hub pushes its move
// to the old one, which stops signing its notice at once, drops the key set
// its retired key signed and the notice it held (H-2), and keeps the
// registration and the mailbox until the agent leaves.
func TestKELPushToTheOldWitnessStopsItsNotice(t *testing.T) {
	srv, store := newWitnessHub(t)
	c, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	registerWithKeys(t, srv, c, "Agent", nil)
	if p := pollAnswer(t, srv, c); p.KeyStateNotice == "" {
		t.Fatalf("setup: no notice before the move: %+v", p)
	}
	newHub, _ := identitytest.Hub()
	if err := identitytest.SwitchWitness(c, newHub.AID(), tsAfter(c)); err != nil {
		t.Fatal(err)
	}
	if code, b := pushKEL(t, srv, c.AID(), kelURL(t, c)); code != http.StatusOK {
		t.Fatalf("push the move: %d %s", code, b)
	}
	if n, why, err := store.NoticeFor(c.AID()); err != nil || n != nil || why != aghub.NoticeErrNotWitness {
		t.Fatalf("the old witness after the move: notice %x, %q, %v; want none, not_witness", n, why, err)
	}
	if _, _, _, _, ok := store.NoticeRowForTest(c.AID()); ok {
		t.Error("the old witness still caches the notice of the old tip")
	}
	p := pollAnswer(t, srv, c) // signed with the key of the move
	if p.KeyStateNotice != "" || p.KeyStateNoticeError != aghub.NoticeErrNotWitness {
		t.Errorf("the poll after the move: %+v, want key_state_notice_error not_witness", p)
	}
	if code, b := getJSON(t, srv.URL+"/agents/"+c.AID()+"/keys"); code != http.StatusNotFound {
		t.Errorf("the key set the retired key signed is still served: %d %s", code, b)
	}
	if lookUpInBucket(t, srv, c.AID(), "") != nil {
		t.Error("the old witness's directory still serves the agent")
	}
	if !store.KnowsAgent(c.AID()) {
		t.Error("the move deregistered the agent before it left")
	}
	if code, b := registerAsIs(t, srv, c, registerBody(t, c, "Agent", nil)); code != http.StatusBadRequest || !reasonIs(b, "witness_not_this_hub") {
		t.Errorf("registering at the old witness: %d %s, want 400 witness_not_this_hub", code, b)
	}
}

// KEL H-3, core CORE-K16, M16: a signed request is taken under the tip of
// the signer's key history only. A signature that verifies under a key the
// signer rotated away from is 401 key_retired even inside the signing-time
// window, where the signature's own time is before the rotation; anything
// else that does not verify is 401 unauthorized.
func TestRetiredKeyRelayauthIs401KeyRetired(t *testing.T) {
	for _, emergency := range []bool{false, true} {
		srv, _ := newWitnessHub(t)
		c, err := aghub.NewAgentForTest()
		if err != nil {
			t.Fatal(err)
		}
		register(t, srv, c, "Agent", nil)
		old := snapshotOf(t, c)
		// The rotation is dated 2 minutes ahead (R-9 takes up to 5), so a
		// request the retired key signs now is signed before it: a check
		// of the signature at its own time would take it.
		rotate := identitytest.Rotate
		if emergency {
			rotate = identitytest.RotateEmergency
		}
		if err := rotate(c, uint64(time.Now().Add(2*time.Minute).UnixMilli())); err != nil {
			t.Fatal(err)
		}
		if code, b := registerCode(t, srv, c, "Agent", nil); code != http.StatusOK {
			t.Fatalf("register the rotation: %d %s", code, b)
		}
		code, b := signedDo(t, srv, old, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{})
		if code != http.StatusUnauthorized || !reasonIs(b, "key_retired") {
			t.Errorf("emergency %v: a poll signed with the retired key: %d %s, want 401 key_retired", emergency, code, b)
		}
		// The retired key cannot register the history it retired either.
		if code, b := signedDo(t, srv, old, relayauth.ActionRegister, http.MethodPost, "/register",
			map[string]any{"aid": c.AID(), "kel": kelURL(t, c)}); code != http.StatusUnauthorized || !reasonIs(b, "key_retired") {
			t.Errorf("emergency %v: a registration signed with the retired key: %d %s, want 401 key_retired", emergency, code, b)
		}
		// A bad signature, and a key state the history does not have, are
		// unauthorized.
		req := signedRequest(t, srv, c, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{})
		sig, _ := relayauth.DecodeSig(req.Header.Get(relayauth.HeaderSig))
		req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(flipped(sig)))
		if code, b, _ := send(t, req); code != http.StatusUnauthorized || !reasonIs(b, "unauthorized") {
			t.Errorf("emergency %v: a bad signature: %d %s, want 401 unauthorized", emergency, code, b)
		}
		req = signedRequest(t, srv, c, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{})
		req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(c.CurrentSeq()+1, 10))
		if code, b, _ := send(t, req); code != http.StatusUnauthorized || !reasonIs(b, "unauthorized") {
			t.Errorf("emergency %v: a key state past the history: %d %s, want 401 unauthorized", emergency, code, b)
		}
		if p := pollAnswer(t, srv, c); p.KeyStateNotice == "" {
			t.Errorf("emergency %v: the current key's poll: %+v", emergency, p)
		}
	}
}

// KEL H-10, H-13, H-14, M14: the hub signs a notice for an AID only while
// it is registered here, its key history's tip names this hub, and the tip
// is not a dip; the notice states the tip of the history this hub holds.
// Otherwise the answer says why, and the hub never signs for itself.
func TestNoticeOnlyForTipOfWitnessedAdmittedAID(t *testing.T) {
	srv, store := newWitnessHub(t)
	hubAID := hubAIDOf(t, srv)
	put := func(c *identity.Controller) {
		t.Helper()
		if err := store.PutAgent(c.AID(), "n", nil, kelBytes(t, c)); err != nil {
			t.Fatal(err)
		}
	}
	witnessed, _ := aghub.NewAgentForTest()
	register(t, srv, witnessed, "Witnessed", nil)
	other, _ := identitytest.Hub()
	elsewhere, _ := aghub.NewAgentWitnessedBy(other.AID(), time.Now())
	pending, _ := identitytest.Agent()
	aHub, _ := identitytest.Hub()
	for _, c := range []*identity.Controller{elsewhere, pending, aHub} {
		put(c) // as the store holds them; no registration would take them
	}
	left, _ := aghub.NewAgentForTest()
	register(t, srv, left, "Left", nil)
	if code, b := leave(t, srv, left); code != http.StatusOK {
		t.Fatalf("leave: %d %s", code, b)
	}
	never, _ := aghub.NewAgentForTest()

	n, why, err := store.NoticeFor(witnessed.AID())
	if err != nil || n == nil || why != "" {
		t.Fatalf("the agent this hub witnesses: %x %q %v", n, why, err)
	}
	body := checkNotice(t, srv, n, witnessed)
	kel, _ := storedKELOf(t, srv, witnessed.AID())
	if body.AID != witnessed.AID() || body.Witness != hubAID || body.Seq != kel[len(kel)-1].Event.Seq ||
		body.Head != kel[len(kel)-1].EventID {
		t.Errorf("the notice states %+v, not the tip of the history held", body)
	}
	if p := pollAnswer(t, srv, witnessed); p.KeyStateNotice != base64.RawURLEncoding.EncodeToString(n) || p.KeyStateNoticeError != "" {
		t.Errorf("the poll carries %+v, want the notice", p)
	}
	for name, tc := range map[string]struct {
		aid, why string
	}{
		"an agent whose tip names another hub": {elsewhere.AID(), aghub.NoticeErrNotWitness},
		"an agent that names no witness yet":   {pending.AID(), aghub.NoticeErrNotWitness},
		"a hub's identity":                     {aHub.AID(), aghub.NoticeErrNotWitness},
		"this hub itself":                      {hubAID, aghub.NoticeErrNotWitness},
		"an agent that left":                   {left.AID(), aghub.NoticeErrNotAdmitted},
		"an AID never registered here":         {never.AID(), aghub.NoticeErrNotAdmitted},
	} {
		n, why, err := store.NoticeFor(tc.aid)
		if err != nil || n != nil || why != tc.why {
			t.Errorf("%s: notice %x, %q, %v; want none, %s", name, n, why, err, tc.why)
		}
		if _, _, _, _, ok := store.NoticeRowForTest(tc.aid); ok {
			t.Errorf("%s: a notice was cached", name)
		}
	}
	if p := pollAnswer(t, srv, elsewhere); p.KeyStateNotice != "" || p.KeyStateNoticeError != aghub.NoticeErrNotWitness {
		t.Errorf("the poll of an agent whose tip names another hub: %+v", p)
	}
}

// KEL H-12: revoking an admission deregisters the agent (DeregisterTx), and
// the notice it held goes in the same transaction; no notice is signed for
// it afterwards.
func TestAdmissionRevokeStopsNotice(t *testing.T) {
	srv, store := newWitnessHub(t)
	c, _ := aghub.NewAgentForTest()
	registerWithKeys(t, srv, c, "Agent", nil)
	if p := pollAnswer(t, srv, c); p.KeyStateNotice == "" {
		t.Fatalf("setup: %+v", p)
	}
	if _, err := store.RevokeAdmission(c.AID()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, ok := store.NoticeRowForTest(c.AID()); ok {
		t.Error("the revoked agent's notice is still cached")
	}
	if n, why, err := store.NoticeFor(c.AID()); err != nil || n != nil || why != aghub.NoticeErrNotAdmitted {
		t.Errorf("after the revocation: %x %q %v; want none, not_admitted", n, why, err)
	}
	if code, b := signedDo(t, srv, c, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{}); code != http.StatusUnauthorized {
		t.Errorf("the revoked agent's poll: %d %s, want 401", code, b)
	}
	if lookUpInBucket(t, srv, c.AID(), "") != nil {
		t.Error("the revoked agent is still in the directory")
	}
}

// KEL H-11: a notice is cached by (aid, seq, head) and served again, to
// every reader, while it is at most NoticeReissue old; a newer one replaces
// it after that, and at once when the key history moves. The directory
// entry, the registry and the poll carry the one notice.
func TestNoticeCacheReusedWithin10Min(t *testing.T) {
	srv, store := newWitnessHub(t)
	t0 := time.UnixMilli(time.Now().UnixMilli())
	now := t0
	store.SetClockForTest(func() time.Time { return now })
	c, _ := aghub.NewAgentForTest()
	registerWithKeys(t, srv, c, "Agent", []string{"work.do"})
	n1, _, err := store.NoticeFor(c.AID())
	if err != nil || n1 == nil {
		t.Fatalf("first notice: %v", err)
	}
	if b := checkNoticeAt(t, srv, n1, c, now); b.ObservedAt != uint64(t0.UnixMilli()) {
		t.Fatalf("observed_at %d, want the hub's clock %d", b.ObservedAt, t0.UnixMilli())
	}
	carried := func(t *testing.T) (dir, listing, poll []byte) {
		t.Helper()
		if e := lookUpInBucket(t, srv, c.AID(), ""); e != nil {
			dir = e.Notice
		}
		for _, a := range getAgentsList(t, srv) {
			if a.AID == c.AID() {
				listing, _ = base64.RawURLEncoding.DecodeString(a.KeyStateNotice)
			}
		}
		poll, _ = base64.RawURLEncoding.DecodeString(pollAnswer(t, srv, c).KeyStateNotice)
		return dir, listing, poll
	}
	now = t0.Add(aghub.NoticeReissue)
	if n, _, _ := store.NoticeFor(c.AID()); !bytes.Equal(n, n1) {
		t.Fatal("a notice NoticeReissue old was not served again")
	}
	if d, l, p := carried(t); !bytes.Equal(d, n1) || !bytes.Equal(l, n1) || !bytes.Equal(p, n1) {
		t.Fatalf("the directory, listing and poll carry other notices than the cached one")
	}
	now = t0.Add(aghub.NoticeReissue + time.Millisecond)
	n2, _, _ := store.NoticeFor(c.AID())
	if bytes.Equal(n2, n1) || checkNoticeAt(t, srv, n2, c, now).ObservedAt != uint64(now.UnixMilli()) {
		t.Fatal("a notice older than NoticeReissue was served again")
	}
	if d, l, p := carried(t); !bytes.Equal(d, n2) || !bytes.Equal(l, n2) || !bytes.Equal(p, n2) {
		t.Fatal("the directory, listing and poll do not all carry the new notice")
	}
	// The history moves: the notice of the new tip at once.
	if err := identitytest.Rotate(c, uint64(now.UnixMilli())+1); err != nil {
		t.Fatal(err)
	}
	k := resignKeySet(t, c, storedKeys(t, srv.URL, c.AID()))
	body := registerBody(t, c, "Agent", []string{"work.do"})
	withEncKeys(t, srv, body, c.AID(), k)
	code, b := registerFunded(t, srv, c, body)
	var out aghub.RegisterResponse
	if code != http.StatusOK || json.Unmarshal(b, &out) != nil {
		t.Fatalf("register the rotation: %d %s", code, b)
	}
	n3, _ := base64.RawURLEncoding.DecodeString(out.KeyStateNotice)
	if bytes.Equal(n3, n2) || checkNoticeAt(t, srv, n3, c, now).Seq != c.CurrentSeq() {
		t.Fatal("the registration of the rotation did not carry the new tip's notice")
	}
	// A clock that stepped back does not serve a notice from its future.
	now = t0
	if n4, _, _ := store.NoticeFor(c.AID()); bytes.Equal(n4, n3) {
		t.Fatal("a notice observed after the hub's clock was served again")
	}
}

// getAgentsList is GET /agents.
func getAgentsList(t *testing.T, srv *httptest.Server) []aghub.AgentView {
	t.Helper()
	code, b := getJSON(t, srv.URL+"/agents")
	if code != http.StatusOK {
		t.Fatalf("GET /agents: %d %s", code, b)
	}
	var out struct {
		Agents []aghub.AgentView `json:"agents"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out.Agents
}

// RunNoticeRefresher: the notice of every agent with a key set, the agents
// a sender can find, is kept at most NoticeReissue old whether or not the
// agent polls (KEL D-26), and the directory entry carries the new one;
// others are left alone.
func TestNoticesOfAgentsWithAKeySetAreKeptFresh(t *testing.T) {
	srv, store := newWitnessHub(t)
	t0 := time.UnixMilli(time.Now().UnixMilli())
	now := t0
	store.SetClockForTest(func() time.Time { return now })
	keyed, bare := twoAgents(t)
	registerWithKeys(t, srv, keyed, "Keyed", nil)
	register(t, srv, bare, "Bare", nil)
	if n, err := store.RefreshNotices(t.Context()); err != nil || n != 0 {
		t.Fatalf("refresh with every notice fresh: %d %v", n, err)
	}
	now = t0.Add(aghub.NoticeReissue + time.Second)
	if n, err := store.RefreshNotices(t.Context()); err != nil || n != 1 {
		t.Fatalf("refresh with one stale notice of an agent with a key set: %d %v, want 1", n, err)
	}
	_, _, observed, n, _ := store.NoticeRowForTest(keyed.AID())
	if observed != now.UnixMilli() {
		t.Errorf("the refreshed notice was observed at %d, want %d", observed, now.UnixMilli())
	}
	if e, _ := storedEntry(t, store, keyed.AID()); e == nil || !bytes.Equal(e.Notice, n) {
		t.Error("the directory entry does not carry the refreshed notice")
	}
	if _, _, observed, _, _ := store.NoticeRowForTest(bare.AID()); observed != t0.UnixMilli() {
		t.Errorf("the notice of an agent without a key set was refreshed (%d)", observed)
	}
}

// KEL-5 (2026-10-04, SSR-H18): an agent that has published no key set is
// not listed — not in /agents (with or without ?cap= and ?q=), not in
// /a2a/v1/agents, not in a directory bucket — and every listed entry
// carries its key set; nor is a card learned from a peer that came without
// one. /stats agrees. The agent stays registered and readable by its AID.
func TestAgentsWithoutKeysAreNotListed(t *testing.T) {
	srv, store := newWitnessHub(t)
	keyed, bare := twoAgents(t)
	registerA2A(t, srv, keyed, "Keyed", []string{"work.do"}, signA2A(t, keyed, a2aCardNamed(keyed, 1, "Keyed", []string{"work.do"})))
	body := registerBody(t, bare, "Bare", []string{"work.do"})
	body["a2a_card"] = signA2A(t, bare, a2aCardNamed(bare, 1, "Bare", []string{"work.do"}))
	if code, b := registerFunded(t, srv, bare, body); code != http.StatusOK {
		t.Fatalf("register without a key set: %d %s", code, b)
	}
	// A card a peer taught without a key set, and one with.
	peerBare, peerKeyed := twoAgents(t)
	for _, e := range []aghub.FedA2ACard{
		a2aEntry(t, peerBare, signA2A(t, peerBare, a2aCardNamed(peerBare, 1, "PeerBare", []string{"work.do"}))),
		keyedEntry(t, peerKeyed, signA2A(t, peerKeyed, a2aCardNamed(peerKeyed, 1, "PeerKeyed", []string{"work.do"}))),
	} {
		if err := store.AdmitFedA2ACard(homePeerAID, e); err != nil {
			t.Fatal(err)
		}
	}
	serverOf(t, srv).SetFederatedDirectory(store.FederatedAgents)

	want := map[string]bool{keyed.AID(): true, peerKeyed.AID(): true}
	check := func(where string, aids []string, keys []string) {
		t.Helper()
		got := map[string]bool{}
		for i, aid := range aids {
			got[aid] = true
			if keys[i] == "" {
				t.Errorf("%s: the entry of %s has no keys", where, aid)
			}
		}
		for aid := range want {
			if !got[aid] {
				t.Errorf("%s: %s is missing", where, aid)
			}
		}
		for _, aid := range []string{bare.AID(), peerBare.AID()} {
			if got[aid] {
				t.Errorf("%s lists %s, which has no key set", where, aid)
			}
		}
	}
	for _, q := range []string{"", "?cap=work.do", "?q=Bare", "?q=Keyed"} {
		code, b := getJSON(t, srv.URL+"/agents"+q)
		var out struct {
			Agents []aghub.AgentView `json:"agents"`
		}
		if code != http.StatusOK || json.Unmarshal(b, &out) != nil {
			t.Fatalf("/agents%s: %d %s", q, code, b)
		}
		var aids, keys []string
		for _, a := range out.Agents {
			aids, keys = append(aids, a.AID), append(keys, a.Keys)
		}
		if q == "?q=Bare" {
			if len(aids) != 0 {
				t.Errorf("/agents?q=Bare: %v", aids)
			}
			continue
		}
		check("/agents"+q, aids, keys)
	}
	l := registry(t, srv, "")
	var aids, keys []string
	for _, e := range l.Agents {
		aids, keys = append(aids, e.AID), append(keys, e.Keys)
	}
	check("/a2a/v1/agents", aids, keys)
	if lookUpInBucket(t, srv, bare.AID(), "") != nil {
		t.Error("the directory has an entry for an agent without a key set")
	}
	if lookUpInBucket(t, srv, keyed.AID(), "") == nil {
		t.Error("the directory has no entry for an agent with a key set")
	}
	code, b := getJSON(t, srv.URL+"/stats")
	var st aghub.HubStats
	if code != http.StatusOK || json.Unmarshal(b, &st) != nil || st.Agents != 1 || st.FederatedAgents != 1 {
		t.Errorf("/stats: %d %s, want 1 local and 1 peer-learned agent", code, b)
	}
	if code, b := getJSON(t, srv.URL+"/agents/"+bare.AID()); code != http.StatusOK {
		t.Errorf("an agent without a key set by its AID: %d %s", code, b)
	}
}

// KEL §2.12 KELPushRate, M42: /agents/kel:push is limited per client
// address key — an IPv4 address, an IPv6 /64 — before the body is read: a
// hundred addresses of one /64 within a second share one bucket (at most
// the burst and what a second refills), another /64 has its own, and IPv4
// addresses do not share.
func TestKELPushRateKeysIPv6By64(t *testing.T) {
	srv, _ := newHubWithStore(t)
	frozen := time.Now()
	serverOf(t, srv).SetKELPushLimiterClockForTest(func() time.Time { return frozen })
	c, _ := aghub.NewAgentForTest()
	body := []byte(`{"aid":"` + c.AID() + `","kel":"` + kelURL(t, c) + `"}`)
	from := func(addr string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+aghub.KELPushPath, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ANet-Wire", wireHeader)
		req.Header.Set("X-Real-IP", addr) // the test client is on loopback, as the proxy is
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			if !reasonIs(b, "rate_limited") || resp.Header.Get("Retry-After") == "" {
				t.Fatalf("429 without rate_limited and Retry-After: %s", b)
			}
		}
		return resp.StatusCode
	}
	taken := 0
	for i := 1; i <= 100; i++ {
		if from("2001:db8:1:2::"+strconv.FormatInt(int64(i), 16)) != http.StatusTooManyRequests {
			taken++
		}
	}
	if taken > aghub.KELPushBurst+1 || taken < aghub.KELPushBurst {
		t.Errorf("100 addresses of one /64 had %d pushes taken, want the burst %d (and at most one more)", taken, aghub.KELPushBurst)
	}
	if code := from("2001:db8:1:3::1"); code == http.StatusTooManyRequests {
		t.Error("another /64 was limited by the first one's bucket")
	}
	for i := 1; i <= aghub.KELPushBurst; i++ {
		if code := from("198.51.100." + strconv.Itoa(i)); code == http.StatusTooManyRequests {
			t.Fatalf("IPv4 address %d was limited by another address's bucket", i)
		}
	}
	limited := false
	for i := 0; i <= aghub.KELPushBurst; i++ {
		if from("198.51.100.1") == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Error("one IPv4 address was never limited")
	}
}
