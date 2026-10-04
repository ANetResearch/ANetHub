package aghub

// First-contact sessions (sealed-sender §4.2.3, SSR-H6 to SSR-H9, SSR-W15).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"
)

// TestSessionLimits: an AID holds at most 4 sessions (a fifth ends the
// oldest), opens at most 30 an hour (the 31st is 429 with the wait), and a
// session lasts an hour; a restart of the hub process ends them all.
func TestSessionLimits(t *testing.T) {
	sc := newScene(t)
	h := sc.h
	send := func(ss session) int { return h.send0(ss, sc.env(), kind0Opts{}).Code }

	// 4 at once; the fifth ends the first.
	held := []session{sc.ss}
	for i := 0; i < 4; i++ {
		held = append(held, h.openSession(sc.sender.c))
	}
	if n := h.srv.relay.sessions.count(sc.sender.aid, h.clock()); n != MaxSessionsPerAID {
		t.Fatalf("%d sessions held, want %d", n, MaxSessionsPerAID)
	}
	if code := send(held[0]); code != http.StatusUnauthorized {
		t.Fatalf("the oldest session after a fifth opened: %d, want 401", code)
	}
	for i, ss := range held[1:] {
		if code := send(ss); code != 200 {
			t.Fatalf("session %d: %d", i+1, code)
		}
	}
	// 30 openings in an hour; the 31st waits until the first is an hour
	// old.
	for i := len(held); i < MaxSessionOpensPerHour; i++ {
		h.advance(time.Second)
		h.openSession(sc.sender.c)
	}
	_, rec := h.tryOpenSession(sc.sender.c)
	expectRefusal(t, rec, http.StatusTooManyRequests, "rate_limited")
	wait, _ := strconv.Atoi(rec.Header().Get("Retry-After"))
	if want := int(time.Hour.Seconds()) - (MaxSessionOpensPerHour - len(held)); wait != want {
		t.Errorf("Retry-After %d, want %d (until the first opening is an hour old)", wait, want)
	}
	// Another AID is not affected.
	h.openSession(sc.recip.c)
	// An hour after the first opening, one more may be opened.
	h.advance(time.Duration(wait) * time.Second)
	last := h.openSession(sc.sender.c)
	// A session ends an hour after it opened.
	if code := send(last); code != 200 {
		t.Fatalf("a new session: %d", code)
	}
	h.advance(SessionLifetime - time.Millisecond)
	if code := send(last); code != 200 {
		t.Fatalf("a session a millisecond before its hour: %d", code)
	}
	h.advance(time.Millisecond)
	if code := send(last); code != http.StatusUnauthorized {
		t.Fatalf("a session after its hour: %d, want 401", code)
	}
	// A restart of the hub process ends every session.
	fresh := h.openSession(sc.recip.c)
	h.restart()
	if code := send(fresh); code != http.StatusUnauthorized {
		t.Fatalf("a session after a restart: %d, want 401", code)
	}
}

// TestSessionRequiresAdmission (SSR-H6): only an AID registered (admitted)
// here opens a session; one that is not, or whose admission was revoked, is
// told 403 admission_required with its AID. Bad signatures are 401.
func TestSessionRequiresAdmission(t *testing.T) {
	h := newRelayHub(t)
	c, _ := identitytest.Hub()
	_, rec := h.tryOpenSession(c)
	expectRefusal(t, rec, http.StatusForbidden, "admission_required")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["aid"] != c.AID() {
		t.Errorf("admission_required without the AID: %s", rec.Body)
	}
	kel, _ := identity.MarshalKEL(c.KEL())
	if err := h.store.PutAgent(c.AID(), "n", nil, kel); err != nil {
		t.Fatal(err)
	}
	if _, rec := h.tryOpenSession(c); rec.Code != 200 {
		t.Fatalf("a registered AID: %d %s", rec.Code, rec.Body)
	}
	// A signature by another key over the request.
	other, _ := identitytest.Hub()
	_, epk, _ := relayauth.NewSessionKey()
	raw, _ := json.Marshal(SessionRequest{EPK: base64.RawURLEncoding.EncodeToString(epk)})
	req := h.signed(other, relayauth.ActionSession, http.MethodPost, "/relay/session", raw)
	req.Header.Set(relayauth.HeaderAID, c.AID())
	expectRefusal(t, h.serve(req, relayClientIP), http.StatusUnauthorized, "unauthorized")
	// Signed for another action.
	req = h.signed(c, relayauth.ActionPoll, http.MethodPost, "/relay/session", raw)
	expectRefusal(t, h.serve(req, relayClientIP), http.StatusUnauthorized, "unauthorized")
	// Not an AID at all.
	req = h.signed(c, relayauth.ActionSession, http.MethodPost, "/relay/session", raw)
	req.Header.Set(relayauth.HeaderAID, "agent")
	expectRefusal(t, h.serve(req, relayClientIP), http.StatusUnauthorized, "unauthorized")
	// Revoked: deregistered, so not admitted any more.
	if _, err := h.store.Admit(c.AID(), 0, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.RevokeAdmission(c.AID()); err != nil {
		t.Fatal(err)
	}
	_, rec = h.tryOpenSession(c)
	expectRefusal(t, rec, http.StatusForbidden, "admission_required")
}

// The body of POST /relay/session: {epk}, strictly, a 32-byte base64url
// X25519 key that a session key can be sealed to.
func TestSessionRequestBody(t *testing.T) {
	h := newRelayHub(t)
	a := h.agent()
	for name, body := range map[string]string{
		"empty":             ``,
		"no epk":            `{}`,
		"an unknown member": `{"epk":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 31)) + `A","x":1}`,
		"31 bytes":          `{"epk":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 31)) + `"}`,
		"padded":            `{"epk":"` + base64.URLEncoding.EncodeToString(make([]byte, 32)) + `"}`,
		"a low-order point": `{"epk":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`,
	} {
		rec := h.serve(h.signed(a.c, relayauth.ActionSession, http.MethodPost, "/relay/session", []byte(body)), relayClientIP)
		expectRefusal(t, rec, http.StatusBadRequest, "bad_request")
		if n := h.srv.relay.sessions.count(a.aid, h.clock()); n != 0 {
			t.Fatalf("%s: a refused request opened a session", name)
		}
	}
	// A refused body does not count as an opening.
	h.srv.relay.sessions.mu.Lock()
	opens := len(h.srv.relay.sessions.opens[a.aid])
	h.srv.relay.sessions.mu.Unlock()
	if opens != 0 {
		t.Fatalf("%d openings counted for refused requests", opens)
	}
}

// TestSessionReplayOnlyDedupes (SSR-W15): a session send has no replay
// cache. The same request again finds its envelope waiting (200 duplicate,
// no token); after the recipient took it, the same request is queued again,
// three times a day at most.
func TestSessionReplayOnlyDedupes(t *testing.T) {
	sc := newScene(t)
	env := sc.env()
	req := sc.h.kind0Request(sc.ss, env, kind0Opts{})
	replay := func() *http.Request {
		r := sc.h.kind0Request(sc.ss, env, kind0Opts{})
		r.Header = req.Header.Clone()
		return r
	}
	first := decodeSent(t, sc.h.serve(req, relayClientIP))
	before := sc.h.effects()
	again := decodeSent(t, sc.h.serve(replay(), relayClientIP))
	if again.Status != RelayDuplicate || again.RID != first.RID {
		t.Fatalf("a replay while the envelope waits: %+v, want duplicate %s", again, first.RID)
	}
	if d := before.diff(sc.h.effects()); d != "" {
		t.Errorf("the replay took or wrote something: %s", d)
	}
	for i := 1; i <= MaxRedeliveries; i++ {
		msgs, _ := sc.h.store.RelayPoll(sc.recip.aid, 0, 10, 1<<20)
		if _, err := sc.h.store.RelayAck(sc.recip.aid, []int64{msgs[0].ID}); err != nil {
			t.Fatal(err)
		}
		rec := sc.h.serve(replay(), relayClientIP)
		if i < MaxRedeliveries {
			if got := decodeSent(t, rec); got.Status != RelayQueued || got.RID == first.RID {
				t.Fatalf("replay %d after the ack: %+v, want a new row", i, got)
			}
			continue
		}
		expectRefusal(t, rec, http.StatusTooManyRequests, "redelivery_limited")
	}
}

// TestRotationAndDeregisterDropSessions (SSR-H9, M37): when the hub takes a
// new event of an AID's key history, or the AID is deregistered, its
// sessions end and its send bucket is full again.
func TestRotationAndDeregisterDropSessions(t *testing.T) {
	sc := newScene(t)
	h := sc.h
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.store.StartDeregWatcher(ctx); err != nil {
		t.Fatal(err)
	}
	if got := decodeSent(t, h.send0(sc.ss, sc.env(), kind0Opts{})); got.Status != RelayQueued {
		t.Fatal(got)
	}
	if h.srv.relay.sessionSend.tokens(sc.sender.aid, rateSessionSend) == rateSessionSend.burst {
		t.Fatal("the send took no token")
	}
	// The same key history again (an agent re-registers on every start):
	// nothing ends.
	kel, _ := identity.MarshalKEL(sc.sender.c.KEL())
	if err := h.store.RegisterAgent(sc.sender.aid, "n", nil, kel, sc.sender.c.KEL()); err != nil {
		t.Fatal(err)
	}
	if code := h.send0(sc.ss, sc.env(), kind0Opts{}).Code; code != 200 {
		t.Fatalf("after a re-registration with the same key history: %d", code)
	}
	// A rotation.
	if err := identitytest.Rotate(sc.sender.c, identitytest.InceptTS+1); err != nil {
		t.Fatal(err)
	}
	kel, _ = identity.MarshalKEL(sc.sender.c.KEL())
	if err := h.store.RegisterAgent(sc.sender.aid, "n", nil, kel, sc.sender.c.KEL()); err != nil {
		t.Fatal(err)
	}
	if code := h.send0(sc.ss, sc.env(), kind0Opts{}).Code; code != http.StatusUnauthorized {
		t.Fatalf("a session after its AID rotated: %d, want 401", code)
	}
	if got := h.srv.relay.sessionSend.tokens(sc.sender.aid, rateSessionSend); got != rateSessionSend.burst {
		t.Errorf("the send bucket after the rotation holds %v, want a full %v", got, rateSessionSend.burst)
	}
	// A session opened under the new key works, until the AID leaves.
	ss := h.openSession(sc.sender.c)
	if code := h.send0(ss, sc.env(), kind0Opts{}).Code; code != 200 {
		t.Fatalf("a new session after the rotation: %d", code)
	}
	if _, err := h.store.Deregister(sc.sender.aid, DeregSelf); err != nil {
		t.Fatal(err)
	}
	if code := h.send0(ss, sc.env(), kind0Opts{}).Code; code != http.StatusUnauthorized {
		t.Fatalf("a session after its AID left: %d, want 401", code)
	}
}

// TestASessionOpenedDuringADropEndsWithIt (SSR-H9): a rotation or a
// deregistration that commits while a session is being opened, after the
// signature was checked against the old key history and before the session
// is recorded, ran its callbacks too early to end that session. The opening
// is refused instead, and leaves no session behind and no opening counted.
func TestASessionOpenedDuringADropEndsWithIt(t *testing.T) {
	defer func() { sessionOpenFault = nil }()
	sc := newScene(t)
	h := sc.h
	openings := func(aid string) int {
		st := h.srv.relay.sessions
		st.mu.Lock()
		defer st.mu.Unlock()
		return len(st.opens[aid])
	}

	// A rotation.
	before := openings(sc.sender.aid)
	sessionOpenFault = func(string) {
		sessionOpenFault = nil
		if err := identitytest.Rotate(sc.sender.c, identitytest.InceptTS+1); err != nil {
			t.Error(err)
			return
		}
		kel, _ := identity.MarshalKEL(sc.sender.c.KEL())
		if err := h.store.RegisterAgent(sc.sender.aid, "n", nil, kel, sc.sender.c.KEL()); err != nil {
			t.Error(err)
		}
	}
	_, rec := h.tryOpenSession(sc.sender.c)
	expectRefusal(t, rec, http.StatusUnauthorized, "key_retired")
	if n := h.srv.relay.sessions.count(sc.sender.aid, h.clock()); n != 0 {
		t.Fatalf("%d sessions outlived a rotation that raced their opening", n)
	}
	if got := openings(sc.sender.aid); got != before {
		t.Errorf("the refused opening was counted: %d openings, want %d", got, before)
	}
	// Signed with the new key, the next opening goes through.
	ss := h.openSession(sc.sender.c)
	if code := h.send0(ss, sc.env(), kind0Opts{}).Code; code != 200 {
		t.Fatalf("a session opened after the rotation: %d", code)
	}

	// A deregistration.
	sessionOpenFault = func(string) {
		sessionOpenFault = nil
		if _, err := h.store.Deregister(sc.recip.aid, DeregSelf); err != nil {
			t.Error(err)
		}
	}
	_, rec = h.tryOpenSession(sc.recip.c)
	expectRefusal(t, rec, http.StatusForbidden, "admission_required")
	if n := h.srv.relay.sessions.count(sc.recip.aid, h.clock()); n != 0 {
		t.Fatalf("%d sessions outlived a deregistration that raced their opening", n)
	}
}

// TestDeregDropsSessionsWithin2s (SSR-H9, HPP PAY-O2): a deregistration in
// the hub process ends the AID's sessions at once; one committed by another
// process (anet-hub admissions revoke) within two seconds, through
// dereg_event.
func TestDeregDropsSessionsWithin2s(t *testing.T) {
	sc := newScene(t)
	h := sc.h
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.store.StartDeregWatcher(ctx); err != nil {
		t.Fatal(err)
	}
	// In the hub process: POST /agents/{aid}/deregister, signed. The
	// session is gone when the answer is.
	recipSession := h.openSession(sc.recip.c)
	rec := h.serve(h.signed(sc.recip.c, relayauth.ActionDeregister, http.MethodPost,
		"/agents/"+sc.recip.aid+"/deregister", nil), relayClientIP)
	if rec.Code != 200 {
		t.Fatalf("deregister: %d %s", rec.Code, rec.Body)
	}
	if _, ok := h.srv.relay.sessions.get(recipSession.sid, h.clock()); ok {
		t.Fatal("the session of an AID that left is live")
	}
	// Another process revokes the sender's admission.
	if _, err := h.store.Admit(sc.sender.aid, 0, "", false); err != nil {
		t.Fatal(err)
	}
	other := sc.h.agent()
	ss := h.openSession(other.c)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), deregHelperEnv+"="+h.dir+"|"+sc.sender.aid)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the other process: %v\n%s", err, out)
	}
	committed := time.Now()
	for {
		if _, ok := h.srv.relay.sessions.get(sc.ss.sid, h.clock()); !ok {
			break
		}
		if time.Since(committed) > 2*time.Second {
			t.Fatal("the session of an AID revoked by another process is live after 2 s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code := h.send0(sc.ss, envelope(t, other.aid, []byte("after")), kind0Opts{}).Code; code != http.StatusUnauthorized {
		t.Fatalf("a send under the dropped session: %d, want 401", code)
	}
	// Somebody else's session is untouched.
	if code := h.send0(ss, envelope(t, other.aid, []byte("mine")), kind0Opts{}).Code; code != 200 {
		t.Fatalf("another AID's session: %d", code)
	}
}

// TestProbationSessionRate (SSR-H8, M29): during its probation an account
// sends 2 a second, 20 at once; afterwards 20 a second, 200 at once.
func TestProbationSessionRate(t *testing.T) {
	sc := newScene(t)
	h := sc.h
	until := h.clock().Add(72 * time.Hour)
	if _, err := h.store.db.Exec(`UPDATE agent SET probation_until=? WHERE aid=?`, until.UnixMilli(), sc.sender.aid); err != nil {
		t.Fatal(err)
	}
	others := []*relayAgent{sc.recip, h.agent(), h.agent(), h.agent(), h.agent()}
	burst := func(n int) int {
		sent := 0
		for i := 0; i < n; i++ {
			to := others[i%len(others)]
			rec := h.send0(sc.ss, envelope(t, to.aid, []byte("p "+strconv.Itoa(sc.counter))), kind0Opts{})
			sc.counter++
			if rec.Code != 200 {
				if reasonOf(rec) != "rate_limited" {
					t.Fatalf("send %d: %d %s", i, rec.Code, rec.Body)
				}
				return sent
			}
			sent++
		}
		return sent
	}
	if n := burst(100); n != int(rateSessionSendProbation.burst) {
		t.Fatalf("on probation %d sends went through at once, want %v", n, rateSessionSendProbation.burst)
	}
	h.advance(time.Second)
	if n := burst(100); n != int(rateSessionSendProbation.perSec) {
		t.Fatalf("on probation %d sends after a second, want %v", n, rateSessionSendProbation.perSec)
	}
	// Probation over: the bucket refills at the full rate up to the full
	// burst.
	h.advance(72 * time.Hour)
	sc.ss = h.openSession(sc.sender.c)                           // the old one ended long ago
	h.srv.relay.firstContact.buckets = map[string]*relayBucket{} // the recipients' share is not under test
	if n := burst(250); n != int(rateSessionSend.burst) {
		t.Fatalf("after probation %d sends went through at once, want %v", n, rateSessionSend.burst)
	}
}
