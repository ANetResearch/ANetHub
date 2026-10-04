package aghub

// RC1 over HTTP (hub-payment-privacy §4.2.5): what a signer is told, which
// K it gets, and the red-team F4 PoC rerun at its scale. The state rules
// are in rc1_test.go and rc1_prop_test.go.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

// rc1Hub is a hub for the tests of this file.
type rc1Hub struct {
	t     *testing.T
	store *Store
	s     *Server
	id    *hubid.Identity
	srv   *httptest.Server
}

// newRC1Hub starts a hub; r, when not nil, is its RC1 state (set before
// the hub serves, as a restart would).
func newRC1Hub(t *testing.T, r *rc1State) *rc1Hub {
	t.Helper()
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	s := NewServer(store)
	s.SetHubAID(id.AID)
	if r != nil {
		s.replay = r
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &rc1Hub{t: t, store: store, s: s, id: id, srv: srv}
}

// agent registers a new agent directly in the store.
func (h *rc1Hub) agent() *identity.Controller {
	h.t.Helper()
	c, err := identitytest.Hub()
	if err != nil {
		h.t.Fatal(err)
	}
	kel, _ := identity.MarshalKEL(c.KEL())
	if err := h.store.PutAgent(c.AID(), "n", nil, kel); err != nil {
		h.t.Fatal(err)
	}
	return c
}

// rc1Answer is one response.
type rc1Answer struct {
	code int
	body []byte
	hdr  http.Header
}

func (a rc1Answer) reason() string {
	var g struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(a.body, &g)
	return g.Reason
}

// do sends a request signed as c at ts (corrupt: a signature of another
// request). It is safe for concurrent use.
func (h *rc1Hub) do(c *identity.Controller, action, method, path string, body any, ts uint64, corrupt bool) rc1Answer {
	raw, _ := json.Marshal(body)
	if body == nil {
		raw = nil
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
	signed := raw
	if corrupt {
		signed = append(append([]byte(nil), raw...), ' ')
	}
	sig, seq := c.Sign(relayauth.PreimageV2(action, c.AID(), h.id.AID, ts, req.Method, req.URL.RequestURI(), signed))
	req.Header.Set(relayauth.HeaderAID, c.AID())
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Error(err)
		return rc1Answer{}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return rc1Answer{resp.StatusCode, b, resp.Header}
}

// poll is a signed /relay/poll as c at ts.
func (h *rc1Hub) poll(c *identity.Controller, ts uint64) rc1Answer {
	return h.do(c, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{}, ts, false)
}

// balance is a signed GET /agents/{aid}/balance as c at ts: a signed
// request that writes nothing.
func (h *rc1Hub) balance(c *identity.Controller, ts uint64) rc1Answer {
	return h.do(c, relayauth.ActionBalance, http.MethodGet, "/agents/"+c.AID()+"/balance", nil, ts, false)
}

func nowMS() uint64 { return uint64(time.Now().UnixMilli()) }

// PAY-R3 and PAY-R8: a time at or below the signer's floor is 401 ts_stale
// with the floor as a member and as X-ANet-TS-Floor; a time accepted
// before is 401 replayed; both only for a signature that verifies. A bad
// signature is 401 unauthorized whatever its time, without a floor, and
// adds nothing to the state. (M-PAY-28)
func TestRC1RefusalsAndTheFloorComeOnlyAfterTheSignature(t *testing.T) {
	h := newRC1Hub(t, nil)
	a := h.agent()
	t1 := nowMS() + 40_000 // floor after it: t1 − W, above the time the hub started
	if got := h.poll(a, t1); got.code != http.StatusOK {
		t.Fatalf("first poll: %d %s", got.code, got.body)
	}
	floor := t1 - rc1W
	stale := h.poll(a, floor)
	if stale.code != http.StatusUnauthorized || stale.reason() != string(wire3.ReasonTSStale) {
		t.Fatalf("a time at the floor: %d %s, want 401 ts_stale", stale.code, stale.body)
	}
	if got := stale.hdr.Get(headerTSFloor); got != strconv.FormatUint(floor, 10) {
		t.Errorf("X-ANet-TS-Floor %q, want %d", got, floor)
	}
	var body struct {
		Floor uint64 `json:"floor"`
	}
	if err := json.Unmarshal(stale.body, &body); err != nil || body.Floor != floor {
		t.Errorf("ts_stale body floor %d (%v), want %d: %s", body.Floor, err, floor, stale.body)
	}
	for _, p := range wire3test.Contract(stale.code, stale.hdr, stale.body) {
		t.Error(p)
	}
	replayed := h.poll(a, t1)
	if replayed.code != http.StatusUnauthorized || replayed.reason() != string(wire3.ReasonReplayed) ||
		replayed.hdr.Get(headerTSFloor) != "" {
		t.Fatalf("the same time again: %d %s (floor header %q), want 401 replayed without a floor",
			replayed.code, replayed.body, replayed.hdr.Get(headerTSFloor))
	}
	// Bad signatures: at the floor, at an accepted time, at a fresh time.
	for _, ts := range []uint64{floor, t1, t1 + 1} {
		got := h.do(a, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{}, ts, true)
		if got.code != http.StatusUnauthorized || got.reason() != string(wire3.ReasonUnauthorized) ||
			got.hdr.Get(headerTSFloor) != "" || bytes.Contains(got.body, []byte(`"floor"`)) {
			t.Errorf("a bad signature at %d: %d %s (floor header %q), want 401 unauthorized without a floor",
				ts, got.code, got.body, got.hdr.Get(headerTSFloor))
		}
	}
	if f, _, recent, _ := h.s.replay.view(a.AID()); f != floor || len(recent) != 1 {
		t.Fatalf("bad signatures changed the state: floor %d, %d times; want %d and 1", f, len(recent), floor)
	}
	// The fresh time a bad signature carried is still free.
	if got := h.poll(a, t1+1); got.code != http.StatusOK {
		t.Fatalf("a fresh time after a bad signature used it: %d %s", got.code, got.body)
	}
	// A time outside the window says so, and has no floor either.
	got := h.poll(a, nowMS()+relayauth.MaxSkewMillis+60_000)
	if got.code != http.StatusUnauthorized || got.reason() != string(wire3.ReasonUnauthorized) ||
		got.hdr.Get(headerTSFloor) != "" || !bytes.Contains(got.body, []byte("system clock")) {
		t.Fatalf("a time outside the window: %d %s, want 401 unauthorized naming the clock", got.code, got.body)
	}
}

// A request signed before this hub's RC1 state existed (before a restart)
// is refused like one below a floor: the restart forgot what was accepted,
// and does not accept it again. (One signed ahead of the hub's clock and
// accepted before the restart is not covered: the state is in memory.)
func TestRC1ARestartRefusesTimesSignedBeforeIt(t *testing.T) {
	before := nowMS() - 2_000
	h := newRC1Hub(t, nil) // started after before was signed: a restart in between
	a := h.agent()
	got := h.poll(a, before)
	if got.code != http.StatusUnauthorized || got.reason() != string(wire3.ReasonTSStale) {
		t.Fatalf("a time signed before the restart: %d %s, want 401 ts_stale", got.code, got.body)
	}
	floor, err := strconv.ParseUint(got.hdr.Get(headerTSFloor), 10, 64)
	if err != nil || floor < before {
		t.Fatalf("floor %q, want at least %d", got.hdr.Get(headerTSFloor), before)
	}
	// What a MonoClock client does with it: raise and sign again, once.
	var clock relayauth.MonoClock
	now := time.Now().UnixMilli()
	clock.Next(h.id.AID, int64(before)) // the client's last time was before
	if !clock.Raise(h.id.AID, int64(floor), now) {
		t.Fatal("the client refused the floor of a restart")
	}
	if got := h.poll(a, uint64(clock.Next(h.id.AID, now))); got.code != http.StatusOK {
		t.Fatalf("signed again above the floor: %d %s", got.code, got.body)
	}
}

// PAY-R4 and core G17: K is 16 for a newcomer's /register and for an
// account on probation (store.ProbationUntil), 64 for an agent; a peer
// hub's is 4096.
func TestRC1KFollowsTheSignersClass(t *testing.T) {
	h := newRC1Hub(t, nil)
	agent, probation := h.agent(), h.agent()
	stranger, _ := identitytest.Hub()
	if _, err := h.store.db.Exec(`UPDATE agent SET admitted_via=?, probation_until=?, trial=? WHERE aid=?`,
		viaOpen, time.Now().Add(time.Hour).UnixMilli(), trialPending, probation.AID()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, aid, action string
		k                 int
	}{
		{"agent", agent.AID(), relayauth.ActionPoll, rc1KAgent},
		{"agent registering again", agent.AID(), relayauth.ActionRegister, rc1KAgent},
		{"newcomer registering", stranger.AID(), relayauth.ActionRegister, rc1KNew},
		{"on probation", probation.AID(), relayauth.ActionPoll, rc1KNew},
		{"on probation registering again", probation.AID(), relayauth.ActionRegister, rc1KNew},
	} {
		if got := h.s.rc1K(tc.aid, tc.action); got != tc.k {
			t.Errorf("%s: K %d, want %d", tc.name, got, tc.k)
		}
	}
	if rc1KNew != 16 || rc1KAgent != 64 || rc1KPeerHub != 4096 {
		t.Fatal("the K of core G17 changed")
	}
	// Over HTTP: 20 polls inside W.
	base := nowMS() + 1_000
	for _, c := range []*identity.Controller{agent, probation} {
		for i := 0; i < 20; i++ {
			if got := h.poll(c, base+uint64(i)); got.code != http.StatusOK {
				t.Fatalf("poll %d: %d %s", i, got.code, got.body)
			}
		}
	}
	if _, _, recent, _ := h.s.replay.view(agent.AID()); len(recent) != 20 {
		t.Errorf("an agent keeps %d times of 20, want all 20 (K = 64)", len(recent))
	}
	if _, _, recent, _ := h.s.replay.view(probation.AID()); len(recent) != rc1KNew {
		t.Errorf("an account on probation keeps %d times, want %d", len(recent), rc1KNew)
	}
	// Probation over: 64 from the next request on.
	if _, err := h.store.db.Exec(`UPDATE agent SET probation_until=? WHERE aid=?`,
		time.Now().Add(-time.Second).UnixMilli(), probation.AID()); err != nil {
		t.Fatal(err)
	}
	if got := h.s.rc1K(probation.AID(), relayauth.ActionPoll); got != rc1KAgent {
		t.Errorf("after probation K %d, want %d", got, rc1KAgent)
	}
}

// [redteam:F4] rerun at the scale of its PoC: one registered AID signing
// polls with times 4m50s in the future used to fill the global replay
// cache (bound 64 in the PoC), and every other agent's /relay/send and
// /relay/poll was answered 503. Under RC1 a signer fills only its own
// state, and the valve (scaled here to the PoC's 64 entries) refuses
// nobody: the attackers are not refused either, the victim's send and
// the recipient's poll are served, and no answer is 503 or 429.
func TestRC1OneSignerFillingItsStateStopsNobody(t *testing.T) {
	// The PoC's bound, 64 entries, as bytes of RC1 state: 64 times and the
	// six signers of the test.
	fixed := int64(6 * (rc1SignerBytes + 59))
	h := newRC1Hub(t, newRC1(time.Now().UnixMilli()-1, rc1Shards, fixed+64*8, fixed+56*8))
	attackers := []*identity.Controller{h.agent(), h.agent(), h.agent(), h.agent()}
	victim, recip := h.agent(), h.agent()

	future := nowMS() + 4*60_000 + 50_000
	refused := func(where string, got rc1Answer) {
		t.Helper()
		if got.code == http.StatusServiceUnavailable || got.code == http.StatusTooManyRequests {
			t.Fatalf("%s: %d %s; replay state must refuse nobody", where, got.code, got.body)
		}
	}
	n := uint64(0)
	for a, c := range attackers {
		for i := 0; i < 16; i++ {
			n++
			got := h.do(c, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{"limit": 1 + i}, future+n, false)
			refused(fmt.Sprintf("attacker %d poll %d", a, i), got)
			if got.code != http.StatusOK {
				t.Fatalf("attacker %d poll %d: %d %s", a, i, got.code, got.body)
			}
		}
	}
	// One attacker keeps going at the PoC's rate, 1,750 signed polls, past
	// what used to be its share; it is not refused for it.
	for i := 0; i < 1750; i++ {
		n++
		got := h.do(attackers[0], relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{"limit": 1}, future+n, false)
		refused(fmt.Sprintf("attacker 0 poll %d", 16+i), got)
		if got.code != http.StatusOK {
			t.Fatalf("attacker 0 poll %d: %d %s", 16+i, got.code, got.body)
		}
	}
	if _, _, recent, _ := h.s.replay.view(attackers[1].AID()); len(recent) != 0 {
		t.Fatalf("the valve did not run: attacker 1 still holds %d times", len(recent))
	}

	env := &seal.SealedEnvelope{V: seal.EnvelopeVersion, To: recip.AID(), Suite: seal.SuiteX25519,
		KID: bytes.Repeat([]byte{7}, seal.KIDLen), Enc: bytes.Repeat([]byte{9}, 32), CT: []byte("ct"),
		Access: &seal.Access{Kind: seal.AccessKindSession}}
	envB, _ := env.Marshal()
	// The victim's signed request is the opening of its session; the send
	// is MACed under it.
	esk, epk, err := relayauth.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	got := h.do(victim, relayauth.ActionSession, http.MethodPost, "/relay/session",
		map[string]any{"epk": base64.RawURLEncoding.EncodeToString(epk)}, nowMS(), false)
	if got.code != http.StatusOK {
		t.Fatalf("victim session while the attackers fill their state: %d %s", got.code, got.body)
	}
	var opened SessionResponse
	if err := json.Unmarshal(got.body, &opened); err != nil {
		t.Fatal(err)
	}
	sid, enc, ct := mustB64(t, opened.SID), mustB64(t, opened.Enc), mustB64(t, opened.CT)
	key, err := relayauth.OpenSessionKey(esk, h.id.AID, sid, enc, ct)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/relay/send", bytes.NewReader(envB))
	req.Header.Set("Content-Type", EnvelopeContentType)
	req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
	req.Header.Set(HeaderAccess, base64.RawURLEncoding.EncodeToString([]byte{0xa1, 0x01, 0x00}))
	ts := uint64(time.Now().UnixMilli())
	mac, err := relayauth.SessionMAC(key, sid, ts, http.MethodPost, "/relay/send", "", envB)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(relayauth.HeaderSession, relayauth.EncodeSessionID(sid))
	req.Header.Set(relayauth.HeaderMAC, relayauth.EncodeMAC(mac))
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("victim send while the attackers fill their state: %d %s", resp.StatusCode, body)
	}
	if got := h.poll(recip, nowMS()); got.code != http.StatusOK || !bytes.Contains(got.body, []byte(`"id":`)) {
		t.Fatalf("recipient poll while the attackers fill their state: %d %s", got.code, got.body)
	}
}

// [redteam:F4] The admission gate (PAY-A1 step 4) refuses a newcomer the
// hub would not take before its signature is checked: on a closed hub one
// that is not on the list, on an open hub one without a good proof of
// work. Neither leaves RC1 state; an admitted newcomer's registration
// leaves its one time.
func TestRC1AStrangerAtAClosedHubLeavesNoState(t *testing.T) {
	h := newRC1Hub(t, nil)
	register := func(c *identity.Controller, extra map[string]any, ip string) (int, string) {
		kel, _ := identity.MarshalKEL(c.KEL())
		body := map[string]any{"aid": c.AID(), "name": "n", "kel": base64.RawURLEncoding.EncodeToString(kel)}
		for k, v := range extra {
			body[k] = v
		}
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/register", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
		req.Header.Set("X-Real-IP", ip)
		ts := nowMS()
		sig, seq := c.Sign(relayauth.PreimageV2(relayauth.ActionRegister, c.AID(), h.id.AID, ts, req.Method, req.URL.RequestURI(), raw))
		req.Header.Set(relayauth.HeaderAID, c.AID())
		req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
		req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
		req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	badPow := map[string]any{"pow": map[string]any{
		"seed": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "nonce": "AA"}}
	for _, mode := range []string{AdmissionClosed, AdmissionOpen} {
		if err := h.store.SetAdmissionMode(mode); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			c, err := identitytest.Hub()
			if err != nil {
				t.Fatal(err)
			}
			for _, extra := range []map[string]any{nil, badPow} {
				if code, b := register(c, extra, "198.51.100."+strconv.Itoa(i)); code != http.StatusForbidden {
					t.Fatalf("%s hub, a stranger registering with %v: %d %s", mode, extra, code, b)
				}
			}
		}
	}
	if n := h.s.replay.signerCount(); n != 0 {
		t.Fatalf("80 refused registrations left %d signers in the replay state", n)
	}
	c, _ := identitytest.Hub()
	if _, err := h.store.Admit(c.AID(), 0, "", false); err != nil {
		t.Fatal(err)
	}
	if code, b := register(c, nil, "203.0.113.1"); code != http.StatusOK {
		t.Fatalf("an admitted newcomer: %d %s", code, b)
	}
	if _, _, recent, ok := h.s.replay.view(c.AID()); !ok || len(recent) != 1 || h.s.replay.signerCount() != 1 {
		t.Fatalf("the admitted registration left %d signers, its own with %d times; want 1 and 1",
			h.s.replay.signerCount(), len(recent))
	}
}

// J-PAY-11, the hub's part, and SI-53: 10,000 signers fill the replay
// state past its valve (scaled from 256 MiB to what 10,000 signers hold
// here, so that it trips again and again). Most of them are synthetic,
// entering RC1 after the point where a signature has verified; 500 are
// registered agents signing over HTTP. Four agents signing as anet does,
// from one MonoClock per process with two requests in flight, are never
// answered 503 or 429, nor is any flood signer; a ts_stale, when the valve
// made a daemon monotonic under a request in flight, is followed by one
// request signed again that succeeds.
func TestRC1TenThousandSignersPastTheValveRefuseNobody(t *testing.T) {
	const signers, signed = 10_000, 500
	// A synthetic signer holds rc1SignerBytes + len(AID) and three times (a
	// slice of capacity 4). The valve trips when the signers hold three
	// quarters of their times and goes down to a quarter, which making
	// every signer monotonic reaches.
	const aidLen = 59
	fixed := int64(signers * (rc1SignerBytes + aidLen))
	times := int64(signers * 8 * 4)
	high := fixed + times*3/4
	h := newRC1Hub(t, newRC1(time.Now().UnixMilli()-1, rc1Shards, high, fixed+times/4))
	// The store's connection pool keeps 2 idle connections; with the
	// requests below in flight together it would open (and parse the
	// schema of) a new one for most of them, which is not what this test
	// is about.
	h.store.db.SetMaxIdleConns(32)

	real := make([]*identity.Controller, signed)
	for i := range real {
		real[i] = h.agent()
	}
	daemons := []*identity.Controller{h.agent(), h.agent(), h.agent(), h.agent()}

	var busy, floodStale, stales, retriesFailed atomic.Int64
	stop := make(chan struct{})
	var dwg sync.WaitGroup
	for d, c := range daemons {
		var clock relayauth.MonoClock // one per process, shared by its requests in flight
		for lane := 0; lane < 2; lane++ {
			dwg.Add(1)
			go func(d, lane int, c *identity.Controller) {
				defer dwg.Done()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					got := h.balance(c, uint64(clock.Next(h.id.AID, time.Now().UnixMilli())))
					if got.code == http.StatusServiceUnavailable || got.code == http.StatusTooManyRequests {
						busy.Add(1)
						t.Errorf("daemon %d: %d %s", d, got.code, got.body)
						return
					}
					if got.reason() == string(wire3.ReasonTSStale) {
						stales.Add(1)
						floor, _ := strconv.ParseInt(got.hdr.Get(headerTSFloor), 10, 64)
						if !clock.Raise(h.id.AID, floor, time.Now().UnixMilli()) {
							t.Errorf("daemon %d: the hub's floor %d was not adopted", d, floor)
							return
						}
						got = h.balance(c, uint64(clock.Next(h.id.AID, time.Now().UnixMilli())))
						if got.code != http.StatusOK {
							retriesFailed.Add(1)
						}
					}
					if got.code != http.StatusOK && got.reason() != string(wire3.ReasonTSStale) {
						t.Errorf("daemon %d lane %d request %d: %d %s", d, lane, i, got.code, got.body)
						return
					}
					time.Sleep(time.Millisecond)
				}
			}(d, lane, c)
		}
	}

	// The flood: every signer three times inside W, out of order.
	base := nowMS()
	offsets := []uint64{20, 10, 30}
	var fwg sync.WaitGroup
	for w := 0; w < 8; w++ {
		fwg.Add(1)
		go func(w int) {
			defer fwg.Done()
			for i := w; i < signers; i += 8 {
				aid := fmt.Sprintf("bafyreisynthetic%043d", i) // as long as an AID
				for _, off := range offsets {
					switch v, _ := h.s.replay.accept(aid, base+uint64(i%1000)+off, rc1KAgent, time.Now().UnixMilli()); v {
					case rc1Stale:
						floodStale.Add(1) // made monotonic by the valve between two of its times
					case rc1Accepted:
					default:
						t.Errorf("synthetic signer %d: verdict %d", i, v)
					}
				}
			}
		}(w)
	}
	for w := 0; w < 4; w++ {
		fwg.Add(1)
		go func(w int) {
			defer fwg.Done()
			for i := w; i < signed; i += 4 {
				for _, off := range offsets {
					got := h.balance(real[i], base+uint64(i)+off)
					switch {
					case got.code == http.StatusServiceUnavailable || got.code == http.StatusTooManyRequests:
						busy.Add(1)
					case got.reason() == string(wire3.ReasonTSStale):
						floodStale.Add(1)
					case got.code != http.StatusOK:
						t.Errorf("signer %d: %d %s", i, got.code, got.body)
					}
				}
			}
		}(w)
	}
	fwg.Wait()
	close(stop)
	dwg.Wait()

	if busy.Load() != 0 {
		t.Fatalf("%d answers were 503 or 429", busy.Load())
	}
	if retriesFailed.Load() != 0 {
		t.Fatalf("%d of %d requests signed again after ts_stale failed", retriesFailed.Load(), stales.Load())
	}
	if n := h.s.replay.signerCount(); n < signers+signed {
		t.Fatalf("%d signers hold state, want all %d (all are inside the window)", n, signers+signed)
	}
	if b := h.s.replay.bytes.Load(); b > high {
		t.Fatalf("the state holds %d bytes, past the valve's %d", b, high)
	}
	monotonic := 0
	for i := 0; i < signers; i++ {
		if _, _, recent, _ := h.s.replay.view(fmt.Sprintf("bafyreisynthetic%043d", i)); len(recent) == 0 {
			monotonic++
		}
	}
	if monotonic == 0 {
		t.Fatal("the valve never ran")
	}
	t.Logf("%d signers made monotonic; daemons: %d ts_stale, each followed by one success; flood: %d ts_stale",
		monotonic, stales.Load(), floodStale.Load())
}

// The cost of RC1 for one signed time with 10,000 signers holding state.
func BenchmarkRC1AcceptAmongTenThousandSigners(b *testing.B) {
	r := newRC1(time.Now().UnixMilli()-1, rc1Shards, rc1MemHigh, rc1MemLow)
	aids := make([]string, 10_000)
	for i := range aids {
		aids[i] = fmt.Sprintf("bafyreisynthetic%043d", i)
	}
	base := uint64(time.Now().UnixMilli())
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			r.accept(aids[i%len(aids)], base+uint64(i/len(aids)), rc1KAgent, time.Now().UnixMilli())
		}
	})
}
