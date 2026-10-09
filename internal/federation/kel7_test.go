package federation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// The federation hub KEL set (KEL H-15, H-16, H-34, SI-43) and authPeer's
// checks before the body (sealed-sender SSR-H16, 2026-10-09).

func marshalKEL(t testing.TB, kel []identity.SignedEvent) []byte {
	t.Helper()
	b, err := identity.MarshalKEL(kel)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// copyOf is a second controller of c's identity as it is now, which can
// make events c does not (a fork, an event from another time).
func copyOf(t testing.TB, c *identity.Controller) *identity.Controller {
	t.Helper()
	b, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	cp, err := identity.Restore(b)
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

// servedKEL is what a fake peer's /hub/identity serves; set replaces it.
type servedKEL struct{ p atomic.Pointer[[]byte] }

func (s *servedKEL) set(b []byte) { c := append([]byte(nil), b...); s.p.Store(&c) }

// peerOf is a federation service of self with one delivery peer, peer,
// whose /hub/identity serves what served holds.
func peerOf(t *testing.T, self, peer *hubid.Identity, served *servedKEL) *Service {
	t.Helper()
	served.set(peer.KEL)
	fake := peerIdentityServer(t, peer.AID, &served.p)
	svc, err := New(t.TempDir(), Config{Delivery: "allowlist", Peers: []Peer{{AID: peer.AID, Endpoint: fake.URL}}}, self)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	return svc
}

func pinLen(t *testing.T, svc *Service, aid string) int {
	t.Helper()
	kel, err := svc.PeerKEL(aid)
	if err != nil {
		t.Fatal(err)
	}
	return len(kel)
}

// KEL H-15: a peer's key history is pinned on first use and afterwards only
// extended: a longer history that extends the pin is taken (the 10-minute
// sync), one that contradicts it is not (and is noted for the operator),
// nor is one whose new event is from the future (R-9). A peer whose key
// history is not a hub's (toad 1) is never pinned.
func TestPinnedPeerKELExtendsNotReplaces(t *testing.T) {
	self, peer, _ := threeHubIdentities(t)
	var served servedKEL
	svc := peerOf(t, self, peer, &served)
	ctx := context.Background()
	if n := pinLen(t, svc, peer.AID); n != 1 {
		t.Fatalf("first pin: %d events", n)
	}
	beforeRot := copyOf(t, peer.Ctrl)
	now := uint64(time.Now().UnixMilli())
	if err := identitytest.Rotate(peer.Ctrl, now); err != nil {
		t.Fatal(err)
	}
	rotated := marshalKEL(t, peer.Ctrl.KEL())
	// A longer history from the future is not taken.
	future := copyOf(t, peer.Ctrl)
	if err := identitytest.Rotate(future, now+uint64(10*time.Minute/time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	served.set(marshalKEL(t, future.KEL()))
	if n := svc.SyncPeerKELs(ctx); n != 0 || pinLen(t, svc, peer.AID) != 1 {
		t.Fatalf("a history with an event from the future extended the pin")
	}
	// The rotation is taken.
	served.set(rotated)
	if n := svc.SyncPeerKELs(ctx); n != 1 || pinLen(t, svc, peer.AID) != 2 {
		t.Fatalf("the peer's rotation did not extend the pin")
	}
	pinned, err := svc.PinnedHubKELs()
	if err != nil || len(pinned) != 1 || pinned[0].AID != peer.AID || !bytes.Equal(pinned[0].KEL, rotated) {
		t.Fatalf("PinnedHubKELs: %+v %v", pinned, err)
	}
	// A fork (the same icp, another rot at seq 1) is not taken.
	if err := identitytest.Rotate(beforeRot, now+3); err != nil {
		t.Fatal(err)
	}
	served.set(marshalKEL(t, beforeRot.KEL()))
	if n := svc.SyncPeerKELs(ctx); n != 0 {
		t.Fatal("a fork extended the pin")
	}
	kel, err := svc.PeerKEL(peer.AID)
	if err != nil || !bytes.Equal(marshalKEL(t, kel), rotated) {
		t.Fatal("a fork replaced the pin")
	}
	if forks := svc.PeerKELForks(); len(forks) != 1 || forks[0].AID != peer.AID {
		t.Errorf("the fork was not noted: %+v", forks)
	}
	// The same history again changes nothing.
	served.set(rotated)
	if n := svc.SyncPeerKELs(ctx); n != 0 || pinLen(t, svc, peer.AID) != 2 {
		t.Error("the same history")
	}
	// An agent's key history (toad 1) under its own AID is no hub's.
	agent, err := identitytest.Agent()
	if err != nil {
		t.Fatal(err)
	}
	var agentServed servedKEL
	agentID := &hubid.Identity{Ctrl: agent, AID: agent.AID(), KEL: marshalKEL(t, agent.KEL())}
	svc2 := peerOf(t, self, agentID, &agentServed)
	if _, err := svc2.PeerKEL(agent.AID()); err == nil {
		t.Fatal("an agent's key history was pinned as a hub's")
	}
	if n := pinnedPeerKELs(t, svc2); n != 0 {
		t.Fatalf("%d pins", n)
	}
}

// KEL SI-43, M19 (the hub's side): a strict prefix of the pin, such as the
// history from before an emergency rotation, which whoever holds the old
// key can serve, is never used: a notice the old key signs after the
// rotation does not verify against what this hub holds, though it would
// against the prefix.
func TestPeerKELStrictPrefixNeverUsed(t *testing.T) {
	self, peer, _ := threeHubIdentities(t)
	var served servedKEL
	svc := peerOf(t, self, peer, &served)
	before := peer.KEL
	oldKey := copyOf(t, peer.Ctrl) // signs with the key of state 0
	rotAt := uint64(time.Now().UnixMilli())
	if err := identitytest.RotateEmergency(peer.Ctrl, rotAt); err != nil {
		t.Fatal(err)
	}
	served.set(marshalKEL(t, peer.Ctrl.KEL()))
	if n := pinLen(t, svc, peer.AID); n != 2 {
		t.Fatalf("pinned %d events", n)
	}
	// The history from before the rotation, served again and asked for.
	served.set(before)
	svc.SyncPeerKELs(context.Background())
	if _, err := svc.RefreshPeerKEL(peer.AID); err != nil {
		t.Fatal(err)
	}
	if n := pinLen(t, svc, peer.AID); n != 2 {
		t.Fatalf("a strict prefix replaced the pin: %d events", n)
	}
	// An agent the peer witnesses, and a notice the old key signs now.
	agent, err := identitytest.Agent()
	if err != nil {
		t.Fatal(err)
	}
	if err := identitytest.SwitchWitness(agent, peer.AID, rotAt); err != nil {
		t.Fatal(err)
	}
	states, err := identity.Replay(agent.KEL())
	if err != nil {
		t.Fatal(err)
	}
	tip := states[len(states)-1]
	at := rotAt + 1000
	notice, err := identity.SignNotice(oldKey, identity.NoticeBody{AID: agent.AID(), Seq: tip.KeyStateSeq, Head: tip.LastEventID, ObservedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	held := func(aid string) ([]identity.SignedEvent, bool) {
		k, err := svc.PeerKEL(aid)
		return k, err == nil
	}
	if err := identity.VerifyNotice(notice, agent.KEL(), held, at); !errors.Is(err, identity.ErrNoticeInvalid) {
		t.Fatalf("the old key's notice against the pinned history: %v, want witness-invalid", err)
	}
	prefix, err := identity.UnmarshalKEL(before)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.VerifyNotice(notice, agent.KEL(), func(string) ([]identity.SignedEvent, bool) { return prefix, true }, at); err != nil {
		t.Fatalf("the check is not the one the prefix would pass: %v", err)
	}
}

// KEL H-15, H-34, core CORE-K16: a peer that rotated signs with its new
// key at once; the pin is fetched again for the key state the request
// names, at most once a minute, and the request is taken under the tip.
func TestAuthPeerFollowsAPeerRotation(t *testing.T) {
	a, b := newTestHub(t), newTestHub(t)
	a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, nil)
	env := fedEnv(t, "did:anet:bob", "x")
	forward := func() (int, string) {
		code, body, _ := do(t, a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env, 0, nil))
		return code, reasonOf(body)
	}
	// b's /hub/identity serves what served holds, so that the test can
	// change it while b serves.
	var served servedKEL
	served.set(b.id.KEL)
	b.mu.Lock()
	routes := b.h
	b.h = stampWire(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hub/identity" {
			routes.ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusOK, hubid.IdentityResponse{AID: b.id.AID, KEL: wire3.EncodeB64URL(*served.p.Load()), Wire: wire3.Version})
	})
	b.mu.Unlock()
	rotate := func() {
		t.Helper()
		if err := identitytest.Rotate(b.id.Ctrl, nextTS()); err != nil {
			t.Fatal(err)
		}
		served.set(marshalKEL(t, b.id.Ctrl.KEL()))
	}
	if code, r := forward(); code != 200 {
		t.Fatalf("before the rotation: %d %s", code, r)
	}
	rotate()
	if code, r := forward(); code != 200 {
		t.Fatalf("signed with the new key: %d %s", code, r)
	}
	if n := pinLen(t, a.svc, b.id.AID); n != 2 {
		t.Fatalf("the pin has %d events", n)
	}
	// Again within the minute: not fetched again.
	rotate()
	fetches := b.hitsOf("/hub/identity")
	if code, r := forward(); code != 401 || r != "unauthorized" {
		t.Fatalf("a second rotation within the minute: %d %s", code, r)
	}
	if got := b.hitsOf("/hub/identity"); got != fetches {
		t.Fatalf("the peer's key history was fetched %d more times within the minute", got-fetches)
	}
	a.svc.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	if code, r := forward(); code != 200 {
		t.Fatalf("a minute later: %d %s", code, r)
	}
}

// SSR-H16: a /fed/v3 request that the headers alone refuse is refused
// before any of its body is read, and never reaches the kernel: a signer
// not a peer, a peer's AID unsigned, a time outside the window or at or
// below the peer's RC1 floor (refused as a bad signature is, without the
// floor: PAY-R8), a key state the peer's key history does not reach, a
// declared length over the route's, the source hub's bucket empty.
func TestFedBodyIsReadOnlyAfterHeaderChecks(t *testing.T) {
	a, b, stranger := newTestHub(t), newTestHub(t), newTestHub(t)
	a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, nil)
	a.k.maxEnvelope = 1 << 10
	var reads atomic.Int32
	testHookPeerBodyRead = func() { reads.Add(1) }
	t.Cleanup(func() { testHookPeerBodyRead = nil })
	env := fedEnv(t, "did:anet:bob", "x")
	big := bytes.Repeat([]byte{1}, 2<<10)
	floorTS := nextTS()
	cases := []struct {
		name   string
		req    func() *http.Request
		code   int
		reason string
	}{
		{"a hub not a peer", func() *http.Request {
			return a.signedReq(stranger.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env, 0, nil)
		}, 403, "not_peer"},
		{"a peer's AID with no signature", func() *http.Request {
			r := a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env, 0, nil)
			r.Header.Del(relayauth.HeaderSig)
			return r
		}, 401, "unauthorized"},
		{"a time 11 minutes old", func() *http.Request {
			return a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env,
				uint64(time.Now().Add(-11*time.Minute).UnixMilli()), nil)
		}, 401, "unauthorized"},
		{"a time at the peer's floor", func() *http.Request {
			a.k.mu.Lock()
			a.k.floors[b.id.AID] = floorTS
			a.k.mu.Unlock()
			return a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env, floorTS, nil)
		}, 401, "unauthorized"},
		{"a key state past the peer's key history", func() *http.Request {
			r := a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env, 0, nil)
			r.Header.Set(relayauth.HeaderSeq, "5")
			return r
		}, 401, "unauthorized"},
		{"a declared length over the route's", func() *http.Request {
			return a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", big, 0, nil)
		}, 413, "too_large"},
		{"the source hub's bucket empty", func() *http.Request {
			a.k.mu.Lock()
			a.k.sourceEmpty = true
			a.k.mu.Unlock()
			return a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env, 0, nil)
		}, 429, "source_rate"},
	}
	for _, tc := range cases {
		code, body, h := do(t, tc.req())
		if code != tc.code || reasonOf(body) != tc.reason {
			t.Errorf("%s: %d %s, want %d %s", tc.name, code, body, tc.code, tc.reason)
		}
		if h.Get(headerTSFloor) != "" || bytes.Contains(body, []byte(`"floor"`)) {
			t.Errorf("%s: an unverified request was told the floor", tc.name)
		}
		if n := reads.Load(); n != 0 {
			t.Fatalf("%s: the body was read (%d reads)", tc.name, n)
		}
	}
	if n := len(a.k.forwarded()); n != 0 {
		t.Fatalf("the kernel was handed %d refused forwards", n)
	}
	a.k.mu.Lock()
	a.k.sourceEmpty = false
	a.k.mu.Unlock()
	if code, body, _ := do(t, a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env, 0, nil)); code != 200 || reads.Load() != 1 {
		t.Fatalf("a good forward: %d %s, %d reads", code, body, reads.Load())
	}
}

// SSR-H16: the /fed/v3 request bodies held at once are bounded for the
// whole hub. A body that does not fit is refused, 429 source_rate with
// Retry-After 1: a declared length before any of it is read, one of unknown
// length once what it read passes the bound. What a request held is given
// back when it is answered.
func TestFedBodyBudget(t *testing.T) {
	a, b := newTestHub(t), newTestHub(t)
	a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, nil)
	a.k.maxEnvelope = 1 << 20
	a.svc.bodies = newBodyBudget(4 << 10)
	reading := make(chan struct{}, 8)
	testHookPeerBodyRead = func() { reading <- struct{}{} }
	t.Cleanup(func() { testHookPeerBodyRead = nil })
	body := func(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }
	send := func(r *http.Request) (int, string, http.Header) {
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			return 0, err.Error(), nil
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, reasonOf(out), resp.Header
	}
	// 1: 3 KiB, its upload held open.
	b1 := body(3<<10, 1)
	pr, pw := io.Pipe()
	req1 := a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", b1, 0, nil)
	req1.Body, req1.ContentLength, req1.GetBody = pr, int64(len(b1)), nil
	done1 := make(chan int, 1)
	go func() { code, _, _ := send(req1); done1 <- code }()
	<-reading
	if held := a.svc.bodies.held(); held != int64(len(b1)) {
		t.Fatalf("a reading request holds %d", held)
	}
	// 2: 2 KiB more does not fit; nothing of it is read.
	code, reason, h := send(a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", body(2<<10, 2), 0, nil))
	if code != 429 || reason != "source_rate" || h.Get("Retry-After") != "1" {
		t.Fatalf("over the bound: %d %s Retry-After %q", code, reason, h.Get("Retry-After"))
	}
	if len(reading) != 0 {
		t.Fatal("a body over the bound was read")
	}
	// 3: of unknown length, refused once what it read passes the bound.
	b3 := body(2<<10, 3)
	req3 := a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", b3, 0, nil)
	req3.Body, req3.ContentLength, req3.GetBody = io.NopCloser(struct{ io.Reader }{bytes.NewReader(b3)}), -1, nil
	if code, reason, _ := send(req3); code != 429 || reason != "source_rate" {
		t.Fatalf("a chunked body over the bound: %d %s", code, reason)
	}
	<-reading
	// 1 completes and gives back what it held.
	go func() { pw.Write(b1); pw.Close() }()
	if code := <-done1; code != 200 {
		t.Fatalf("the held request: %d", code)
	}
	if held := a.svc.bodies.held(); held != 0 {
		t.Fatalf("after the requests were answered %d is held", held)
	}
	if code, reason, _ := send(a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", body(2<<10, 4), 0, nil)); code != 200 {
		t.Fatalf("2 KiB once the bound is free: %d %s", code, reason)
	}
	if got := a.k.forwarded(); len(got) != 2 || !bytes.Equal(got[0].body, b1) {
		t.Fatalf("the kernel got %d forwards", len(got))
	}
	// The bound of the hub is 256 MiB.
	if fedBodyBudget != 256<<20 {
		t.Errorf("fedBodyBudget = %d", fedBodyBudget)
	}
}

// FuzzPinPeerKEL serves fuzzed bytes as a peer's key history, after a pin of
// two events. Properties: nothing panics, and what is pinned afterwards is
// the pin or a history that extends it (never shorter, never another).
func FuzzPinPeerKEL(f *testing.F) {
	self, err := hubid.LoadOrIncept(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	peer, err := hubid.LoadOrIncept(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add(peer.KEL)
	base := copyOf(f, peer.Ctrl)
	now := uint64(time.Now().UnixMilli())
	if err := identitytest.Rotate(base, now); err != nil {
		f.Fatal(err)
	}
	pinBlob := marshalKEL(f, base.KEL())
	f.Add(pinBlob)
	longer := copyOf(f, base)
	if err := identitytest.Rotate(longer, now+1); err != nil {
		f.Fatal(err)
	}
	f.Add(marshalKEL(f, longer.KEL()))
	fork := copyOf(f, peer.Ctrl)
	if err := identitytest.RotateEmergency(fork, now+2); err != nil {
		f.Fatal(err)
	}
	f.Add(marshalKEL(f, fork.KEL()))
	pin, err := identity.UnmarshalKEL(pinBlob)
	if err != nil {
		f.Fatal(err)
	}
	svc, err := New(f.TempDir(), Config{Delivery: "allowlist", Peers: []Peer{{AID: peer.AID, Endpoint: "http://127.0.0.1:1"}}}, self)
	if err != nil {
		f.Fatal(err)
	}
	defer svc.Close()
	f.Fuzz(func(t *testing.T, served []byte) {
		if err := svc.storePin(peer.AID, pinBlob); err != nil {
			t.Fatal(err)
		}
		if next, err := provenPeerKEL(served, peer.AID); err == nil {
			_, _ = svc.pinPeerKEL(peer.AID, next, served)
		}
		after, err := svc.pinnedPeerKEL(peer.AID)
		if err != nil {
			t.Fatal(err)
		}
		if len(after) < len(pin) || identity.ExtendsKEL(pin, after) != nil {
			t.Fatalf("the pin became a history of %d events that does not extend it", len(after))
		}
	})
}

// FuzzAuthPeerHeaders sends /fed/v3/forward requests with fuzzed relayauth
// headers and a declared length. Properties: no 5xx; the body is read only
// when the signer is the peer, the time is within the window and above the
// floor, the key state is one the peer's pinned key history reaches and the
// declared length fits; no refusal tells the floor.
func FuzzAuthPeerHeaders(f *testing.F) {
	a, b := newTestHub(f), newTestHub(f)
	a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, nil)
	a.k.maxEnvelope = 1 << 10
	if _, err := a.svc.peerKEL(a.svc.peer(b.id.AID)); err != nil {
		f.Fatal(err)
	}
	a.k.floors[b.id.AID] = uint64(time.Now().Add(-time.Minute).UnixMilli())
	var reads atomic.Int32
	testHookPeerBodyRead = func() { reads.Add(1) }
	defer func() { testHookPeerBodyRead = nil }()
	h := a.h
	f.Add(true, "0", "0", "AAAA", int64(10), []byte("envelope"))
	f.Add(true, "-120000", "0", "", int64(-1), []byte("x"))
	f.Add(false, "0", "1", "zz", int64(5000), []byte(nil))
	f.Add(true, "+5", "007", "AA==", int64(0), []byte("y"))
	f.Fuzz(func(t *testing.T, asPeer bool, ts, seq, sig string, length int64, body []byte) {
		req, err := http.NewRequest(http.MethodPost, "http://hub.test/fed/v3/forward", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.ContentLength = length
		if length < -1 || length > 1<<20 {
			req.ContentLength = int64(len(body))
		}
		req.Header.Set(wire3.Header, "3")
		aid := b.id.AID
		if !asPeer {
			aid = a.id.AID
		}
		// A time relative to now when it parses as one, else as given.
		if d, err := strconv.ParseInt(ts, 10, 64); err == nil && d > -1e7 && d < 1e7 {
			ts = strconv.FormatInt(time.Now().UnixMilli()+d, 10)
		}
		for k, v := range map[string]string{relayauth.HeaderAID: aid, relayauth.HeaderTS: ts, relayauth.HeaderSeq: seq, relayauth.HeaderSig: sig} {
			if v != "" && !bytes.ContainsAny([]byte(v), "\r\n\x00") {
				req.Header.Set(k, v)
			}
		}
		before := reads.Load()
		rec := &recorder{h: http.Header{}}
		h.ServeHTTP(rec, req)
		if rec.code >= 500 {
			t.Fatalf("%d", rec.code)
		}
		if rec.h.Get(headerTSFloor) != "" && rec.code != 401 {
			t.Fatalf("a floor on a %d", rec.code)
		}
		if reads.Load() == before {
			return
		}
		// The body was read: the headers passed.
		n, err := strconv.ParseUint(req.Header.Get(relayauth.HeaderTS), 10, 64)
		s, serr := strconv.ParseUint(req.Header.Get(relayauth.HeaderSeq), 10, 64)
		if !asPeer || err != nil || serr != nil || !withinMaxSkew(n, a.svc.now()) || n <= a.k.PeerFloor(aid) || s >= 1 ||
			req.ContentLength > a.k.maxEnvelope {
			t.Fatalf("the body was read for headers that do not pass: peer %v ts %q seq %q length %d", asPeer, ts, seq, req.ContentLength)
		}
	})
}

// recorder is a minimal ResponseWriter whose body is thrown away.
type recorder struct {
	h    http.Header
	code int
}

func (r *recorder) Header() http.Header { return r.h }
func (r *recorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = 200
	}
	return len(b), nil
}
func (r *recorder) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
}
