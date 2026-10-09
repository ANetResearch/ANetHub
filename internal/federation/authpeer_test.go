package federation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// TestAuthPeer (sealed-sender SSR-H16, core G3): every /fed/v3 route is
// open to the hubs of the peer table only, signed by the asking hub for the
// route's action over exactly the request. Each refusal comes from authPeer
// with its own code, before the kernel sees anything.
func TestAuthPeer(t *testing.T) {
	a, b, stranger := newTestHub(t), newTestHub(t), newTestHub(t)
	a.start(Config{Delivery: "allowlist", Discovery: "allowlist", Peers: []Peer{b.peer()}}, &fakeDirectory{})
	env := fedEnv(t, "did:anet:bob", "x")
	fwd := func(as *testHub, action string, edit func(*http.Request)) (int, string) {
		req := a.signedReq(as.id, action, http.MethodPost, "/fed/v3/forward", env, 0, nil)
		if edit != nil {
			edit(req)
		}
		code, body, _ := do(t, req)
		return code, reasonOf(body)
	}
	cases := []struct {
		name   string
		as     *testHub
		action string
		edit   func(*http.Request)
		code   int
		reason string
	}{
		{"no signature", b, relayauth.ActionFedForward, func(r *http.Request) { r.Header.Del(relayauth.HeaderSig) },
			401, "unauthorized"},
		{"two signatures", b, relayauth.ActionFedForward, func(r *http.Request) { r.Header.Add(relayauth.HeaderSig, r.Header.Get(relayauth.HeaderSig)) },
			401, "unauthorized"},
		{"a time not in canonical decimal", b, relayauth.ActionFedForward,
			func(r *http.Request) { r.Header.Set(relayauth.HeaderTS, "0"+r.Header.Get(relayauth.HeaderTS)) }, 401, "unauthorized"},
		{"a hub that is not a peer", stranger, relayauth.ActionFedForward, nil, 403, "not_peer"},
		// Step 1 comes before the signature's own headers are read.
		{"a hub that is not a peer, its signature malformed", stranger, relayauth.ActionFedForward,
			func(r *http.Request) { r.Header.Set(relayauth.HeaderSig, "not a signature") }, 403, "not_peer"},
		{"a hub that is not a peer, its time missing", stranger, relayauth.ActionFedForward,
			func(r *http.Request) { r.Header.Del(relayauth.HeaderTS) }, 403, "not_peer"},
		{"a peer, its signature malformed", b, relayauth.ActionFedForward,
			func(r *http.Request) { r.Header.Set(relayauth.HeaderSig, "not a signature") }, 401, "unauthorized"},
		{"no signer named", b, relayauth.ActionFedForward,
			func(r *http.Request) { r.Header.Del(relayauth.HeaderAID) }, 401, "unauthorized"},
		{"a peer naming another peer's AID", stranger, relayauth.ActionFedForward,
			func(r *http.Request) { r.Header.Set(relayauth.HeaderAID, b.id.AID) }, 401, "unauthorized"},
		{"another action", b, relayauth.ActionFedBucket, nil, 401, "unauthorized"},
		{"a retired action", b, "fedkeys", nil, 401, "unauthorized"},
		{"another target", b, relayauth.ActionFedForward,
			func(r *http.Request) { r.URL.RawQuery = "x=1" }, 401, "unauthorized"},
	}
	for _, tc := range cases {
		if code, reason := fwd(tc.as, tc.action, tc.edit); code != tc.code || reason != tc.reason {
			t.Errorf("%s: %d %s, want %d %s", tc.name, code, reason, tc.code, tc.reason)
		}
	}
	// Signed over another body, and outside the time window.
	if code, body, _ := do(t, a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env, 0, []byte("other"))); code != 401 || reasonOf(body) != "unauthorized" {
		t.Errorf("a signature over another body: %d %s", code, body)
	}
	old := uint64(time.Now().Add(-11 * time.Minute).UnixMilli())
	if code, body, _ := do(t, a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env, old, nil)); code != 401 || reasonOf(body) != "unauthorized" {
		t.Errorf("a time 11 minutes old: %d %s", code, body)
	}
	if n := len(a.k.forwarded()); n != 0 {
		t.Fatalf("the kernel was handed %d refused forwards", n)
	}
	// The same signed request twice: RC1 (the kernel's, K = 4096) refuses
	// the second.
	req := a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", env, 0, nil)
	again := req.Clone(context.Background())
	again.Body = io.NopCloser(bytes.NewReader(env))
	if code, body, _ := do(t, req); code != http.StatusOK {
		t.Fatalf("a good forward: %d %s", code, body)
	}
	if code, body, _ := do(t, again); code != 401 || reasonOf(body) != "replayed" {
		t.Errorf("the same request again: %d %s, want 401 replayed", code, body)
	}
	got := a.k.forwarded()
	if len(got) != 1 || got[0].peer != b.id.AID || !bytes.Equal(got[0].body, env) {
		t.Fatalf("the kernel was handed %+v", got)
	}
}

// The route's switch: with delivery federation off, a peer's forward and
// bucket requests are not_peer; with discovery off, so are its card and
// review stream requests.
func TestAuthPeerFollowsTheRoutesSwitch(t *testing.T) {
	a, b := newTestHub(t), newTestHub(t)
	a.start(Config{Delivery: "off", Discovery: "allowlist", Peers: []Peer{b.peer()}}, &fakeDirectory{})
	for _, rt := range []struct{ action, path string }{
		{relayauth.ActionFedForward, "/fed/v3/forward"},
		{relayauth.ActionFedBucket, "/fed/v3/directory:bucket"},
	} {
		code, body, _ := do(t, a.signedReq(b.id, rt.action, http.MethodPost, rt.path, []byte("{}"), 0, nil))
		if code != http.StatusForbidden || reasonOf(body) != "not_peer" {
			t.Errorf("%s with delivery off: %d %s", rt.path, code, body)
		}
	}
}

// A request signed under a key the peer hub has rotated away from is
// key_retired, not unauthorized.
func TestAuthPeerKeyRetired(t *testing.T) {
	a, b := newTestHub(t), newTestHub(t)
	snap, err := b.id.Ctrl.Export()
	if err != nil {
		t.Fatal(err)
	}
	kel := b.id.Ctrl.KEL()
	rotAt := kel[len(kel)-1].Event.Timestamp + 1
	for nextTS() < rotAt {
	}
	if err := identitytest.Rotate(b.id.Ctrl, rotAt); err != nil {
		t.Fatal(err)
	}
	if b.id.KEL, err = identity.MarshalKEL(b.id.Ctrl.KEL()); err != nil {
		t.Fatal(err)
	}
	oldKey, err := identity.Restore(snap)
	if err != nil {
		t.Fatal(err)
	}
	a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, nil)
	env := fedEnv(t, "did:anet:bob", "x")
	req, _ := http.NewRequest(http.MethodPost, a.srv.URL+"/fed/v3/forward", bytes.NewReader(env))
	req.Header.Set(wire3.Header, "3")
	ts := nextTS()
	sig, seq := oldKey.Sign(relayauth.PreimageV2(relayauth.ActionFedForward, b.id.AID, a.id.AID, ts, http.MethodPost, "/fed/v3/forward", env))
	req.Header.Set(relayauth.HeaderAID, b.id.AID)
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	if code, body, _ := do(t, req); code != 401 || reasonOf(body) != "key_retired" {
		t.Fatalf("a signature under the rotated-away key: %d %s, want 401 key_retired", code, body)
	}
}

// /fed/v3/forward steps 1 to 4 (sealed-sender §4.2.7) come in their order:
// the peer table, the source hub's bucket (looked at, before the body is
// read), the body's size, the signature.
func TestFedForwardStepsBeforeTheKernel(t *testing.T) {
	a, b, stranger := newTestHub(t), newTestHub(t), newTestHub(t)
	a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, nil)
	a.k.maxEnvelope = 1 << 10
	big := bytes.Repeat([]byte{1}, 2<<10)
	// 1 before 2: a stranger is not_peer even with the bucket empty.
	a.k.sourceEmpty = true
	if code, body, _ := do(t, a.signedReq(stranger.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", big, 0, nil)); code != 403 || reasonOf(body) != "not_peer" {
		t.Errorf("step 1: %d %s", code, body)
	}
	// 2 before 3 and 4: the bucket answers before the body or the
	// signature is looked at.
	code, body, h := do(t, a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", big, 0, []byte("other")))
	if code != 429 || reasonOf(body) != "source_rate" || h.Get("Retry-After") != "3" {
		t.Errorf("step 2: %d %s Retry-After %q", code, body, h.Get("Retry-After"))
	}
	a.k.sourceEmpty = false
	// 3 before 4.
	if code, body, _ := do(t, a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", big, 0, []byte("other"))); code != 413 || reasonOf(body) != "too_large" {
		t.Errorf("step 3: %d %s", code, body)
	}
	if n := len(a.k.forwarded()); n != 0 {
		t.Fatalf("the kernel was handed %d refused forwards", n)
	}
}

// Forward hands the envelope to the one peer named, with its access, signed
// for fed_forward; a peer that answers replayed is asked once more with a
// new signature, and only once.
func TestForwardRetriesReplayedOnce(t *testing.T) {
	a, b := newTestHub(t), newTestHub(t)
	sa := a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, nil)
	var calls atomic.Int32
	var replays int32 = 1
	b.start(Config{Delivery: "allowlist", Peers: []Peer{a.peer()}}, nil)
	b.mu.Lock()
	full := b.h
	b.h = stampWire(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fed/v3/forward" && calls.Add(1) <= atomic.LoadInt32(&replays) {
			wire3.Refuse(w, wire3.ReasonReplayed)
			return
		}
		full.ServeHTTP(w, r)
	})
	b.mu.Unlock()
	env := fedEnv(t, "did:anet:bob", "y")
	resp, err := sa.Forward(context.Background(), b.id.AID, env, "YWNjZXNz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("after one replayed: %d after %d calls", resp.StatusCode, calls.Load())
	}
	got := b.k.forwarded()
	if len(got) != 1 || got[0].access != "YWNjZXNz" || !bytes.Equal(got[0].body, env) || got[0].peer != a.id.AID {
		t.Fatalf("the peer's kernel got %+v", got)
	}
	// Two replayed in a row: the second answer is the caller's.
	calls.Store(0)
	atomic.StoreInt32(&replays, 2)
	resp, err = sa.Forward(context.Background(), b.id.AID, env, "YWNjZXNz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || calls.Load() != 2 {
		t.Fatalf("after two replayed: %d after %d calls", resp.StatusCode, calls.Load())
	}
	// Not a delivery peer: nothing is sent.
	if _, err := sa.Forward(context.Background(), "did:anet:nobody", env, "x"); err == nil {
		t.Fatal("a forward to a hub that is not a peer was sent")
	}
	if _, err := sa.Bucket(context.Background(), "did:anet:nobody", []byte("{}")); err == nil {
		t.Fatal("a bucket request to a hub that is not a peer was sent")
	}
}

// TestFedPeerWireMismatchStops (core CORE-V1; sealed-sender §8.2 SS-6): an
// answer of a peer that states another hub wire, or none, is counted, and
// this hub stops talking to that peer: the next requests fail without being
// sent, until peerWireRetry has passed; then one goes through, and a peer
// that speaks wire 3 again is talked to as before. A refusal without the
// header (a proxy in front of the hub: a 502 for a hub that is down, a 413
// for a body over the proxy's own limit) is not counted and stops nothing.
func TestFedPeerWireMismatchStops(t *testing.T) {
	var wire atomic.Value
	wire.Store("2")
	var hits atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch v := wire.Load().(string); v {
		case "proxy":
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		case "proxy-413":
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		case "":
		default:
			w.Header().Set(wire3.Header, v)
		}
		writeJSON(w, http.StatusOK, map[string]any{"max_bits": 0, "entries": []any{}})
	}))
	defer peer.Close()
	h := newTestHub(t)
	svc := h.start(Config{Delivery: "allowlist", Peers: []Peer{{AID: "did:anet:peer", Endpoint: peer.URL}}}, nil)
	now := time.Now()
	svc.now = func() time.Time { return now }
	ask := func() error {
		resp, err := svc.wire.RoundTrip(mustReq(t, peer.URL+"/fed/v3/directory:bucket"))
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := ask(); !errors.Is(err, ErrPeerWire) || svc.PeerWireMismatches() != 1 || hits.Load() != 1 {
		t.Fatalf("an answer of wire 2: %v, %d counted, %d sent", err, svc.PeerWireMismatches(), hits.Load())
	}
	// Stopped: nothing is sent.
	for i := 0; i < 3; i++ {
		if err := ask(); !errors.Is(err, ErrPeerWire) || hits.Load() != 1 {
			t.Fatalf("a request while stopped: %v, %d sent", err, hits.Load())
		}
	}
	// Through the service's own requests too.
	if _, err := svc.Bucket(context.Background(), "did:anet:peer", []byte("{}")); !errors.Is(err, ErrPeerWire) || hits.Load() != 1 {
		t.Fatalf("Bucket while stopped: %v, %d sent", err, hits.Load())
	}
	// No header at all is a mismatch too.
	now = now.Add(peerWireRetry)
	wire.Store("")
	if err := ask(); !errors.Is(err, ErrPeerWire) || svc.PeerWireMismatches() != 2 || hits.Load() != 2 {
		t.Fatalf("an answer without the header: %v, %d counted, %d sent", err, svc.PeerWireMismatches(), hits.Load())
	}
	// Upgraded: after the wait, one request goes through and talking
	// resumes.
	now = now.Add(peerWireRetry - time.Second)
	if err := ask(); !errors.Is(err, ErrPeerWire) || hits.Load() != 2 {
		t.Fatalf("a request a second before the wait ends: %v, %d sent", err, hits.Load())
	}
	now = now.Add(time.Second)
	wire.Store("3")
	for i := 0; i < 2; i++ {
		if err := ask(); err != nil {
			t.Fatalf("a request to the upgraded peer: %v", err)
		}
	}
	// A proxy's 502 without the header is the peer being unreachable, not
	// another wire.
	wire.Store("proxy")
	if err := ask(); err != nil || svc.PeerWireMismatches() != 2 {
		t.Fatalf("a proxy's 502: %v, %d counted", err, svc.PeerWireMismatches())
	}
	if err := ask(); err != nil || hits.Load() != 6 {
		t.Fatalf("the peer was cut off after a proxy's 502: %v, %d sent", err, hits.Load())
	}
	// Nor is a proxy's 413: an envelope larger than the peer's proxy takes
	// must not cut every sender here off from the peer.
	wire.Store("proxy-413")
	for i := 0; i < 2; i++ {
		resp, err := svc.wire.RoundTrip(mustReq(t, peer.URL+"/fed/v3/forward"))
		if err != nil || resp.StatusCode != http.StatusRequestEntityTooLarge || svc.PeerWireMismatches() != 2 {
			t.Fatalf("a proxy's 413: %v, %d counted", err, svc.PeerWireMismatches())
		}
		resp.Body.Close()
	}
	wire.Store("3")
	if err := ask(); err != nil || hits.Load() != 9 {
		t.Fatalf("the peer was cut off after a proxy's 413: %v, %d sent", err, hits.Load())
	}
}

func mustReq(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	return req
}
