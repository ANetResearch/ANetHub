package aghub

// Federation v3, the kernel's half (sealed-sender §4.2.6, §4.2.7, SSR-H12 to
// SSR-H15a, SSR-W19, SSR-W21): hubs on frozen clocks, each with the real
// federation module, peered with each other over HTTP.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// fedNode is one hub of a fedNet: a relayHub (the kernel, on its frozen
// clock) with its federation module, served over HTTP.
type fedNode struct {
	*relayHub
	fed  *federation.Service
	http *httptest.Server
	mu   sync.Mutex
	root http.Handler
	hits map[string]int
	// seen holds every request to /fed/v3/forward as it crossed: its
	// headers and its body.
	seen [][]byte
	// down makes the hub answer every request 503 without the wire
	// header, as a reverse proxy in front of a hub that is down does.
	down atomic.Bool
	// answer, when set, answers /fed/v3/forward in place of the hub,
	// bucket /fed/v3/directory:bucket and status /fed/v3/relay-status.
	answer, bucket, status http.HandlerFunc
	// statusSeen holds every request to /fed/v3/relay-status as it
	// crossed: its headers and its body.
	statusSeen [][]byte
}

// fedNet is hubs peered for delivery, each with each other one.
type fedNet struct {
	t     testing.TB
	nodes []*fedNode
}

func newFedNet(t testing.TB, n int) *fedNet {
	t.Helper()
	net := &fedNet{t: t}
	for i := 0; i < n; i++ {
		nd := &fedNode{relayHub: newRelayHub(t), hits: map[string]int{}}
		nd.http = httptest.NewServer(http.HandlerFunc(nd.serveHTTP))
		t.Cleanup(nd.http.Close)
		net.nodes = append(net.nodes, nd)
	}
	for i, nd := range net.nodes {
		var peers []federation.Peer
		for j, p := range net.nodes {
			if i != j {
				peers = append(peers, federation.Peer{AID: p.hubAID, Endpoint: p.http.URL})
			}
		}
		fed, err := federation.New(t.TempDir(), federation.Config{Delivery: "allowlist", Witness: "off", Peers: peers}, nd.hubID)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fed.Close() })
		nd.wire(fed)
	}
	return net
}

// wire connects the node's kernel and federation module, as cmd/anet-hub
// does, and serves them.
func (nd *fedNode) wire(fed *federation.Service) {
	nd.fed = fed
	fed.SetKernel(nd.srv)
	fed.SetDeliveryStatus(nd.srv)
	nd.srv.SetFederation(fed)
	nd.srv.SetPeerKELResolver(fed.PeerKEL)
	mux := http.NewServeMux()
	mux.Handle("/hub/identity", nd.hubID.Handler())
	mux.Handle("/fed/v3/", fed.Handler())
	mux.Handle("/", nd.srv.Handler())
	nd.mu.Lock()
	nd.root = wire3.Contract(mux)
	nd.mu.Unlock()
}

func (nd *fedNode) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if nd.down.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	nd.mu.Lock()
	nd.hits[r.URL.Path]++
	root, answer, bucket, status := nd.root, nd.answer, nd.bucket, nd.status
	if r.URL.Path == "/fed/v3/forward" || r.URL.Path == "/fed/v3/relay-status" {
		var dump bytes.Buffer
		_ = r.Header.Write(&dump)
		body, _ := io.ReadAll(r.Body)
		dump.Write(body)
		if r.URL.Path == "/fed/v3/forward" {
			nd.seen = append(nd.seen, dump.Bytes())
		} else {
			nd.statusSeen = append(nd.statusSeen, dump.Bytes())
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	nd.mu.Unlock()
	if status != nil && r.URL.Path == "/fed/v3/relay-status" {
		status(w, r)
		return
	}
	if answer != nil && r.URL.Path == "/fed/v3/forward" {
		answer(w, r)
		return
	}
	if bucket != nil && r.URL.Path == "/fed/v3/directory:bucket" {
		bucket(w, r)
		return
	}
	root.ServeHTTP(w, r)
}

// hitsOf is how many requests for path reached the node.
func (nd *fedNode) hitsOf(path string) int {
	nd.mu.Lock()
	defer nd.mu.Unlock()
	return nd.hits[path]
}

// forwards is how many forwards reached the node.
func (nd *fedNode) forwards() int { return nd.hitsOf("/fed/v3/forward") }

// sourceTokens is what the node's source bucket for the peer holds.
func (nd *fedNode) sourceTokens(peer *fedNode) float64 {
	return nd.srv.relay.fedSource.tokens(peer.hubAID, rateFedSource)
}

// send0To sends a first contact from a new agent of nd to the AID to, with
// the hint home ("" for none).
func (nd *fedNode) send0To(to, home string, ct string) *httptest.ResponseRecorder {
	nd.t.Helper()
	sender := nd.agent()
	ss := nd.openSession(sender.c)
	return nd.send0(ss, envelope(nd.t, to, []byte(ct)), kind0Opts{home: home})
}

// send1Hint sends env under its kind-1 access, with the hint home ("" for
// none), from ip ("" for relayClientIP).
func (nd *fedNode) send1Hint(env []byte, home, ip string) *httptest.ResponseRecorder {
	nd.t.Helper()
	if ip == "" {
		ip = relayClientIP
	}
	req := kind1Request(nd.t, env)
	if home != "" {
		req.Header.Set(relayauth.HeaderHome, home)
	}
	return nd.serve(req, ip)
}

// capEnv is an envelope to owner under a new credential of class that owner
// issued, valid for exp.
func capEnv(t testing.TB, h *fedNode, owner *relayAgent, class uint64, exp time.Duration, ct string) ([]byte, grant) {
	t.Helper()
	g := h.issue(owner, class, exp)
	return withCap(t, envelope(t, owner.aid, []byte(ct)), g), g
}

// signedForward is a /fed/v3/forward request to nd signed by the hub as,
// with env as the body and its access as X-ANet-Access; edit may change it
// before it is signed.
func (nd *fedNode) signedForward(as *fedNode, env []byte, edit func(*http.Request)) *http.Request {
	return nd.signedForwardThen(as, env, edit, nil)
}

// signedForwardThen is signedForward, with after applied to the request
// once it is signed.
func (nd *fedNode) signedForwardThen(as *fedNode, env []byte, edit, after func(*http.Request)) *http.Request {
	nd.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://hub.test/fed/v3/forward", bytes.NewReader(env))
	req.Header.Set(wire3.Header, "3")
	req.Header.Set("Content-Type", EnvelopeContentType)
	req.Header.Set(HeaderAccess, base64.RawURLEncoding.EncodeToString(accessRaw(nd.t, env)))
	if edit != nil {
		edit(req)
	}
	body, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(body))
	ts := relaySignTS()
	sig, seq := as.hubID.Ctrl.Sign(relayauth.PreimageV2(relayauth.ActionFedForward, as.hubAID, nd.hubAID, ts,
		req.Method, req.URL.RequestURI(), body))
	req.Header.Set(relayauth.HeaderAID, as.hubAID)
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	if after != nil {
		after(req)
	}
	return req
}

// fedServe runs req against nd's federation routes, as its peer as asks.
func (nd *fedNode) fedServe(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	nd.mu.Lock()
	root := nd.root
	nd.mu.Unlock()
	root.ServeHTTP(rec, req)
	return rec
}

// queued is how many rows nd's relay table holds for to.
func (nd *fedNode) queued(to string) int {
	nd.t.Helper()
	var n int
	if err := nd.store.db.QueryRow(`SELECT COUNT(*) FROM relay_message WHERE to_aid=?`, to).Scan(&n); err != nil {
		nd.t.Fatal(err)
	}
	return n
}

// ---- the destination ----

// TestFedForwardOrder (sealed-sender §4.2.7, SSR-H15): every step of
// /fed/v3/forward at the home refuses with its code, before any later step
// and without taking a token or writing a row; steps 1 to 4 are the
// federation module's (authPeer, internal/federation TestAuthPeer and
// TestFedForwardStepsBeforeTheKernel), here as the wired hub answers them.
func TestFedForwardOrder(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	owner, other := b.agent(), b.agent()
	good := func(ct string) []byte { e, _ := capEnv(t, b, owner, seal.CapClassContact, time.Hour, ct); return e }
	type step struct {
		name   string
		as     *fedNode
		env    []byte
		edit   func(*http.Request)
		after  func(*http.Request)
		before func()
		status int
		reason string
	}
	g11 := b.issue(owner, seal.CapClassContact, time.Hour)
	small := DefaultLimits()
	small.MaxEnvelope = 64 << 10
	full := bytes.Repeat([]byte{1}, int(small.MaxEnvelope)+1)
	steps := []step{
		// 1. The peer table: a hub not in it (c is A's and B's peer, so a
		// fresh hub stands in).
		{name: "1 not a peer", as: func() *fedNode { return newFedNet(t, 1).nodes[0] }(), env: good("1"),
			status: 403, reason: "not_peer"},
		// 2. The source hub's bucket, before the body is read.
		{name: "2 source bucket", as: a, env: full, before: func() {
			if err := b.srv.SetLimits(small); err != nil {
				t.Fatal(err)
			}
			drain(b.srv.relay.fedSource, a.hubAID, rateFedSource)
		}, status: 429, reason: "source_rate"},
		// 3. The body.
		{name: "3 too large", as: a, env: full, before: func() { b.srv.relay.fedSource.forget(a.hubAID) },
			status: 413, reason: "too_large"},
		// 4. The signature.
		{name: "4 signed for another body", as: a, env: good("4"), before: func() {
			if err := b.srv.SetLimits(DefaultLimits()); err != nil {
				t.Fatal(err)
			}
		}, after: func(r *http.Request) { r.Body = io.NopCloser(bytes.NewReader(good("4b"))) }, status: 401, reason: "unauthorized"},
		// 5. The headers.
		{name: "5 content type", as: a, env: good("5"), edit: func(r *http.Request) { r.Header.Set("Content-Type", "application/json") },
			status: 400, reason: "bad_request"},
		{name: "5 no access", as: a, env: good("5"), edit: func(r *http.Request) { r.Header.Del(HeaderAccess) },
			status: 400, reason: "bad_envelope"},
		{name: "5 session headers", as: a, env: envelope(t, owner.aid, []byte("5s")),
			edit: func(r *http.Request) {
				r.Header.Set(relayauth.HeaderSession, relayauth.EncodeSessionID(make([]byte, 16)))
			},
			status: 400, reason: "bad_request"},
		// 6. The credential.
		{name: "6 owner not here", as: a, env: func() []byte {
			o := c.agent()
			e, _ := capEnv(t, c, o, seal.CapClassContact, time.Hour, "6")
			return e
		}(), status: 403, reason: "access_invalid"},
		{name: "6 revoked", as: a, env: func() []byte {
			e, g := capEnv(t, b, owner, seal.CapClassContact, time.Hour, "6r")
			if _, _, err := b.store.RevokeCaps(owner.aid, [][]byte{g.body.CapID}); err != nil {
				t.Fatal(err)
			}
			return e
		}(), status: 403, reason: "access_invalid"},
		// 7. The envelope.
		{name: "7 not an envelope", as: a, env: []byte("not an envelope"),
			edit: func(r *http.Request) {
				r.Header.Set(HeaderAccess, base64.RawURLEncoding.EncodeToString([]byte{0xa1, 0x01, 0x00}))
			},
			status: 400, reason: "bad_envelope"},
		{name: "7 header and body differ", as: a, env: good("7"), edit: func(r *http.Request) {
			r.Header.Set(HeaderAccess, base64.RawURLEncoding.EncodeToString(accessRaw(t, good("7b"))))
		}, status: 400, reason: "bad_envelope"},
		{name: "7 a recipient AID holding U+0000", as: a, env: envelope(t, other.aid+"\x00x", []byte("7n")),
			status: 400, reason: "bad_request"},
		// 8. The credential, completed: a proof for another envelope.
		{name: "8 proof", as: a, env: func() []byte {
			e, g := capEnv(t, b, owner, seal.CapClassContact, time.Hour, "8")
			_ = e
			other := withCap(t, envelope(t, owner.aid, []byte("8 other")), g)
			body := envelope(t, owner.aid, []byte("8"))
			out, err := seal.SetAccess(body, mustOuter(t, other).Access)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}(), status: 403, reason: "access_invalid"},
		// 9. The recipient.
		{name: "9 unknown", as: a, env: envelope(t, other.aid+"x", []byte("9")), status: 404, reason: "unknown_destination"},
		// 10. Non-contact mail larger than the share.
		{name: "10 stranger size", as: a, env: envelope(t, owner.aid, bytes.Repeat([]byte("s"), DefaultNonContactBytes)),
			status: 413, reason: "too_large_for_stranger"},
		// 11. The buckets.
		{name: "11 first contacts", as: a, env: envelope(t, other.aid, []byte("11")),
			before: func() { drain(b.srv.relay.firstContact, other.aid, firstContactRate(b.store.QuotaFor(other.aid))) },
			status: 429, reason: "strangers_busy"},
		{name: "11 the credential's bucket", as: a, env: withCap(t, envelope(t, owner.aid, []byte("11c")), g11),
			before: func() { drain(b.srv.relay.caps, capKey(&g11.body), capRate(&g11.body)) },
			status: 429, reason: "rate_limited"},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			if s.before != nil {
				s.before()
			}
			before := b.effects()
			src := b.sourceTokens(s.as)
			rec := b.fedServe(b.signedForwardThen(s.as, s.env, s.edit, s.after))
			expectRefusal(t, rec, s.status, s.reason)
			if s.status != 429 && s.status != 413 {
				if d := before.diff(b.effects()); d != "" {
					t.Errorf("a refused forward changed something: %s", d)
				}
			}
			if s.status == 403 && strings.HasPrefix(s.name, "6") && b.sourceTokens(s.as) != src {
				t.Errorf("the source bucket lost %v tokens for what the source hub could not know", src-b.sourceTokens(s.as))
			}
		})
	}
	// 12. The mailbox: full.
	l := DefaultLimits()
	l.MailboxMessages = 1
	if err := b.srv.SetLimits(l); err != nil {
		t.Fatal(err)
	}
	if rec := b.fedServe(b.signedForward(a, good("12a"), nil)); rec.Code != 200 {
		t.Fatalf("12 the first: %d %s", rec.Code, rec.Body)
	}
	before := b.sourceTokens(a)
	expectRefusal(t, b.fedServe(b.signedForward(a, good("12b"), nil)), 507, "mailbox_full")
	if after := b.sourceTokens(a); after != before {
		t.Errorf("a refusal of the mailbox kept the source hub's token: %v -> %v", before, after)
	}
	// 13. Queued, with the home's rid; the same envelope again: duplicate.
	if err := b.srv.SetLimits(DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	env := good("13")
	rec := b.fedServe(b.signedForward(a, env, nil))
	var ans FedForwardResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &ans) != nil || ans.Status != RelayQueued {
		t.Fatalf("13: %d %s", rec.Code, rec.Body)
	}
	if rid, err := wire3.DecodeB64URLSize("rid", ans.RID, RIDLen); err != nil || len(rid) != RIDLen {
		t.Fatalf("13: rid %q", ans.RID)
	}
	rec = b.fedServe(b.signedForward(a, env, nil))
	var dup FedForwardResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &dup) != nil || dup.Status != RelayDuplicate || dup.RID != ans.RID {
		t.Fatalf("13 again: %d %s", rec.Code, rec.Body)
	}
}

// mustOuter parses env's outer layer.
func mustOuter(t testing.TB, env []byte) *seal.SealedEnvelope {
	t.Helper()
	o, err := seal.ParseOuter(env)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// TestSourceRatePenalty (SSR-H15a): the home takes FedSourcePenalty tokens
// from the source hub's bucket for what the source hub should have refused
// itself — a credential that does not decode or is of another type, a
// signature that does not verify under the epoch the source saw too, an
// owner that is not the recipient, a proof for another envelope — and one
// token for a forward it queues.
func TestSourceRatePenalty(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	owner, other := b.agent(), b.agent()
	_, wrongKey, _ := ed25519.GenerateKey(nil)
	cases := []struct {
		name string
		env  func() []byte
	}{
		{"decode", func() []byte {
			return withCap(t, envelope(t, owner.aid, []byte("d")), rawGrant([]byte("not a cap body"), owner.mboxPriv))
		}},
		{"type", func() []byte {
			g := b.issue(owner, seal.CapClassContact, time.Hour)
			body := g.body
			body.Type = "anet.other/1"
			raw, err := coredet.Marshal(&body)
			if err != nil {
				t.Fatal(err)
			}
			return withCap(t, envelope(t, owner.aid, []byte("t")), rawGrant(raw, owner.mboxPriv))
		}},
		{"signature", func() []byte {
			g := b.issue(owner, seal.CapClassContact, time.Hour)
			g.cap = &seal.Cap{Body: g.cap.Body, Sig: ed25519.Sign(wrongKey, g.cap.Body)}
			return withCap(t, envelope(t, owner.aid, []byte("s")), g)
		}},
		{"owner", func() []byte {
			g := b.issue(owner, seal.CapClassContact, time.Hour)
			return withCap(t, envelope(t, other.aid, []byte("o")), g)
		}},
		{"proof", func() []byte {
			g := b.issue(owner, seal.CapClassContact, time.Hour)
			_, g.holder, _ = ed25519.GenerateKey(nil)
			return withCap(t, envelope(t, owner.aid, []byte("p")), g)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b.srv.relay.fedSource.forget(a.hubAID)
			before := b.sourceTokens(a)
			expectRefusal(t, b.fedServe(b.signedForward(a, tc.env(), nil)), 403, "access_invalid")
			if lost := before - b.sourceTokens(a); lost < 9.99 || lost > 10.01 {
				t.Errorf("the source bucket lost %v tokens, want 10", lost)
			}
		})
	}
	// A forward queued costs one token.
	b.srv.relay.fedSource.forget(a.hubAID)
	env, _ := capEnv(t, b, owner, seal.CapClassContact, time.Hour, "ok")
	if rec := b.fedServe(b.signedForward(a, env, nil)); rec.Code != 200 {
		t.Fatalf("a good forward: %d %s", rec.Code, rec.Body)
	}
	if lost := rateFedSource.burst - b.sourceTokens(a); lost < 0.99 || lost > 1.01 {
		t.Errorf("a queued forward took %v tokens, want 1", lost)
	}
}

// TestSourceRateNotPenalizedForStaleOrigin (SSR-H15a, M42): what the source
// hub could not know — a revocation (only the home holds the table), an
// epoch it has not seen yet, an owner that is not registered at this hub (its
// home cache is old), a cap_exp past (the hubs' clocks differ) — is answered
// 403 and costs the source hub's bucket nothing.
func TestSourceRateNotPenalizedForStaleOrigin(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	owner := b.agent()
	cases := []struct {
		name string
		env  func() []byte
	}{
		{"revoked", func() []byte {
			e, g := capEnv(t, b, owner, seal.CapClassStranger, time.Hour, "r")
			if _, _, err := b.store.RevokeCaps(owner.aid, [][]byte{g.body.CapID}); err != nil {
				t.Fatal(err)
			}
			return e
		}},
		{"epoch", func() []byte {
			e, _ := capEnv(t, b, owner, seal.CapClassStranger, time.Hour, "e")
			b.publish(owner, owner.mbox.Epoch+1)
			return e
		}},
		{"owner elsewhere", func() []byte {
			o := c.agent()
			e, _ := capEnv(t, c, o, seal.CapClassStranger, time.Hour, "x")
			return e
		}},
		{"cap_exp", func() []byte {
			e, _ := capEnv(t, b, owner, seal.CapClassStranger, time.Minute, "c")
			b.advance(time.Minute + time.Duration(seal.CapExpGraceMS)*time.Millisecond + time.Second)
			return e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b.srv.relay.fedSource.forget(a.hubAID)
			expectRefusal(t, b.fedServe(b.signedForward(a, tc.env(), nil)), 403, "access_invalid")
			if got := b.sourceTokens(a); got != rateFedSource.burst {
				t.Errorf("the source bucket holds %v tokens, want it full (%v)", got, rateFedSource.burst)
			}
		})
	}
}

// TestRevokedCapViaFederationIsRefused (M34): a credential its owner
// revoked at its home is refused when it comes through a peer, as it is
// when it comes from a sender at the home: 403 to the sender, nothing
// queued.
func TestRevokedCapViaFederationIsRefused(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	owner := b.agent()
	env, g := capEnv(t, b, owner, seal.CapClassContact, time.Hour, "revoked")
	if _, _, err := b.store.RevokeCaps(owner.aid, [][]byte{g.body.CapID}); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, a.send1Hint(env, "", ""), 403, "access_invalid")
	if n := b.queued(owner.aid); n != 0 {
		t.Fatalf("the home queued %d envelopes under a revoked credential", n)
	}
	if b.forwards() != 1 {
		t.Fatalf("forwards at the home: %d, want 1 (the origin cannot read the home's revocations)", b.forwards())
	}
	// At the home itself, the same.
	expectRefusal(t, b.send1(withCap(t, envelope(t, owner.aid, []byte("again")), g), ""), 403, "access_invalid")
}

// ---- the origin ----

// TestOriginForwardsToOneHome (SI-17, M9): a send for an agent registered at
// a peer is handed to that one peer, its home, and to no other; the
// forward carries nothing of the sender (SI-2); the sender is answered with
// the home's rid and via_hub. Kind 0 and kind 1, with and without the
// sender's hint.
func TestOriginForwardsToOneHome(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	recip := b.agent()
	senderA := a.agent()
	check := func(name string, rec *httptest.ResponseRecorder, wantB int) {
		t.Helper()
		out := decodeSent(t, rec)
		var full RelaySendResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &full)
		if out.Status != RelayQueued || full.ViaHub != b.hubAID || out.RID == "" {
			t.Fatalf("%s: %s", name, rec.Body)
		}
		if b.forwards() != wantB || c.forwards() != 0 {
			t.Fatalf("%s: forwards at the home %d (want %d), at the other peer %d (want 0)", name, b.forwards(), wantB, c.forwards())
		}
	}
	ss := a.openSession(senderA.c)
	check("kind 0, no hint", a.send0(ss, envelope(t, recip.aid, []byte("k0")), kind0Opts{}), 1)
	check("kind 0, hint", a.send0(ss, envelope(t, recip.aid, []byte("k0h")), kind0Opts{home: b.hubAID}), 2)
	env, _ := capEnv(t, b, recip, seal.CapClassContact, time.Hour, "k1")
	check("kind 1, no hint", a.send1Hint(env, "", ""), 3)
	env, _ = capEnv(t, b, recip, seal.CapClassContact, time.Hour, "k1h")
	check("kind 1, hint", a.send1Hint(env, b.hubAID, ""), 4)
	if n := b.queued(recip.aid); n != 4 {
		t.Fatalf("the home queued %d", n)
	}
	if n := a.queued(recip.aid); n != 0 {
		t.Fatalf("the origin queued %d", n)
	}
	// SI-2: no forward names the sender.
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, f := range b.seen {
		if bytes.Contains(f, []byte(senderA.aid)) {
			t.Fatal("a forward carries the sender's AID")
		}
	}
}

// TestUnresolvableHomeForwardsNothing (SSR-H12 step 5): a recipient no peer
// knows is 404 recipient_unknown for a first contact and the one 403 of
// SSR-H3 for a credential, and nothing is forwarded to anyone.
func TestUnresolvableHomeForwardsNothing(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	nowhere := newRelayHub(t)
	ghost := nowhere.agent()
	expectRefusal(t, a.send0To(ghost.aid, "", "k0"), 404, "recipient_unknown")
	expectRefusal(t, a.send0To(ghost.aid, nowhere.hubAID, "k0 hint"), 404, "recipient_unknown")
	g := nowhere.issue(ghost, seal.CapClassContact, time.Hour)
	env := withCap(t, envelope(t, ghost.aid, []byte("k1")), g)
	rec := a.send1Hint(env, "", "")
	expectRefusal(t, rec, 403, "access_invalid")
	local := a.send1(withCap(t, envelope(t, ghost.aid+"z", []byte("k1z")), g), "198.51.100.9")
	if rec.Body.String() != local.Body.String() {
		t.Errorf("an unresolvable owner's refusal %q differs from an unknown local owner's %q", rec.Body, local.Body)
	}
	if b.forwards()+c.forwards() != 0 {
		t.Fatalf("forwards: %d at B, %d at C", b.forwards(), c.forwards())
	}
}

// TestOriginVerifiesKind1BeforeForward (SSR-H14, M23): the origin checks a
// remote owner's credential as far as it can before it forwards: a forged
// signature, a proof by another holder key, a credential for another
// recipient are refused at the origin, with the one 403, and never reach the
// home, whose source bucket stays full.
func TestOriginVerifiesKind1BeforeForward(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	owner, other := b.agent(), b.agent()
	_, wrongKey, _ := ed25519.GenerateKey(nil)
	forged := b.issue(owner, seal.CapClassContact, time.Hour)
	forged.cap = &seal.Cap{Body: forged.cap.Body, Sig: ed25519.Sign(wrongKey, forged.cap.Body)}
	stolen := b.issue(owner, seal.CapClassContact, time.Hour)
	_, stolen.holder, _ = ed25519.GenerateKey(nil)
	moved := b.issue(owner, seal.CapClassContact, time.Hour)
	for i, env := range [][]byte{
		withCap(t, envelope(t, owner.aid, []byte("f")), forged), // a forged signature
		withCap(t, envelope(t, owner.aid, []byte("h")), stolen), // a proof by another holder key
		withCap(t, envelope(t, other.aid, []byte("r")), moved),  // for another recipient
	} {
		expectRefusal(t, a.send1Hint(env, b.hubAID, ""), 403, "access_invalid")
		// A forged signature is refused at step 2, before the body is
		// read, as for an owner registered here.
		if read := a.read.Load(); i == 0 && read != 0 {
			t.Errorf("a forged signature was refused after reading %d bytes of the body", read)
		}
	}
	if b.forwards() != 0 {
		t.Fatalf("%d forged credentials reached the home", b.forwards())
	}
	if got := b.sourceTokens(a); got != rateFedSource.burst {
		t.Fatalf("the home's source bucket for the origin holds %v", got)
	}
}

// TestOriginNegativeCachesRefusedCap (SSR-H14a, M43): once the home refused
// a credential, the origin refuses it itself with the same answer, without
// forwarding it or taking from its bucket, until its cap_exp.
func TestOriginNegativeCachesRefusedCap(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	owner := b.agent()
	g := b.issue(owner, seal.CapClassStranger, 10*time.Minute)
	if _, _, err := b.store.RevokeCaps(owner.aid, [][]byte{g.body.CapID}); err != nil {
		t.Fatal(err)
	}
	send := func(ct string) *httptest.ResponseRecorder {
		return a.send1Hint(withCap(t, envelope(t, owner.aid, []byte(ct)), g), b.hubAID, "")
	}
	first := send("1")
	expectRefusal(t, first, 403, "access_invalid")
	if b.forwards() != 1 {
		t.Fatalf("forwards %d, want 1", b.forwards())
	}
	// The home's 403 is a refused credential at this hub too (SSR-H3b).
	if got := a.srv.relay.addrFailure.tokens(rateKeyOfString(relayClientIP), rateAddrFailure); got != rateAddrFailure.burst-1 {
		t.Errorf("the home's refusal left the address's bucket at %v, want %v", got, rateAddrFailure.burst-1)
	}
	key := capKey(&g.body)
	tokens := a.srv.relay.caps.tokens(key, capRate(&g.body))
	second := send("2")
	expectRefusal(t, second, 403, "access_invalid")
	if second.Body.String() != first.Body.String() {
		t.Errorf("the cached refusal %q differs from the home's %q", second.Body, first.Body)
	}
	if b.forwards() != 1 {
		t.Fatalf("a credential the home refused was forwarded again: %d forwards", b.forwards())
	}
	if got := a.srv.relay.caps.tokens(key, capRate(&g.body)); got != tokens {
		t.Errorf("the cached refusal took from the credential's bucket: %v -> %v", tokens, got)
	}
	// Kept until cap_exp; past it the credential is refused for its
	// expiry, and the entry is dropped.
	// The hubs' clocks stand still from when each was made, so A's is set
	// against the credential's cap_exp, not moved by a fixed amount.
	advanceTo(a, g.body.CapExp-uint64(time.Minute.Milliseconds()))
	expectRefusal(t, send("3"), 403, "access_invalid")
	if b.forwards() != 1 {
		t.Fatalf("the refusal was forgotten before cap_exp: %d forwards", b.forwards())
	}
	advanceTo(a, g.body.CapExp+seal.CapExpGraceMS+1000)
	expectRefusal(t, send("4"), 403, "access_invalid")
	if b.forwards() != 1 {
		t.Fatalf("an expired credential was forwarded: %d forwards", b.forwards())
	}
	if n := a.srv.fedState.neg.len(); n != 0 {
		t.Errorf("%d refused credentials kept after their cap_exp", n)
	}
}

// TestNegativeCacheMissAfterOwnerMoves (SSR-H14a): the refused credentials
// are kept by (home, owner, cap_id), so once the owner lives at another
// hub, a credential its old home refused is asked of the new one.
func TestNegativeCacheMissAfterOwnerMoves(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	owner := b.agent()
	g := b.issue(owner, seal.CapClassContact, time.Hour)
	if _, _, err := b.store.RevokeCaps(owner.aid, [][]byte{g.body.CapID}); err != nil {
		t.Fatal(err)
	}
	send := func(ct, home string) *httptest.ResponseRecorder {
		return a.send1Hint(withCap(t, envelope(t, owner.aid, []byte(ct)), g), home, "")
	}
	expectRefusal(t, send("at B", b.hubAID), 403, "access_invalid")
	expectRefusal(t, send("at B again", b.hubAID), 403, "access_invalid")
	if b.forwards() != 1 {
		t.Fatalf("forwards at B: %d", b.forwards())
	}
	// The owner moves to C with the same mailbox key.
	kel, _ := b.store.AgentKEL(owner.aid)
	if err := c.store.PutAgent(owner.aid, "moved", nil, kel); err != nil {
		t.Fatal(err)
	}
	keyset, _, _, _ := b.store.LocalKeys(owner.aid)
	if _, err := c.store.PublishKeys(owner.aid, keyset, 0, owner.c.KEL(), c.clock()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.store.db.Exec(`DELETE FROM agent WHERE aid=?`, owner.aid); err != nil {
		t.Fatal(err)
	}
	out := decodeSent(t, send("at C", c.hubAID))
	if out.Status != RelayQueued || c.forwards() != 1 || c.queued(owner.aid) != 1 {
		t.Fatalf("after the move: %+v, %d forwards at C", out, c.forwards())
	}
}

// TestForwardAnswerMapping (SSR-H13): every answer of the home maps to one
// answer to the sender: 200 with the home's rid and via_hub; 404
// unknown_destination as recipient_unknown; the refusals of the table with
// their status, reason and Retry-After; anything else, and no answer, as 502
// home_unreachable.
func TestForwardAnswerMapping(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	recip := b.agent()
	rid := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, RIDLen))
	type row struct {
		status     int
		body       string
		retryAfter string
		wire       string
		wantStatus int
		wantReason string
		wantRetry  string
	}
	refusal := func(r wire3.Reason) string {
		b, _ := wire3.Body(wire3.Refusal{Reason: r})
		return string(b)
	}
	rows := []row{
		{200, `{"status":"queued","rid":"` + rid + `","recipient_quiet":true}`, "", "3", 200, "", ""},
		{200, `{"status":"duplicate","rid":"` + rid + `","recipient_quiet":false}`, "", "3", 200, "", ""},
		{404, refusal(wire3.ReasonUnknownDestination), "", "3", 404, "recipient_unknown", ""},
		{409, refusal(wire3.ReasonKidStale), "", "3", 409, "kid_stale", ""},
		{400, refusal(wire3.ReasonBadEnvelope), "", "3", 400, "bad_envelope", ""},
		{400, refusal(wire3.ReasonExpired), "", "3", 400, "expired", ""},
		{400, refusal(wire3.ReasonBadExp), "", "3", 400, "bad_exp", ""},
		{400, refusal(wire3.ReasonBadRequest), "", "3", 400, "bad_request", ""},
		{413, refusal(wire3.ReasonTooLarge), "", "3", 413, "too_large", ""},
		{413, refusal(wire3.ReasonTooLargeForStranger), "", "3", 413, "too_large_for_stranger", ""},
		{429, refusal(wire3.ReasonRateLimited), "7", "3", 429, "rate_limited", "7"},
		{429, refusal(wire3.ReasonStrangersBusy), "8", "3", 429, "strangers_busy", "8"},
		{429, refusal(wire3.ReasonRedeliveryLimited), "9", "3", 429, "redelivery_limited", "9"},
		{507, refusal(wire3.ReasonMailboxFull), "11", "3", 507, "mailbox_full", "11"},
		{403, refusal(wire3.ReasonNotPeer), "", "3", 502, "home_unreachable", "60"},
		// A first contact carries no credential the home could refuse.
		{403, refusal(wire3.ReasonAccessInvalid), "", "3", 502, "home_unreachable", "60"},
		{401, refusal(wire3.ReasonUnauthorized), "", "3", 502, "home_unreachable", "60"},
		{401, refusal(wire3.ReasonReplayed), "", "3", 502, "home_unreachable", "60"},
		{429, refusal(wire3.ReasonSourceRate), "13", "3", 502, "home_unreachable", "13"},
		{500, refusal(wire3.ReasonInternal), "", "3", 502, "home_unreachable", "60"},
		{503, "busy", "", "", 502, "home_unreachable", "60"},
		{200, `{"status":"queued"}`, "", "3", 502, "home_unreachable", "60"},
		{200, `{"status":"queued","rid":"` + rid + `","recipient_quiet":true}`, "", "2", 502, "home_unreachable", "60"},
		{429, refusal(wire3.ReasonKidStale), "", "3", 502, "home_unreachable", "60"},
		// A Retry-After passed on is held between a second and an hour
		// (SSR-H13, 2026-10-09).
		{429, refusal(wire3.ReasonRateLimited), "4294967295", "3", 429, "rate_limited", "3600"},
		{507, refusal(wire3.ReasonMailboxFull), "3601", "3", 507, "mailbox_full", "3600"},
		{429, refusal(wire3.ReasonStrangersBusy), "0", "3", 429, "strangers_busy", "1"},
		{429, refusal(wire3.ReasonSourceRate), "86400", "3", 502, "home_unreachable", "3600"},
		{503, "busy", "0", "", 502, "home_unreachable", "1"},
		// A 413 without a hub's body: the proxy in front of the home took
		// no larger body (SSR-H13, 2026-10-09).
		{413, "<html>413 Request Entity Too Large</html>", "", "", 413, "too_large", ""},
		{413, `{"error":"too big"}`, "", "3", 413, "too_large", ""},
		{413, `{"reason":"payload_too_big","error":"x"}`, "", "", 413, "too_large", ""},
	}
	for i, r := range rows {
		t.Run(fmt.Sprintf("%d %d %s", i, r.status, reasonOfBody(r.body)), func(t *testing.T) {
			b.mu.Lock()
			b.answer = func(w http.ResponseWriter, _ *http.Request) {
				if r.wire != "" {
					w.Header().Set(wire3.Header, r.wire)
				} else {
					w.Header().Del(wire3.Header)
				}
				if r.retryAfter != "" {
					w.Header().Set("Retry-After", r.retryAfter)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(r.status)
				_, _ = io.WriteString(w, r.body)
			}
			b.mu.Unlock()
			resetWire(t, a, b)
			rec := a.send0To(recip.aid, b.hubAID, fmt.Sprint("m", i))
			if rec.Code != r.wantStatus {
				t.Fatalf("answered %d %s, want %d", rec.Code, rec.Body, r.wantStatus)
			}
			if r.wantStatus == 200 {
				var out RelaySendResponse
				if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.RID != rid || out.ViaHub != b.hubAID {
					t.Fatalf("answered %s", rec.Body)
				}
				return
			}
			expectRefusal(t, rec, r.wantStatus, r.wantReason)
			if r.wantRetry != "" && rec.Header().Get("Retry-After") != r.wantRetry {
				t.Errorf("Retry-After %q, want %q", rec.Header().Get("Retry-After"), r.wantRetry)
			}
			if want, _ := wire3.Body(wire3.Refusal{Reason: wire3.Reason(r.wantReason)}); rec.Body.String() != string(want) {
				t.Errorf("the origin passed on the home's body: %s", rec.Body)
			}
		})
	}
	// The home does not answer at all.
	b.mu.Lock()
	b.answer = nil
	b.mu.Unlock()
	resetWire(t, a, b)
	b.down.Store(true)
	expectRefusal(t, a.send0To(recip.aid, b.hubAID, "down"), 502, "home_unreachable")
}

// TestAProxysRefusalDoesNotCutThePeerOff (sealed-sender §8.2 SS-6, core
// CORE-V1): a refusal without X-ANet-Wire comes from a proxy in front of the
// home, such as a 413 for an envelope over the proxy's body limit when the
// home runs a smaller -relay-max-envelope than this hub. The sender is told
// home_unreachable; it is not counted as another wire, and the next send to
// that home goes through: one sender cannot stop this hub's federation with
// a peer.
func TestAProxysRefusalDoesNotCutThePeerOff(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	recip := b.agent()
	var refused atomic.Bool
	b.mu.Lock()
	b.answer = func(w http.ResponseWriter, r *http.Request) {
		if refused.CompareAndSwap(false, true) {
			http.Error(w, "413 Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		b.mu.Lock()
		root := b.root
		b.mu.Unlock()
		root.ServeHTTP(w, r)
	}
	b.mu.Unlock()
	// The envelope does not fit there, and sending it again will not help
	// (SSR-H13, 2026-10-09): 413 too_large, not home_unreachable.
	expectRefusal(t, a.send0To(recip.aid, b.hubAID, "over the proxy's limit"), 413, "too_large")
	if rec := a.send0To(recip.aid, b.hubAID, "within it"); rec.Code != 200 {
		t.Fatalf("a send after the proxy's 413: %d %s", rec.Code, rec.Body)
	}
	if n := a.fed.PeerWireMismatches(); n != 0 {
		t.Errorf("the proxy's 413 was counted as another wire (%d)", n)
	}
	if n := b.queued(recip.aid); n != 1 {
		t.Errorf("the home holds %d envelopes, want the one sent after the proxy's 413", n)
	}
}

// TestTheHomeSaysWhetherTheRecipientIsQuiet (core §2.12.2, SSR-H13): the
// home answers a forward with recipient_quiet as it answers a send of its
// own, and the origin hands it on to the sender.
func TestTheHomeSaysWhetherTheRecipientIsQuiet(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	recip := b.agent()
	if _, err := b.store.db.Exec(`UPDATE agent SET last_seen_at=? WHERE aid=?`,
		time.Now().Add(-30*24*time.Hour).UTC().Format(time.RFC3339Nano), recip.aid); err != nil {
		t.Fatal(err)
	}
	rec := a.send0To(recip.aid, b.hubAID, "to a quiet agent")
	var out RelaySendResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil || !out.RecipientQuiet || out.ViaHub != b.hubAID {
		t.Fatalf("%d %s; want 200, via B, recipient_quiet", rec.Code, rec.Body)
	}
}

// TestAHintedHomeIsTheOnlyPeerAsked (SSR-H12, §4.2.6): for a credential's
// owner whose home only the sender's hint names (no federated card, nothing
// resolved before), the origin asks that one peer for the owner's entry,
// and no other peer learns the bucket.
func TestAHintedHomeIsTheOnlyPeerAsked(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	owner := b.agent()
	env, _ := capEnv(t, b, owner, seal.CapClassContact, time.Hour, "hinted")
	if rec := a.send1Hint(env, b.hubAID, ""); rec.Code != 200 {
		t.Fatalf("a send with the owner's home as the hint: %d %s", rec.Code, rec.Body)
	}
	if n := b.hitsOf("/fed/v3/directory:bucket"); n == 0 {
		t.Fatal("the hinted home was not asked for the owner's entry")
	}
	if n := c.hitsOf("/fed/v3/directory:bucket"); n != 0 {
		t.Fatalf("a peer the hint did not name was asked %d bucket requests", n)
	}
}

func reasonOfBody(b string) string {
	var r struct{ Reason string }
	_ = json.Unmarshal([]byte(b), &r)
	return r.Reason
}

// resetWire gives a a new federation module, so a peer it stopped talking
// to after an answer of another wire is talked to again.
func resetWire(t *testing.T, a, b *fedNode) {
	t.Helper()
	fed, err := federation.New(t.TempDir(), federation.Config{Delivery: "allowlist", Witness: "off",
		Peers: []federation.Peer{{AID: b.hubAID, Endpoint: b.http.URL}}}, a.hubID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fed.Close() })
	a.wire(fed)
}

// TestOwnerResolutionIsMadeAgainForANewerEpoch (§4.2.6, §2.12): the
// origin resolves a remote owner's mailbox key once and uses it for a day;
// a credential under a newer epoch has it resolved again, asking the peers
// rather than their cached answers, at most once a minute for one owner.
func TestOwnerResolutionIsMadeAgainForANewerEpoch(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	owner := b.agent()
	send := func(ct string) *httptest.ResponseRecorder {
		env, _ := capEnv(t, b, owner, seal.CapClassContact, time.Hour, ct)
		return a.send1Hint(env, "", "")
	}
	if rec := send("epoch 1"); rec.Code != 200 {
		t.Fatalf("epoch 1: %d %s", rec.Code, rec.Body)
	}
	buckets := b.hitsOf("/fed/v3/directory:bucket")
	if rec := send("epoch 1 again"); rec.Code != 200 || b.hitsOf("/fed/v3/directory:bucket") != buckets {
		t.Fatalf("a second send asked the peers again: %d, %d bucket requests", rec.Code, b.hitsOf("/fed/v3/directory:bucket")-buckets)
	}
	b.publish(owner, 2)
	if rec := send("epoch 2"); rec.Code != 200 {
		t.Fatalf("a credential under the new epoch: %d %s", rec.Code, rec.Body)
	}
	b.publish(owner, 3)
	expectRefusal(t, send("epoch 3 within the minute"), 403, "access_invalid")
	a.advance(HomeRefreshEvery)
	if rec := send("epoch 3"); rec.Code != 200 {
		t.Fatalf("a credential under epoch 3 a minute later: %d %s", rec.Code, rec.Body)
	}
}

// TestFedBucketMergeAndPartial (SSR-W19, SSR-W21): a hub answers a bucket
// with its own entries and each delivery peer's for the same bucket, asked at
// no more bits than the peer serves; an answer of a peer is used for ten
// minutes; a peer that does not answer, and whose answer is not cached,
// makes the bucket partial.
func TestFedBucketMergeAndPartial(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	var aids []string
	for _, nd := range []*fedNode{a, b, b, c} {
		aids = append(aids, nd.agent().aid)
	}
	query := func() DirBucketResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://hub.test/directory:bucket", strings.NewReader(`{"prefix":"","bits":0}`))
		req.Header.Set(wire3.Header, "3")
		req.Header.Set("Content-Type", "application/json")
		rec := a.serve(req, "192.0.2.77")
		var out DirBucketResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("POST /directory:bucket: %d %s", rec.Code, rec.Body)
		}
		return out
	}
	hashes := func(out DirBucketResponse) map[string]bool {
		m := map[string]bool{}
		for _, e := range out.Entries {
			m[e.H] = true
		}
		return m
	}
	want := func(out DirBucketResponse, n int, partial bool) {
		t.Helper()
		if len(out.Entries) != n || out.Partial != partial {
			t.Fatalf("%d entries, partial %v; want %d, %v", len(out.Entries), out.Partial, n, partial)
		}
	}
	out := query()
	want(out, 4, false)
	for _, aid := range aids {
		h, _ := dirbox.Hash(aid)
		if !hashes(out)[base64.RawURLEncoding.EncodeToString(h)] {
			t.Errorf("the merged bucket has no entry for %s", aid)
		}
	}
	// In hash order.
	for i := 1; i < len(out.Entries); i++ {
		if out.Entries[i-1].H > out.Entries[i].H && len(out.Entries[i-1].H) == len(out.Entries[i].H) {
			x, _ := base64.RawURLEncoding.DecodeString(out.Entries[i-1].H)
			y, _ := base64.RawURLEncoding.DecodeString(out.Entries[i].H)
			if bytes.Compare(x, y) > 0 {
				t.Fatal("the merged bucket is not in hash order")
			}
		}
	}
	// C goes down: its answer is cached for ten minutes.
	c.down.Store(true)
	want(query(), 4, false)
	a.advance(BucketCacheTTL)
	want(query(), 3, true)
	c.down.Store(false)
	want(query(), 4, false)
	// A peer's own entries only: C's bucket at /fed/v3/directory:bucket
	// does not carry what it learned from anyone.
	body := []byte(`{"prefix":"","bits":0}`)
	req := httptest.NewRequest(http.MethodPost, "http://hub.test/fed/v3/directory:bucket", bytes.NewReader(body))
	req.Header.Set(wire3.Header, "3")
	req.Header.Set("Content-Type", "application/json")
	ts := relaySignTS()
	sig, seq := a.hubID.Ctrl.Sign(relayauth.PreimageV2(relayauth.ActionFedBucket, a.hubAID, c.hubAID, ts, req.Method, req.URL.RequestURI(), body))
	req.Header.Set(relayauth.HeaderAID, a.hubAID)
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	rec := c.fedServe(req)
	var fb map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &fb) != nil {
		t.Fatalf("C's /fed/v3/directory:bucket: %d %s", rec.Code, rec.Body)
	}
	if _, has := fb["partial"]; has || len(fb["entries"].([]any)) != 1 {
		t.Fatalf("C's own bucket: %s", rec.Body)
	}
}

// TestKind1RemoteStep2ConstantVerifyCount (SSR-H3, SSR-H3a, M45 for a
// remote owner): every refusal of step 2 for an owner registered at a peer —
// an owner no peer knows, a credential its home refused before, an older
// epoch, a forged signature, an expiry — is the one 403 of SSR-H3, made
// before the body is read, at the cost of exactly one Ed25519 verification;
// each debits the client address's bucket of refusals (SSR-H3b).
func TestKind1RemoteStep2ConstantVerifyCount(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	owner := b.agent()
	nowhere := newRelayHub(t)
	ghost := nowhere.agent()
	_, wrongKey, _ := ed25519.GenerateKey(nil)
	// The owner's home and key are resolved, and one credential refused by
	// the home, before counting.
	refused := b.issue(owner, seal.CapClassContact, time.Hour)
	if _, _, err := b.store.RevokeCaps(owner.aid, [][]byte{refused.body.CapID}); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, a.send1Hint(withCap(t, envelope(t, owner.aid, []byte("seed")), refused), b.hubAID, ""), 403, "access_invalid")
	old := b.issue(owner, seal.CapClassContact, time.Hour)
	b.publish(owner, 2)
	if rec := a.send1Hint(withCap(t, envelope(t, owner.aid, []byte("epoch 2")), b.issue(owner, seal.CapClassContact, time.Hour)), b.hubAID, ""); rec.Code != 200 {
		t.Fatalf("a credential under epoch 2: %d %s", rec.Code, rec.Body)
	}
	forged := b.issue(owner, seal.CapClassContact, time.Hour)
	forged.cap = &seal.Cap{Body: forged.cap.Body, Sig: ed25519.Sign(wrongKey, forged.cap.Body)}
	expiring := b.issue(owner, seal.CapClassContact, time.Second)
	refusals := map[string][]byte{
		"an owner no peer knows":        withCap(t, envelope(t, ghost.aid, []byte("g")), nowhere.issue(ghost, seal.CapClassContact, time.Hour)),
		"a credential the home refused": withCap(t, envelope(t, owner.aid, []byte("r")), refused),
		"an older epoch":                withCap(t, envelope(t, owner.aid, []byte("o")), old),
		"a forged signature":            withCap(t, envelope(t, owner.aid, []byte("f")), forged),
	}
	var n int
	verifyEd25519 = func(pub ed25519.PublicKey, msg, sig []byte) bool {
		n++
		return ed25519.Verify(pub, msg, sig)
	}
	defer func() { verifyEd25519 = ed25519.Verify }()
	var body string
	i := 0
	check := func(name string, env []byte) {
		t.Helper()
		i++
		ip := "203.0.113." + strconv.Itoa(200+i)
		n = 0
		rec := a.send1Hint(env, b.hubAID, ip)
		expectRefusal(t, rec, 403, "access_invalid")
		if body == "" {
			body = rec.Body.String()
		} else if rec.Body.String() != body {
			t.Errorf("%s: answered %q, the others %q", name, rec.Body, body)
		}
		if n != 1 {
			t.Errorf("%s: step 2 made %d Ed25519 verifications, want exactly 1", name, n)
		}
		if read := a.read.Load(); read != 0 {
			t.Errorf("%s: refused after reading %d bytes of the body", name, read)
		}
		if got := a.srv.relay.addrFailure.tokens(rateKeyOfString(ip), rateAddrFailure); got != rateAddrFailure.burst-1 {
			t.Errorf("%s: the address's bucket holds %v, want %v", name, got, rateAddrFailure.burst-1)
		}
	}
	for name, env := range refusals {
		check(name, env)
	}
	forwards := b.forwards()
	advanceTo(a, expiring.body.CapExp+seal.CapExpGraceMS+1000)
	check("an expiry", withCap(t, envelope(t, owner.aid, []byte("x")), expiring))
	if b.forwards() != forwards {
		t.Fatalf("a refusal of step 2 was forwarded")
	}
}

// TestEntryHomeIsTheServingPeer (SSR-W20, SSR-W22): a peer answers for its
// own agents only, so an entry it serves names it as the home; one that
// names another hub, or that does not open under the AID looked for, is
// not taken.
func TestEntryHomeIsTheServingPeer(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	owner, other := b.agent(), b.agent()
	h, err := dirbox.Hash(owner.aid)
	if err != nil {
		t.Fatal(err)
	}
	entries, _, err := b.store.DirBucket(h, dirbox.HashBits, nil)
	if err != nil || len(entries) != 1 {
		t.Fatalf("B's entry for the owner: %v %v", entries, err)
	}
	pe := peerEntry{h: mustB64(t, entries[0].H), box: mustB64(t, entries[0].Box)}
	if e, ok := a.srv.verifyEntry(owner.aid, b.hubAID, pe, a.clock()); !ok || e.home != b.hubAID || e.mbox.Epoch != owner.mbox.Epoch {
		t.Fatalf("B's entry, served by B: %+v %v", e, ok)
	}
	if _, ok := a.srv.verifyEntry(owner.aid, c.hubAID, pe, a.clock()); ok {
		t.Fatal("B's entry, served by C, was taken")
	}
	if _, ok := a.srv.verifyEntry(other.aid, b.hubAID, pe, a.clock()); ok {
		t.Fatal("an entry was taken for an AID it is not filed under")
	}
}

// TestForkedEntriesResolveNothing (SSR-W22): two peers serve entries of
// one AID whose key histories fork (neither extends the other): the home
// is not resolved and nothing is forwarded; the sender's hint still names
// one.
func TestForkedEntriesResolveNothing(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	c0, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := c0.Export()
	if err != nil {
		t.Fatal(err)
	}
	fork, err := identity.Restore(snap)
	if err != nil {
		t.Fatal(err)
	}
	rotAt := uint64(time.Now().Add(-time.Minute).UnixMilli())
	if err := identitytest.Rotate(c0, rotAt); err != nil {
		t.Fatal(err)
	}
	if err := identitytest.Rotate(fork, rotAt+7); err != nil {
		t.Fatal(err)
	}
	for _, at := range []struct {
		hub *fedNode
		c   *identity.Controller
	}{{b, c0}, {c, fork}} {
		kel, err := identity.MarshalKEL(at.c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		if err := at.hub.store.PutAgent(at.c.AID(), "forked", nil, kel); err != nil {
			t.Fatal(err)
		}
		at.hub.publish(&relayAgent{c: at.c, aid: at.c.AID()}, 1)
	}
	sealToKeysAt(t, b.store, c0.AID()) // what is sent goes to B's agent
	expectRefusal(t, a.send0To(c0.AID(), "", "fork"), 404, "recipient_unknown")
	if b.forwards()+c.forwards() != 0 {
		t.Fatalf("a forked recipient was forwarded to: %d at B, %d at C", b.forwards(), c.forwards())
	}
	if rec := a.send0To(c0.AID(), b.hubAID, "hinted"); rec.Code != 200 {
		t.Fatalf("with the hint: %d %s", rec.Code, rec.Body)
	}
}

// TestPeerRC1KeepsFourThousandTimes (core G17): RC1 keeps the last 4096
// times of a peer hub, not the 64 of an agent: a peer's requests may
// arrive out of order by more than an agent's.
func TestPeerRC1KeepsFourThousandTimes(t *testing.T) {
	h := newRelayHub(t)
	const peer = "did:anet:peer-hub"
	t0 := uint64(time.Now().UnixMilli())
	for i := uint64(1); i <= 100; i++ {
		rec := httptest.NewRecorder()
		if !h.srv.PeerRC1(rec, peer, t0+i) {
			t.Fatalf("time %d: %s", i, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	if !h.srv.PeerRC1(rec, peer, t0) {
		t.Fatalf("a time 100 behind the latest, within the window: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	if h.srv.PeerRC1(rec, peer, t0+5) || reasonOf(rec) != "replayed" {
		t.Fatalf("a time taken before: %d %s", rec.Code, rec.Body)
	}
}

// TestOwnerResolutionIsMadeAgainAfterABadSignature (§2.12): a credential
// that does not verify under the mailbox key held for its remote owner is
// refused, and has the owner's resolution made again at its next use (at
// most once a minute), so a key held in error does not outlive the minute.
func TestOwnerResolutionIsMadeAgainAfterABadSignature(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	owner := b.agent()
	send := func(ct string) *httptest.ResponseRecorder {
		env, _ := capEnv(t, b, owner, seal.CapClassContact, time.Hour, ct)
		return a.send1Hint(env, "", "")
	}
	if rec := send("resolved"); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// The key held goes wrong (same epoch, another key).
	wrong, _, _ := ed25519.GenerateKey(nil)
	held, ok := a.srv.fedState.home(owner.aid, a.clock())
	if !ok {
		t.Fatal("nothing held for the owner")
	}
	held.mbox = seal.Mbox{Epoch: held.mbox.Epoch, Pub: wrong}
	a.srv.fedState.putHome(owner.aid, held)
	a.advance(HomeRefreshEvery)
	expectRefusal(t, send("under the wrong key"), 403, "access_invalid")
	if rec := send("made again"); rec.Code != 200 {
		t.Fatalf("after the refusal: %d %s, want the owner's key resolved again", rec.Code, rec.Body)
	}
}

// TestAMovedOwnerIsFoundAgainAfterARefusal (SSR-H14a 2): when the home
// held for a remote owner refuses a credential, the owner's resolution is
// made again at its next use: an owner that moved to another hub is found
// there, and the sends that follow reach it.
func TestAMovedOwnerIsFoundAgainAfterARefusal(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	owner := b.agent()
	send := func(ct string) *httptest.ResponseRecorder {
		env, _ := capEnv(t, b, owner, seal.CapClassContact, time.Hour, ct)
		return a.send1Hint(env, "", "")
	}
	if rec := send("at B"); rec.Code != 200 || b.forwards() != 1 {
		t.Fatalf("at B: %d %s", rec.Code, rec.Body)
	}
	// The owner moves to C with the same mailbox key.
	kel, _ := b.store.AgentKEL(owner.aid)
	if err := c.store.PutAgent(owner.aid, "moved", nil, kel); err != nil {
		t.Fatal(err)
	}
	keyset, _, _, _ := b.store.LocalKeys(owner.aid)
	if _, err := c.store.PublishKeys(owner.aid, keyset, 0, owner.c.KEL(), c.clock()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.store.db.Exec(`DELETE FROM agent WHERE aid=?`, owner.aid); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, send("to B, which no longer has it"), 403, "access_invalid")
	if b.forwards() != 2 {
		t.Fatalf("forwards at B: %d", b.forwards())
	}
	if rec := send("found at C"); rec.Code != 200 || c.forwards() != 1 || b.forwards() != 2 {
		t.Fatalf("after the refusal: %d %s; forwards at B %d, at C %d", rec.Code, rec.Body, b.forwards(), c.forwards())
	}
}

// TestAPeersEndlessBucketIsNoAnswer (SSR-W21): a peer whose bucket does not
// move on from one page to the next, or goes on for more than
// PeerBucketMaxPages pages, is taken as not answering: the merged bucket
// is partial, and the asking ends.
func TestAPeersEndlessBucketIsNoAnswer(t *testing.T) {
	for _, moving := range []bool{false, true} {
		t.Run(fmt.Sprint("moving ", moving), func(t *testing.T) {
			net := newFedNet(t, 2)
			a, c := net.nodes[0], net.nodes[1]
			a.agent()
			var n atomic.Int64
			c.mu.Lock()
			c.bucket = func(w http.ResponseWriter, _ *http.Request) {
				i := n.Add(1)
				h := make([]byte, dirbox.HashLen)
				if moving {
					h[30], h[31] = byte(i>>8), byte(i)
				}
				e := base64.RawURLEncoding.EncodeToString(h)
				w.Header().Set(wire3.Header, "3")
				writeJSON(w, http.StatusOK, map[string]any{"max_bits": 0, "next": e,
					"entries": []map[string]string{{"h": e, "box": "AAAA"}}})
			}
			c.mu.Unlock()
			req := httptest.NewRequest(http.MethodPost, "http://hub.test/directory:bucket", strings.NewReader(`{"prefix":"","bits":0}`))
			req.Header.Set(wire3.Header, "3")
			req.Header.Set("Content-Type", "application/json")
			rec := a.serve(req, "192.0.2.78")
			var out DirBucketResponse
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil || !out.Partial || len(out.Entries) != 1 {
				t.Fatalf("%d %s; want A's own entry and partial", rec.Code, rec.Body)
			}
			want := int64(2)
			if moving {
				want = PeerBucketMaxPages
			}
			if got := n.Load(); got != want {
				t.Fatalf("the peer was asked %d pages, want %d", got, want)
			}
		})
	}
}

// advanceTo moves nd's clock forward to the unix-ms time at (not back).
func advanceTo(nd *fedNode, at uint64) {
	if now := nd.nowMS(); at > now {
		nd.advance(time.Duration(at-now) * time.Millisecond)
	}
}
