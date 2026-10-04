package aghub

// /relay/send v3, step by step (sealed-sender §4.2.1, SSR-H2): each step
// refuses with its own code, and a refusal takes no token and writes no row.
// The one exception is the address bucket of step 1a: a 403 access_invalid
// debits it by one, after the answer (SSR-H3b). TestRelaySendOrder_Step<n>
// has one case per failure code of step n, each on a new hub.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

// relayScene is a hub with a sender (with a session), a recipient and the
// two credentials the recipient issued to the sender.
type relayScene struct {
	h        *relayHub
	sender   *relayAgent
	recip    *relayAgent
	ss       session
	contact  grant
	stranger grant
	counter  int
}

func newScene(t testing.TB) *relayScene {
	h := newRelayHub(t)
	sc := &relayScene{h: h, sender: h.agent(), recip: h.agent()}
	sc.ss = h.openSession(sc.sender.c)
	sc.contact = h.issue(sc.recip, seal.CapClassContact, 7*24*time.Hour)
	sc.stranger = h.issue(sc.recip, seal.CapClassStranger, 7*24*time.Hour)
	return sc
}

// env is a new envelope for the recipient, different every call.
func (sc *relayScene) env() []byte {
	sc.counter++
	return envelope(sc.h.t, sc.recip.aid, []byte("message "+strconv.Itoa(sc.counter)))
}

// send0 is a first contact of a new envelope, the request changed by edit
// after it was MACed.
func (sc *relayScene) send0(edit func(*http.Request)) *httptest.ResponseRecorder {
	return sc.h.send0(sc.ss, sc.env(), kind0Opts{edit: edit})
}

// send1 is a send of env under g.
func (sc *relayScene) send1(env []byte, g grant) *httptest.ResponseRecorder {
	return sc.h.send1(withCap(sc.h.t, env, g), "")
}

// send1Edited is a send of a new envelope under the contact credential, the
// request changed by edit.
func (sc *relayScene) send1Edited(edit func(*http.Request)) *httptest.ResponseRecorder {
	req := kind1Request(sc.h.t, withCap(sc.h.t, sc.env(), sc.contact))
	edit(req)
	return sc.h.serve(req, relayClientIP)
}

// stepCase is one refusal of one step.
type stepCase struct {
	name   string
	status int
	reason string
	// setup readies the scene before what the refusal may change is noted.
	setup func(sc *relayScene)
	send  func(sc *relayScene) *httptest.ResponseRecorder
	// debit: a 403 that debits the address bucket by one (SSR-H3b).
	debit bool
}

// runSteps runs each case on a new scene: the refusal, the wire-3 contract
// of its answer, and that nothing was taken or written.
func runSteps(t *testing.T, cases []stepCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := newScene(t)
			if c.setup != nil {
				c.setup(sc)
			}
			before := sc.h.effects()
			rec := c.send(sc)
			if rec.Code != c.status || reasonOf(rec) != c.reason {
				t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body, c.status, c.reason)
			}
			for _, p := range wire3test.Contract(rec.Code, rec.Header(), rec.Body.Bytes()) {
				t.Error(p)
			}
			if c.debit {
				k := "addr|" + rateKeyOfString(relayClientIP)
				was, ok := before.buckets[k]
				if !ok {
					was = rateAddrFailure.burst
				}
				before.buckets[k] = was - 1
			}
			if d := before.diff(sc.h.effects()); d != "" {
				t.Errorf("the refusal took or wrote something: %s", d)
			}
		})
	}
}

// rateKeyOfString is the clientIP key of an address behind the proxy.
func rateKeyOfString(ip string) string {
	req := httptest.NewRequest(http.MethodGet, "http://hub.test/", nil)
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set("X-Real-IP", ip)
	return clientIP(req)
}

// drain takes every token of key's bucket in set at rate r.
func drain(set *bucketSet, key string, r relayRate) {
	for {
		if ok, _ := set.take(key, r); !ok {
			return
		}
	}
}

var b64u = base64.RawURLEncoding.EncodeToString

func TestRelaySendOrder_Step0(t *testing.T) {
	runSteps(t, []stepCase{
		{name: "no wire header", status: 426, reason: "wire_too_old", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Del(wireVersionHeader) })
		}},
		{name: "wire 2", status: 426, reason: "wire_too_old", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set(wireVersionHeader, "2") })
		}},
		{name: "wire 4", status: 400, reason: "wire_too_new", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set(wireVersionHeader, "4") })
		}},
	})
}

func TestRelaySendOrder_Step1(t *testing.T) {
	setAccess := func(raw []byte) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set(HeaderAccess, b64u(raw)) }
	}
	cbor := func(v any) []byte {
		b, err := coredet.Marshal(v)
		if err != nil {
			panic(err)
		}
		return b
	}
	sig := bytes.Repeat([]byte{1}, 64)
	runSteps(t, []stepCase{
		{name: "a JSON content type", status: 400, reason: "bad_request", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set("Content-Type", "application/json") })
		}},
		{name: "no content type", status: 400, reason: "bad_request", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Del("Content-Type") })
		}},
		{name: "a content type with a parameter", status: 400, reason: "bad_request", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set("Content-Type", EnvelopeContentType+"; charset=utf-8") })
		}},
		{name: "X-ANet-AID on a first contact", status: 400, reason: "identity_headers_not_allowed", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set(relayauth.HeaderAID, sc.sender.aid) })
		}},
		{name: "X-ANet-Seq on a first contact", status: 400, reason: "identity_headers_not_allowed", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set(relayauth.HeaderSeq, "0") })
		}},
		{name: "X-ANet-AID under a credential", status: 400, reason: "identity_headers_not_allowed", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send1Edited(func(r *http.Request) { r.Header.Set(relayauth.HeaderAID, sc.sender.aid) })
		}},
		{name: "an empty X-ANet-Sig under a credential", status: 400, reason: "identity_headers_not_allowed", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send1Edited(func(r *http.Request) { r.Header.Set(relayauth.HeaderSig, "") })
		}},
		{name: "no X-ANet-Access", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Del(HeaderAccess) })
		}},
		{name: "X-ANet-Access twice", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Add(HeaderAccess, r.Header.Get(HeaderAccess)) })
		}},
		{name: "X-ANet-Access over 1 KiB", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send1Edited(func(r *http.Request) { r.Header.Set(HeaderAccess, strings.Repeat("A", MaxAccessHeader+1)) })
		}},
		{name: "X-ANet-Access padded", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set(HeaderAccess, "oQEA=") })
		}},
		{name: "X-ANet-Access in standard base64", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send1Edited(func(r *http.Request) {
				h := r.Header.Get(HeaderAccess)
				h = strings.NewReplacer("-", "+", "_", "/").Replace(h)
				if !strings.ContainsAny(h, "+/") {
					h = "+" + h[1:]
				}
				r.Header.Set(HeaderAccess, h)
			})
		}},
		{name: "an access of kind 2", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(setAccess(cbor(map[uint64]any{1: uint64(2)})))
		}},
		{name: "a kind-0 access with a proof", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(setAccess(cbor(map[uint64]any{1: uint64(0), 3: sig})))
		}},
		{name: "a kind-1 access without a proof", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send1Edited(setAccess(cbor(map[uint64]any{1: uint64(1), 2: map[uint64]any{1: []byte("b"), 2: sig}})))
		}},
		{name: "a kind-1 access with a short proof", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send1Edited(setAccess(cbor(map[uint64]any{1: uint64(1), 2: map[uint64]any{1: []byte("b"), 2: sig}, 3: sig[:63]})))
		}},
		{name: "an access with an unknown key", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(setAccess(cbor(map[uint64]any{1: uint64(0), 4: uint64(1)})))
		}},
		{name: "an access that is not CoreDet", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(setAccess([]byte{0xa1, 0x01, 0x18, 0x00}))
		}},
		{name: "an access that is CBOR null", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(setAccess([]byte{0xf6}))
		}},
		{name: "X-ANet-Session under a credential", status: 400, reason: "bad_request", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send1Edited(func(r *http.Request) { r.Header.Set(relayauth.HeaderSession, relayauth.EncodeSessionID(sc.ss.sid)) })
		}},
		{name: "X-ANet-MAC under a credential", status: 400, reason: "bad_request", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send1Edited(func(r *http.Request) { r.Header.Set(relayauth.HeaderMAC, relayauth.EncodeMAC(make([]byte, 32))) })
		}},
		{name: "a first contact without X-ANet-Session", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Del(relayauth.HeaderSession) })
		}},
		{name: "a first contact without X-ANet-MAC", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Del(relayauth.HeaderMAC) })
		}},
		{name: "a first contact without X-ANet-TS", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Del(relayauth.HeaderTS) })
		}},
		{name: "a session id of 15 bytes", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set(relayauth.HeaderSession, b64u(make([]byte, 15))) })
		}},
		{name: "a MAC in padded base64", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set(relayauth.HeaderMAC, r.Header.Get(relayauth.HeaderMAC)+"=") })
		}},
		{name: "a non-canonical X-ANet-TS", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set(relayauth.HeaderTS, "0"+r.Header.Get(relayauth.HeaderTS)) })
		}},
		{name: "X-ANet-Home not an AID", status: 400, reason: "bad_request", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set(relayauth.HeaderHome, "hub.example") })
		}},
		{name: "X-ANet-Home twice", status: 400, reason: "bad_request", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) {
				r.Header.Add(relayauth.HeaderHome, sc.h.hubAID)
				r.Header.Add(relayauth.HeaderHome, sc.h.hubAID)
			})
		}},
	})
}

func TestRelaySendOrder_Step1a(t *testing.T) {
	runSteps(t, []stepCase{
		{name: "a credential from an address whose refusals ran out", status: 429, reason: "rate_limited",
			setup: func(sc *relayScene) {
				drain(sc.h.srv.relay.addrFailure, rateKeyOfString(relayClientIP), rateAddrFailure)
			},
			send: func(sc *relayScene) *httptest.ResponseRecorder { return sc.send1(sc.env(), sc.contact) }},
	})
}

func TestRelaySendOrder_Step2(t *testing.T) {
	// A capability over body, signed by key.
	signedBody := func(sc *relayScene, mut func(b map[uint64]any), key ed25519.PrivateKey) grant {
		hp, _, _ := ed25519.GenerateKey(nil)
		b := map[uint64]any{0: seal.CapType, 1: sc.recip.aid, 2: sc.recip.mbox.Epoch, 3: bytes.Repeat([]byte{3}, 16),
			4: seal.CapClassContact, 5: uint64(sc.h.clock().Add(time.Hour).UnixMilli()), 6: []byte(hp)}
		mut(b)
		raw, err := coredet.Marshal(b)
		if err != nil {
			panic(err)
		}
		return rawGrant(raw, key)
	}
	refused := func(name string, setup func(sc *relayScene), g func(sc *relayScene) grant) stepCase {
		return stepCase{name: name, status: 403, reason: "access_invalid", debit: true, setup: setup,
			send: func(sc *relayScene) *httptest.ResponseRecorder { return sc.send1(sc.env(), g(sc)) }}
	}
	var bareOwner *relayAgent
	ts := func(sc *relayScene, d time.Duration) *uint64 {
		v := uint64(sc.h.clock().Add(d).UnixMilli())
		return &v
	}
	runSteps(t, []stepCase{
		{name: "an unknown session", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.h.send0(session{sid: bytes.Repeat([]byte{5}, 16), key: bytes.Repeat([]byte{6}, 32)}, sc.env(), kind0Opts{})
		}},
		{name: "a session that ended", status: 401, reason: "session_invalid",
			setup: func(sc *relayScene) { sc.h.advance(SessionLifetime) },
			send:  func(sc *relayScene) *httptest.ResponseRecorder { return sc.send0(nil) }},
		{name: "X-ANet-TS 6 minutes old", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.h.send0(sc.ss, sc.env(), kind0Opts{ts: ts(sc, -6*time.Minute)})
		}},
		{name: "X-ANet-TS 6 minutes ahead", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.h.send0(sc.ss, sc.env(), kind0Opts{ts: ts(sc, 6*time.Minute)})
		}},
		{name: "the session's send bucket is empty", status: 429, reason: "rate_limited",
			setup: func(sc *relayScene) { drain(sc.h.srv.relay.sessionSend, sc.sender.aid, rateSessionSend) },
			send:  func(sc *relayScene) *httptest.ResponseRecorder { return sc.send0(nil) }},
		refused("a capability body that does not decode", nil, func(sc *relayScene) grant {
			return rawGrant([]byte{0xa1, 0x00, 0x00}, sc.recip.mboxPriv)
		}),
		refused("a capability with another type tag", nil, func(sc *relayScene) grant {
			return signedBody(sc, func(b map[uint64]any) { b[0] = "anet.cap/2" }, sc.recip.mboxPriv)
		}),
		refused("a capability of class 3", nil, func(sc *relayScene) grant {
			return signedBody(sc, func(b map[uint64]any) { b[4] = uint64(3) }, sc.recip.mboxPriv)
		}),
		refused("an owner this hub does not know", nil, func(sc *relayScene) grant {
			c, _ := identitytest.Hub()
			return signedBody(sc, func(b map[uint64]any) { b[1] = c.AID() }, sc.recip.mboxPriv)
		}),
		refused("an owner without a mailbox key", func(sc *relayScene) { bareOwner = sc.h.bareAgent() }, func(sc *relayScene) grant {
			return signedBody(sc, func(b map[uint64]any) { b[1] = bareOwner.aid }, sc.recip.mboxPriv)
		}),
		refused("an epoch the owner has left", func(sc *relayScene) { sc.h.publish(sc.recip, 2) }, func(sc *relayScene) grant {
			return sc.contact
		}),
		refused("a signature by another key", nil, func(sc *relayScene) grant {
			_, other, _ := ed25519.GenerateKey(nil)
			return signedBody(sc, func(map[uint64]any) {}, other)
		}),
		refused("a capability that expired", nil, func(sc *relayScene) grant {
			return sc.h.issue(sc.recip, seal.CapClassContact, -6*time.Minute)
		}),
		refused("a capability expiring past 31 days", nil, func(sc *relayScene) grant {
			return signedBody(sc, func(b map[uint64]any) {
				b[5] = uint64(sc.h.clock().Add(31*24*time.Hour + time.Minute).UnixMilli())
			}, sc.recip.mboxPriv)
		}),
		refused("a revoked capability", func(sc *relayScene) {
			if _, _, err := sc.h.store.RevokeCaps(sc.recip.aid, [][]byte{sc.contact.body.CapID}); err != nil {
				sc.h.t.Fatal(err)
			}
		}, func(sc *relayScene) grant { return sc.contact }),
		{name: "the capability's bucket is empty", status: 429, reason: "rate_limited",
			setup: func(sc *relayScene) {
				drain(sc.h.srv.relay.caps, capKey(&sc.stranger.body), rateStrangerCap)
			},
			send: func(sc *relayScene) *httptest.ResponseRecorder { return sc.send1(sc.env(), sc.stranger) }},
	})
}

func TestRelaySendOrder_Step3(t *testing.T) {
	small := func(sc *relayScene) {
		l := DefaultLimits()
		l.MaxEnvelope = 512
		if err := sc.h.srv.SetLimits(l); err != nil {
			sc.h.t.Fatal(err)
		}
	}
	big := func(sc *relayScene) []byte { return envelope(sc.h.t, sc.recip.aid, bytes.Repeat([]byte("x"), 600)) }
	runSteps(t, []stepCase{
		{name: "a first contact over MaxEnvelope", status: 413, reason: "too_large", setup: small,
			send: func(sc *relayScene) *httptest.ResponseRecorder { return sc.h.send0(sc.ss, big(sc), kind0Opts{}) }},
		{name: "a send under a credential over MaxEnvelope", status: 413, reason: "too_large", setup: small,
			send: func(sc *relayScene) *httptest.ResponseRecorder { return sc.send1(big(sc), sc.contact) }},
	})
}

func TestRelaySendOrder_Step4(t *testing.T) {
	outer := func(sc *relayScene, mut func(m map[uint64]any)) []byte {
		m := map[uint64]any{1: uint64(2), 2: sc.recip.aid, 3: uint64(1), 4: bytes.Repeat([]byte{7}, 16),
			5: bytes.Repeat([]byte{9}, 32), 6: []byte("ct"), 7: map[uint64]any{1: uint64(0)}}
		mut(m)
		b, err := coredet.Marshal(m)
		if err != nil {
			panic(err)
		}
		return b
	}
	runSteps(t, []stepCase{
		{name: "a body that is no envelope", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.h.send0(sc.ss, []byte("a plaintext task"), kind0Opts{})
		}},
		{name: "an envelope of version 1", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.h.send0(sc.ss, outer(sc, func(m map[uint64]any) { m[1] = uint64(1) }), kind0Opts{})
		}},
		{name: "an unknown critical outer key", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.h.send0(sc.ss, outer(sc, func(m map[uint64]any) { m[9] = uint64(1) }), kind0Opts{})
		}},
		{name: "a first contact whose outer key 7 is a credential", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			env := withCap(sc.h.t, sc.env(), sc.contact)
			return sc.h.send0(sc.ss, env, kind0Opts{edit: func(r *http.Request) {
				r.Header.Set(HeaderAccess, b64u([]byte{0xa1, 0x01, 0x00}))
			}})
		}},
		{name: "a credential whose outer key 7 is a first contact", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			hdr := kind1Request(sc.h.t, withCap(sc.h.t, sc.env(), sc.contact)).Header.Get(HeaderAccess)
			req := kind1Request(sc.h.t, sc.env())
			req.Header.Set(HeaderAccess, hdr)
			return sc.h.serve(req, relayClientIP)
		}},
		{name: "outer key 7 spelled otherwise than the header", status: 400, reason: "bad_envelope", send: func(sc *relayScene) *httptest.ResponseRecorder {
			// The same access, its kind written in two bytes: not CoreDet,
			// so not the bytes of the header.
			env := outer(sc, func(m map[uint64]any) { m[7] = map[uint64]any{1: uint64(0)} })
			env = bytes.Replace(env, []byte{0x07, 0xa1, 0x01, 0x00}, []byte{0x07, 0xa1, 0x01, 0x18, 0x00}, 1)
			return sc.h.send0(sc.ss, env, kind0Opts{edit: func(r *http.Request) {
				r.Header.Set(HeaderAccess, b64u([]byte{0xa1, 0x01, 0x00}))
			}})
		}},
		{name: "a recipient AID holding U+0000", status: 400, reason: "bad_request", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.h.send0(sc.ss, outer(sc, func(m map[uint64]any) { m[2] = sc.recip.aid + "\x00x" }), kind0Opts{})
		}},
	})
}

func TestRelaySendOrder_Step5(t *testing.T) {
	runSteps(t, []stepCase{
		{name: "a MAC over another body", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.h.send0(sc.ss, sc.env(), kind0Opts{macBody: []byte("another body")})
		}},
		{name: "X-ANet-Home added after the MAC", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.Header.Set(relayauth.HeaderHome, sc.h.hubAID) })
		}},
		{name: "a MAC for another path", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.send0(func(r *http.Request) { r.URL.RawQuery = "x=1"; r.RequestURI = "/relay/send?x=1" })
		}},
		{name: "a MAC under another session's key", status: 401, reason: "session_invalid", send: func(sc *relayScene) *httptest.ResponseRecorder {
			return sc.h.send0(session{sid: sc.ss.sid, key: bytes.Repeat([]byte{8}, 32)}, sc.env(), kind0Opts{})
		}},
		{name: "a proof over another envelope", status: 403, reason: "access_invalid", debit: true,
			send: func(sc *relayScene) *httptest.ResponseRecorder {
				hdr := kind1Request(sc.h.t, withCap(sc.h.t, sc.env(), sc.contact)).Header.Get(HeaderAccess)
				raw, _ := base64.RawURLEncoding.DecodeString(hdr)
				a, err := decodeAccessHeader(raw)
				if err != nil {
					sc.h.t.Fatal(err)
				}
				other, err := seal.SetAccess(sc.env(), a)
				if err != nil {
					sc.h.t.Fatal(err)
				}
				return sc.h.send1(other, "")
			}},
		{name: "a proof by another holder key", status: 403, reason: "access_invalid", debit: true,
			send: func(sc *relayScene) *httptest.ResponseRecorder {
				g := sc.contact
				_, g.holder, _ = ed25519.GenerateKey(nil)
				return sc.send1(sc.env(), g)
			}},
		{name: "a credential for another recipient", status: 403, reason: "access_invalid", debit: true,
			send: func(sc *relayScene) *httptest.ResponseRecorder {
				return sc.send1(envelope(sc.h.t, sc.sender.aid, []byte("misdirected")), sc.contact)
			}},
	})
}

func TestRelaySendOrder_Step6(t *testing.T) {
	runSteps(t, []stepCase{
		{name: "a first contact for an AID registered nowhere here", status: 404, reason: "recipient_unknown",
			send: func(sc *relayScene) *httptest.ResponseRecorder {
				c, _ := identitytest.Hub()
				return sc.h.send0(sc.ss, envelope(sc.h.t, c.AID(), nil), kind0Opts{})
			}},
	})
}

// Step 7: the same envelope waiting for the same recipient is a duplicate:
// 200 with the row's rid, and nothing is taken or written, whichever
// credential the copy came under (env_digest leaves out outer key 7).
func TestRelaySendOrder_Step7(t *testing.T) {
	sc := newScene(t)
	env := sc.env()
	first := decodeSent(t, sc.h.send0(sc.ss, env, kind0Opts{}))
	if first.Status != RelayQueued {
		t.Fatalf("first send: %+v", first)
	}
	for name, send := range map[string]func() *httptest.ResponseRecorder{
		"the same first contact again": func() *httptest.ResponseRecorder { return sc.h.send0(sc.ss, env, kind0Opts{}) },
		"the same envelope under a credential": func() *httptest.ResponseRecorder {
			return sc.send1(env, sc.contact)
		},
	} {
		before := sc.h.effects()
		got := decodeSent(t, send())
		if got.Status != RelayDuplicate || got.RID != first.RID {
			t.Errorf("%s: %+v, want duplicate %s", name, got, first.RID)
		}
		if d := before.diff(sc.h.effects()); d != "" {
			t.Errorf("%s took or wrote something: %s", name, d)
		}
	}
	if n := sc.h.rows(sc.recip.aid); n != 1 {
		t.Fatalf("%d rows, want 1", n)
	}
}

func TestRelaySendOrder_Step7a(t *testing.T) {
	big := func(sc *relayScene) []byte {
		return envelope(sc.h.t, sc.recip.aid, bytes.Repeat([]byte("s"), DefaultNonContactBytes))
	}
	runSteps(t, []stepCase{
		{name: "a first contact over the non-contact share", status: 413, reason: "too_large_for_stranger",
			send: func(sc *relayScene) *httptest.ResponseRecorder { return sc.h.send0(sc.ss, big(sc), kind0Opts{}) }},
		{name: "a stranger's send over the non-contact share", status: 413, reason: "too_large_for_stranger",
			send: func(sc *relayScene) *httptest.ResponseRecorder { return sc.send1(big(sc), sc.stranger) }},
	})
	// A contact's mail of that size goes into the mailbox's total.
	sc := newScene(t)
	if got := decodeSent(t, sc.send1(big(sc), sc.contact)); got.Status != RelayQueued {
		t.Fatalf("a contact's large send: %+v", got)
	}
}

func TestRelaySendOrder_Step8(t *testing.T) {
	runSteps(t, []stepCase{
		{name: "the recipient's first-contact bucket is empty", status: 429, reason: "strangers_busy",
			setup: func(sc *relayScene) {
				drain(sc.h.srv.relay.firstContact, sc.recip.aid, firstContactRate(DefaultQuota()))
			},
			send: func(sc *relayScene) *httptest.ResponseRecorder { return sc.send0(nil) }},
	})
}

func TestRelaySendOrder_Step9(t *testing.T) {
	var window time.Duration
	runSteps(t, []stepCase{
		{name: "an envelope queued three times today", status: 429, reason: "redelivery_limited",
			setup: func(sc *relayScene) {
				env := sc.env()
				sc.counter-- // send0 below sends env again
				for i := 0; i < MaxRedeliveries; i++ {
					if got := decodeSent(sc.h.t, sc.h.send0(sc.ss, env, kind0Opts{})); got.Status != RelayQueued {
						sc.h.t.Fatalf("delivery %d: %+v", i, got)
					}
					msgs, _ := sc.h.store.RelayPoll(sc.recip.aid, 0, 10, 1<<20)
					if _, err := sc.h.store.RelayAck(sc.recip.aid, []int64{msgs[0].ID}); err != nil {
						sc.h.t.Fatal(err)
					}
					sc.h.advance(10 * time.Minute)
				}
				window = RedeliveryWindow - MaxRedeliveries*10*time.Minute
			},
			send: func(sc *relayScene) *httptest.ResponseRecorder {
				rec := sc.send0(nil)
				if ra := rec.Header().Get("Retry-After"); ra != strconv.Itoa(int(window.Seconds())) {
					sc.h.t.Errorf("Retry-After %q, want what is left of the window, %d s", ra, int(window.Seconds()))
				}
				return rec
			}},
	})
	// After the window, the envelope may be queued again.
	sc := newScene(t)
	env := sc.env()
	for i := 0; i < MaxRedeliveries; i++ {
		decodeSent(t, sc.send1(env, sc.contact))
		msgs, _ := sc.h.store.RelayPoll(sc.recip.aid, 0, 10, 1<<20)
		_, _ = sc.h.store.RelayAck(sc.recip.aid, []int64{msgs[0].ID})
	}
	expectRefusal(t, sc.send1(env, sc.contact), 429, "redelivery_limited")
	sc.h.advance(RedeliveryWindow)
	if got := decodeSent(t, sc.send1(env, sc.contact)); got.Status != RelayQueued {
		t.Fatalf("after the window: %+v", got)
	}
}

func TestRelaySendOrder_Step10(t *testing.T) {
	fill := func(sc *relayScene, n int, class uint64, capID []byte) {
		for i := 0; i < n; i++ {
			env := envelope(sc.h.t, sc.recip.aid, []byte("filler "+strconv.Itoa(i)))
			d, _ := seal.EnvDigest(env)
			if _, err := sc.h.store.RelayEnqueue(RelayItem{To: sc.recip.aid, Envelope: env, Digest: d, Class: class, CapID: capID}); err != nil {
				sc.h.t.Fatal(err)
			}
		}
	}
	runSteps(t, []stepCase{
		{name: "a full mailbox", status: 507, reason: "mailbox_full",
			setup: func(sc *relayScene) {
				l := DefaultLimits()
				l.MailboxMessages = 3
				if err := sc.h.srv.SetLimits(l); err != nil {
					sc.h.t.Fatal(err)
				}
				fill(sc, 3, seal.CapClassContact, sc.contact.body.CapID)
			},
			send: func(sc *relayScene) *httptest.ResponseRecorder { return sc.send1(sc.env(), sc.contact) }},
		{name: "a full non-contact share, for a first contact", status: 429, reason: "strangers_busy",
			setup: func(sc *relayScene) { fill(sc, DefaultNonContactMsgs, seal.CapClassStranger, nil) },
			send:  func(sc *relayScene) *httptest.ResponseRecorder { return sc.send0(nil) }},
		{name: "a full non-contact share, for a stranger's credential", status: 429, reason: "strangers_busy",
			setup: func(sc *relayScene) { fill(sc, DefaultNonContactMsgs, seal.CapClassStranger, nil) },
			send:  func(sc *relayScene) *httptest.ResponseRecorder { return sc.send1(sc.env(), sc.stranger) }},
		{name: "a stranger's credential with 200 rows waiting", status: 429, reason: "strangers_busy",
			setup: func(sc *relayScene) { fill(sc, MaxStrangerCapRows, seal.CapClassStranger, sc.stranger.body.CapID) },
			send:  func(sc *relayScene) *httptest.ResponseRecorder { return sc.send1(sc.env(), sc.stranger) }},
	})
	// Contact mail does not count against the non-contact share (SSR-H4).
	sc := newScene(t)
	fill(sc, DefaultNonContactMsgs, seal.CapClassStranger, nil)
	if got := decodeSent(t, sc.send1(sc.env(), sc.contact)); got.Status != RelayQueued {
		t.Fatalf("a contact's send with the non-contact share full: %+v", got)
	}
}

// Step 11: what a queued send answers, writes and takes.
func TestRelaySendOrder_Step11(t *testing.T) {
	sc := newScene(t)
	type row struct {
		class int64
		capID []byte
	}
	read := func(rid string) (row, []byte) {
		var r row
		var payload []byte
		if err := sc.h.store.db.QueryRow(`SELECT class, cap_id, payload FROM relay_message WHERE rid=?`,
			mustB64(t, rid)).Scan(&r.class, &r.capID, &payload); err != nil {
			t.Fatalf("the row of rid %s: %v", rid, err)
		}
		return r, payload
	}
	for _, c := range []struct {
		name    string
		g       *grant // nil: a first contact
		class   int64
		capID   []byte
		buckets map[string]float64
	}{
		{"a first contact", nil,
			2, nil, map[string]float64{"session|" + sc.sender.aid: rateSessionSend.burst - 1,
				"first|" + sc.recip.aid: firstContactRate(DefaultQuota()).burst - 1}},
		{"a contact's credential", &sc.contact,
			1, sc.contact.body.CapID, map[string]float64{"cap|" + capKey(&sc.contact.body): rateContactCap.burst - 1}},
		{"a stranger's credential", &sc.stranger,
			2, sc.stranger.body.CapID, map[string]float64{"cap|" + capKey(&sc.stranger.body): rateStrangerCap.burst - 1}},
	} {
		before := sc.h.buckets()
		env := sc.env()
		var rec *httptest.ResponseRecorder
		if c.g == nil {
			rec = sc.h.send0(sc.ss, env, kind0Opts{})
		} else {
			env = withCap(t, env, *c.g)
			rec = sc.h.send1(env, "")
		}
		got := decodeSent(t, rec)
		var raw map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &raw)
		if got.Status != RelayQueued || len(mustB64(t, got.RID)) != RIDLen || raw["recipient_quiet"] != false {
			t.Errorf("%s: %s", c.name, rec.Body)
		}
		if _, ok := raw["via_hub"]; ok {
			t.Errorf("%s: a local send names a hub: %s", c.name, rec.Body)
		}
		r, payload := read(got.RID)
		if r.class != c.class || !bytes.Equal(r.capID, c.capID) {
			t.Errorf("%s: the row has class %d cap_id %x, want %d %x", c.name, r.class, r.capID, c.class, c.capID)
		}
		// The row holds the envelope as sent, key 7 and all.
		if !bytes.Equal(payload, env) {
			t.Errorf("%s: the row's envelope differs from the one sent", c.name)
		}
		after := sc.h.buckets()
		for k, want := range c.buckets {
			if after[k] != want {
				t.Errorf("%s: bucket %s holds %v, want %v", c.name, printable(k), after[k], want)
			}
			delete(after, k)
		}
		for k, v := range after {
			if before[k] != v {
				t.Errorf("%s: bucket %s changed too: %v -> %v", c.name, printable(k), before[k], v)
			}
		}
	}
}
