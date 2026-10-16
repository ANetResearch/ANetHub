package aghub

// The relay v3 fixture: a hub on a frozen clock, agents with mailbox keys,
// first-contact sessions, delivery credentials, and the two kinds of send
// (sealed-sender §4.2). The tests of /relay/session and /relay/send build on
// it.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// relayHub is a hub whose store clock stands still until the test moves it.
type relayHub struct {
	t      testing.TB
	dir    string
	store  *Store
	srv    *Server
	h      http.Handler
	hubAID string
	hubID  *hubid.Identity
	mu     sync.Mutex
	now    time.Time
	// read is how many bytes of its body the hub read of the last request
	// serve sent.
	read atomic.Int64
}

// relayClientIP is the address relay requests come from unless a test says
// otherwise (through the loopback proxy's X-Real-IP).
const relayClientIP = "203.0.113.20"

func newRelayHub(t testing.TB) *relayHub {
	t.Helper()
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	h := &relayHub{t: t, dir: dir, store: store, hubAID: id.AID, hubID: id, now: time.Now().Truncate(time.Millisecond)}
	store.clock = h.clock
	h.restart()
	return h
}

// restart replaces the hub process's server on the same store: every
// session and bucket is gone, as after a restart.
func (h *relayHub) restart() {
	s := NewServer(h.store)
	s.SetHubAID(h.hubAID)
	l := DefaultLimits()
	l.RegisterPerMinute, l.RegisterBurst = 1e9, 1<<30
	if err := s.SetLimits(l); err != nil {
		h.t.Fatal(err)
	}
	h.srv, h.h = s, s.Handler()
}

func (h *relayHub) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

// advance moves the hub's clock.
func (h *relayHub) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func (h *relayHub) nowMS() uint64 { return uint64(h.clock().UnixMilli()) }

// relayAgent is an agent registered at the hub, with its mailbox key.
type relayAgent struct {
	c        *identity.Controller
	aid      string
	mbox     seal.Mbox
	mboxPriv ed25519.PrivateKey
}

// agent registers a new agent with a key set whose mailbox key has epoch 1.
func (h *relayHub) agent() *relayAgent {
	h.t.Helper()
	a := h.bareAgent()
	h.publish(a, 1)
	return a
}

// bareAgent registers a new agent that has published no key set.
func (h *relayHub) bareAgent() *relayAgent {
	h.t.Helper()
	c, err := identitytest.Hub()
	if err != nil {
		h.t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.store.PutAgent(c.AID(), "n", nil, kel); err != nil {
		h.t.Fatal(err)
	}
	return &relayAgent{c: c, aid: c.AID()}
}

// publish gives a a new mailbox key under epoch and publishes a key set
// carrying it.
func (h *relayHub) publish(a *relayAgent, epoch uint64) {
	h.t.Helper()
	h.publishTo(a, epoch, h.clock())
}

// publishTo is publish at the time at.
func (h *relayHub) publishTo(a *relayAgent, epoch uint64, at time.Time) {
	h.t.Helper()
	fixturePublish(h.t, h.store, a, epoch, at)
}

// fixturePublish gives a a new mailbox key under epoch and publishes, at
// store, a key set carrying it and one encryption key valid at at, which
// envelope seals to from then on (fixtureKIDs). It returns that key.
func fixturePublish(t testing.TB, store *Store, a *relayAgent, epoch uint64, at time.Time) seal.EncKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a.mbox, a.mboxPriv = seal.Mbox{Epoch: epoch, Pub: pub}, priv
	now := uint64(at.UnixMilli())
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
	if err != nil {
		t.Fatal(err)
	}
	set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: a.aid, Seq: now + epoch,
		Keys: []seal.EncKey{kp.Public}, IssuedAt: now, Mbox: a.mbox}
	signed, err := seal.SignEncKeySet(set, a.c.Sign)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var prev uint64 // the set this one follows (FS-H4): the one stored
	_ = store.db.QueryRow(`SELECT seq FROM agent_keys WHERE aid=?`, a.aid).Scan(&prev)
	if _, err := store.PublishKeys(a.aid, raw, prev, a.c.KEL(), at); err != nil {
		t.Fatal(err)
	}
	fixtureKIDs.Store(a.aid, kp.Public)
	return kp.Public
}

// sealToKeysAt makes envelope seal to aid's key at store: the newest key of
// the set store holds for aid (when one agent published other sets at other
// hubs).
func sealToKeysAt(t testing.TB, store *Store, aid string) {
	t.Helper()
	keyset, _, _, err := store.LocalKeys(aid)
	if err != nil || keyset == nil {
		t.Fatalf("no key set for %s: %v", aid, err)
	}
	signed, err := seal.UnmarshalSignedEncKeySet(keyset)
	if err != nil {
		t.Fatal(err)
	}
	var es seal.EncKeySet
	if err := coredet.UnmarshalStrict(signed.Set, &es); err != nil {
		t.Fatal(err)
	}
	fixtureKIDs.Store(aid, es.Keys[len(es.Keys)-1])
}

// fixtureKIDs is the encryption key of the key set each agent of these
// fixtures published last, by AID (a seal.EncKey). envelope seals to it, so
// a well-formed send passes the hub's kid check (forward-secrecy FS-H1);
// an envelope to an agent that published nothing carries a kid no key set
// holds.
var fixtureKIDs sync.Map

// fixtureKID is the kid envelope seals an envelope to to.
func fixtureKID(to string) []byte {
	if k, ok := fixtureKIDs.Load(to); ok {
		return k.(seal.EncKey).KID
	}
	return bytes.Repeat([]byte{7}, seal.KIDLen)
}

// relaySigned hands out relayauth times: every request a different, later
// millisecond (RC1 takes each of a signer's times once).
var relaySigned atomic.Int64

// relayTick lets the wall clock pass the millisecond in which the hub under
// test last signed a request of its own, before a test signs one by hand for
// the same signer: RC1 takes each of a signer's times once, and on a fast
// machine the two would otherwise share a millisecond.
func relayTick() { time.Sleep(2 * time.Millisecond) }

func relaySignTS() uint64 {
	for {
		last := relaySigned.Load()
		now := time.Now().UnixMilli()
		if now <= last {
			now = last + 1
		}
		if relaySigned.CompareAndSwap(last, now) {
			return uint64(now)
		}
	}
}

// signed is a request signed by c with relayauth v2 for action.
func (h *relayHub) signed(c *identity.Controller, action, method, path string, body []byte) *http.Request {
	req := httptest.NewRequest(method, "http://hub.test"+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
	ts := relaySignTS()
	sig, seq := c.Sign(relayauth.PreimageV2(action, c.AID(), h.hubAID, ts, req.Method, req.URL.RequestURI(), body))
	req.Header.Set(relayauth.HeaderAID, c.AID())
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	return req
}

// serve runs req against the hub from ip (through the loopback proxy).
func (h *relayHub) serve(req *http.Request, ip string) *httptest.ResponseRecorder {
	h.read.Store(0)
	if req.Body != nil {
		req.Body = countingBody{req.Body, &h.read}
	}
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set("X-Real-IP", ip)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

// countingBody counts the bytes the hub reads of a request body.
type countingBody struct {
	r io.ReadCloser
	n *atomic.Int64
}

func (c countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c countingBody) Close() error { return c.r.Close() }

// session is an open first-contact session of the test.
type session struct {
	aid      string
	sid, key []byte
}

// openSession opens a session for a's agent, or fails the test.
func (h *relayHub) openSession(c *identity.Controller) session {
	h.t.Helper()
	ss, rec := h.tryOpenSession(c)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("POST /relay/session: %d %s", rec.Code, rec.Body)
	}
	return ss
}

// tryOpenSession sends POST /relay/session for c and returns the session
// it opened, if any, and the answer.
func (h *relayHub) tryOpenSession(c *identity.Controller) (session, *httptest.ResponseRecorder) {
	h.t.Helper()
	return openSessionVia(h.t, h.h, h.hubAID, c)
}

// openSessionVia opens a session for c on the hub handler hdl, whose AID is
// hubAID: the session it opened, if any, and the answer.
func openSessionVia(t testing.TB, hdl http.Handler, hubAID string, c *identity.Controller) (session, *httptest.ResponseRecorder) {
	t.Helper()
	esk, epk, err := relayauth.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(SessionRequest{EPK: base64.RawURLEncoding.EncodeToString(epk)})
	req := httptest.NewRequest(http.MethodPost, "http://hub.test/relay/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
	ts := relaySignTS()
	sig, seq := c.Sign(relayauth.PreimageV2(relayauth.ActionSession, c.AID(), hubAID, ts, req.Method, req.URL.RequestURI(), body))
	req.Header.Set(relayauth.HeaderAID, c.AID())
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set("X-Real-IP", relayClientIP)
	rec := httptest.NewRecorder()
	hdl.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return session{}, rec
	}
	var out SessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	sid := mustB64(t, out.SID)
	key, err := relayauth.OpenSessionKey(esk, hubAID, sid, mustB64(t, out.Enc), mustB64(t, out.CT))
	if err != nil {
		t.Fatalf("the session key does not open: %v", err)
	}
	return session{aid: c.AID(), sid: sid, key: key}, rec
}

func mustB64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("%q is not base64url: %v", s, err)
	}
	return b
}

// envelope is a structurally valid envelope for to (the hub only reads the
// outer layer), with a kind-0 access; ct varies it. It is sealed to the key
// to published last in these fixtures (fixtureKID).
func envelope(t testing.TB, to string, ct []byte) []byte {
	t.Helper()
	return envelopeTo(t, to, fixtureKID(to), ct)
}

// envelopeTo is envelope sealed to kid.
func envelopeTo(t testing.TB, to string, kid, ct []byte) []byte {
	t.Helper()
	if len(ct) == 0 {
		ct = []byte("ciphertext")
	}
	env := &seal.SealedEnvelope{
		V: seal.EnvelopeVersion, To: to, Suite: seal.SuiteX25519,
		KID: kid, Enc: bytes.Repeat([]byte{9}, 32), CT: ct,
		Access: &seal.Access{Kind: seal.AccessKindSession},
	}
	b, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// kind0Opts change a first-contact send away from the well-formed one.
type kind0Opts struct {
	home    string  // X-ANet-Home, MACed
	ts      *uint64 // X-ANet-TS (default: the hub's clock)
	macBody []byte  // the body the MAC is computed over (default: the body sent)
	edit    func(*http.Request)
	ip      string // the client address (default relayClientIP)
}

// kind0Request is a first-contact /relay/send of env under ss.
func (h *relayHub) kind0Request(ss session, env []byte, o kind0Opts) *http.Request {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://hub.test/relay/send", bytes.NewReader(env))
	req.Header.Set("Content-Type", EnvelopeContentType)
	req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
	req.Header.Set(HeaderAccess, base64.RawURLEncoding.EncodeToString(accessRaw(h.t, env)))
	if o.home != "" {
		req.Header.Set(relayauth.HeaderHome, o.home)
	}
	ts := h.nowMS()
	if o.ts != nil {
		ts = *o.ts
	}
	macBody := env
	if o.macBody != nil {
		macBody = o.macBody
	}
	mac, err := relayauth.SessionMAC(ss.key, ss.sid, ts, req.Method, req.URL.RequestURI(), o.home, macBody)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set(relayauth.HeaderSession, relayauth.EncodeSessionID(ss.sid))
	req.Header.Set(relayauth.HeaderMAC, relayauth.EncodeMAC(mac))
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	if o.edit != nil {
		o.edit(req)
	}
	return req
}

// send0 sends env as a first contact under ss.
func (h *relayHub) send0(ss session, env []byte, o kind0Opts) *httptest.ResponseRecorder {
	h.t.Helper()
	ip := o.ip
	if ip == "" {
		ip = relayClientIP
	}
	return h.serve(h.kind0Request(ss, env, o), ip)
}

// accessRaw is outer key 7 of env, as X-ANet-Access carries it.
func accessRaw(t testing.TB, env []byte) []byte {
	t.Helper()
	outer, err := seal.ParseOuter(env)
	if err != nil {
		raw, _ := coredet.Marshal(&seal.Access{Kind: seal.AccessKindSession})
		return raw
	}
	raw, err := coredet.Marshal(outer.Access)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// grant is a delivery credential the test holds: the capability and the
// holder key.
type grant struct {
	cap    *seal.Cap
	body   seal.CapBody
	holder ed25519.PrivateKey
}

// issue is a capability owner signs with its mailbox key, of class and
// expiring in exp from now.
func (h *relayHub) issue(owner *relayAgent, class uint64, exp time.Duration) grant {
	h.t.Helper()
	hp, hs, err := ed25519.GenerateKey(nil)
	if err != nil {
		h.t.Fatal(err)
	}
	id := make([]byte, seal.CapIDLen)
	_, _ = rand.Read(id)
	body := seal.CapBody{Type: seal.CapType, Owner: owner.aid, Epoch: owner.mbox.Epoch, CapID: id, Class: class,
		CapExp: uint64(h.clock().Add(exp).UnixMilli()), Holder: hp}
	c, err := seal.SignCap(owner.mboxPriv, &body)
	if err != nil {
		h.t.Fatal(err)
	}
	return grant{cap: c, body: body, holder: hs}
}

// rawGrant is a capability over any body bytes, signed by key: for the
// bodies SignCap refuses to sign.
func rawGrant(body []byte, key ed25519.PrivateKey) grant {
	_, hs, _ := ed25519.GenerateKey(nil)
	return grant{cap: &seal.Cap{Body: body, Sig: ed25519.Sign(key, body)}, holder: hs}
}

// withCap is env with a kind-1 access under g: the holder's proof over its
// env_digest.
func withCap(t testing.TB, env []byte, g grant) []byte {
	t.Helper()
	d, err := seal.EnvDigest(env)
	if err != nil {
		t.Fatal(err)
	}
	id := g.body.CapID
	if id == nil {
		id = make([]byte, seal.CapIDLen)
	}
	proof := seal.SignAccess(g.holder, id, d)
	out, err := seal.SetAccess(env, &seal.Access{Kind: seal.AccessKindCap, Cap: g.cap, Proof: proof})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// kind1Request is a /relay/send of env (which carries its kind-1 access).
func kind1Request(t testing.TB, env []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://hub.test/relay/send", bytes.NewReader(env))
	req.Header.Set("Content-Type", EnvelopeContentType)
	req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
	req.Header.Set(HeaderAccess, base64.RawURLEncoding.EncodeToString(accessRaw(t, env)))
	return req
}

// send1 sends env under its kind-1 access from ip (relayClientIP when
// empty).
func (h *relayHub) send1(env []byte, ip string) *httptest.ResponseRecorder {
	h.t.Helper()
	if ip == "" {
		ip = relayClientIP
	}
	return h.serve(kind1Request(h.t, env), ip)
}

// sent is a decoded 200 of /relay/send.
type sent struct {
	Status         string `json:"status"`
	RID            string `json:"rid"`
	RecipientQuiet bool   `json:"recipient_quiet"`
}

func decodeSent(t testing.TB, rec *httptest.ResponseRecorder) sent {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("send: %d %s", rec.Code, rec.Body)
	}
	var out sent
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// reasonOf is the reason of a G1 error body.
func reasonOf(rec *httptest.ResponseRecorder) string {
	var b struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	return b.Reason
}

// expectRefusal checks one refusal: status and reason, and Retry-After when
// the status asks the caller to wait.
func expectRefusal(t testing.TB, rec *httptest.ResponseRecorder, status int, reason string) {
	t.Helper()
	if rec.Code != status || reasonOf(rec) != reason {
		t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body, status, reason)
	}
	if (status == 429 || status == 507 || status == 502) && rec.Header().Get("Retry-After") == "" {
		t.Fatalf("%d %s without Retry-After", status, reason)
	}
}

// buckets is every bucket of the hub's relay state that is not full, by
// set and key.
func (h *relayHub) buckets() map[string]float64 {
	out := map[string]float64{}
	for name, b := range map[string]*bucketSet{"session": h.srv.relay.sessionSend, "cap": h.srv.relay.caps,
		"first": h.srv.relay.firstContact, "addr": h.srv.relay.addrFailure} {
		b.mu.Lock()
		now := b.now()
		for k, x := range b.buckets {
			t := x.tokens
			if d := now.Sub(x.at); d > 0 {
				t += d.Seconds() * x.rate.perSec
			}
			t = math.Min(x.rate.burst, t)
			if t < x.rate.burst {
				out[name+"|"+k] = t
			}
		}
		b.mu.Unlock()
	}
	return out
}

// effects is what a request may have changed: every row of the database
// and every bucket that is not full.
type effects struct {
	db      string
	buckets map[string]float64
}

func (h *relayHub) effects() effects {
	h.t.Helper()
	return effects{db: dumpDB(h.t, h.store.db), buckets: h.buckets()}
}

// same reports how after differs from before, or "".
func (e effects) diff(after effects) string {
	var out []string
	if e.db != after.db {
		out = append(out, "a row was written")
	}
	keys := map[string]bool{}
	for k := range e.buckets {
		keys[k] = true
	}
	for k := range after.buckets {
		keys[k] = true
	}
	var ks []string
	for k := range keys {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		b, a := e.buckets[k], after.buckets[k]
		if _, ok := e.buckets[k]; !ok {
			b = -1
		}
		if _, ok := after.buckets[k]; !ok {
			a = -1
		}
		if b != a {
			out = append(out, fmt.Sprintf("bucket %q: %v -> %v (-1: full)", printable(k), b, a))
		}
	}
	return strings.Join(out, "; ")
}

// printable is a bucket key without its binary part.
func printable(k string) string {
	if i := strings.IndexByte(k, 0); i >= 0 {
		return k[:i] + "\\0…"
	}
	return k
}

// rows is how many relay rows the hub holds for to.
func (h *relayHub) rows(to string) int {
	h.t.Helper()
	n, err := h.store.RelayPending(to)
	if err != nil {
		h.t.Fatal(err)
	}
	return n
}
