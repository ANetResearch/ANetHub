package aghub_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// Helpers that speak the hub wire the way a daemon does: relayauth v2
// headers over the exact bytes sent, X-ANet-Wire: 3 (wireHeader), sealed
// envelopes on the relay.

// rawBody turns a test body into the bytes sent: nil is an empty body,
// []byte is sent as is, anything else is JSON-encoded.
func rawBody(t *testing.T, body any) []byte {
	t.Helper()
	switch b := body.(type) {
	case nil:
		return nil
	case []byte:
		return b
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
}

// lastSignedMS is the X-ANet-TS of the last request signed "now" by these
// helpers. The hub takes each of a signer's times once (RC1), so a second
// request signed in the same millisecond is refused as replayed by design.
// A daemon signs each request at a later time than the last
// (relayauth.MonoClock); the helpers do the same.
var lastSignedMS atomic.Int64

// signingNow is the time to sign a request at "now": the current time, but
// always at least one millisecond after the previous one it returned, so
// no two helper signatures share a timestamp. Tests that mean a specific
// time (outside the skew window, a fixed replay) pass it to signV2 instead.
func signingNow() time.Time {
	for {
		last := lastSignedMS.Load()
		now := time.Now().UnixMilli()
		if now <= last {
			now = last + 1
		}
		if lastSignedMS.CompareAndSwap(last, now) {
			return time.UnixMilli(now)
		}
	}
}

// signV2 signs req (whose body is raw) as c for hubAID at time at.
func signV2(t *testing.T, req *http.Request, c *identity.Controller, action, hubAID string, raw []byte, at time.Time) {
	t.Helper()
	ts := uint64(at.UnixMilli())
	sig, seq := c.Sign(relayauth.PreimageV2(action, c.AID(), hubAID, ts, req.Method, req.URL.RequestURI(), raw))
	req.Header.Set(relayauth.HeaderAID, c.AID())
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
}

// wireHeader is the X-ANet-Wire value every helper request declares.
var wireHeader = strconv.Itoa(aghub.WireVersion)

// newRequest builds an unsigned request.
func newRequest(t *testing.T, srv *httptest.Server, method, path string, raw []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ANet-Wire", wireHeader)
	return req
}

// signedRequest builds a wire-2 request signed as c for this hub, now
// (signingNow).
func signedRequest(t *testing.T, srv *httptest.Server, c *identity.Controller, action, method, path string, body any) *http.Request {
	t.Helper()
	raw := rawBody(t, body)
	req := newRequest(t, srv, method, path, raw)
	signV2(t, req, c, action, hubAIDOf(t, srv), raw, signingNow())
	return req
}

// send performs a request and returns the status, body and headers.
func send(t *testing.T, req *http.Request) (int, []byte, http.Header) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

// signedDo sends a signed wire-2 request as c.
func signedDo(t *testing.T, srv *httptest.Server, c *identity.Controller, action, method, path string, body any) (int, []byte) {
	t.Helper()
	code, b, _ := send(t, signedRequest(t, srv, c, action, method, path, body))
	return code, b
}

// testEnvelope is a structurally valid sealed envelope addressed to "to",
// sealed to the key to published last (publishedKID). The hub only parses
// the outer layer, so the ciphertext need not be real for tests of the
// relay itself; relayRoundTrip below uses a real one.
func testEnvelope(t *testing.T, to string, ct []byte) []byte {
	t.Helper()
	if len(ct) == 0 {
		ct = []byte("ciphertext")
	}
	env := &seal.SealedEnvelope{
		V: seal.EnvelopeVersion, To: to, Suite: seal.SuiteX25519,
		KID: publishedKID(to), Enc: bytes.Repeat([]byte{9}, 32), CT: ct,
		Access: &seal.Access{Kind: seal.AccessKindSession},
	}
	b, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// relaySend sends one envelope from sender as a first contact (outer access
// kind 0), under the session relaySession keeps for sender on srv, the way a
// daemon sends before it holds a delivery credential.
func relaySend(t *testing.T, srv *httptest.Server, sender *identity.Controller, to string, envelope []byte) (int, []byte, http.Header) {
	t.Helper()
	return send(t, sessionSendRequest(t, srv, relaySession(t, srv, sender), envelope, ""))
}

// testSession is a first-contact session a test opened.
type testSession struct {
	sid, key []byte
}

// testSessions holds the session of each (hub, sender), so that a test that
// sends many messages opens one session, as a daemon does (a hub refuses an
// AID's 31st opening in an hour).
var testSessions sync.Map

// relaySession is sender's session on srv, opened on first use.
func relaySession(t *testing.T, srv *httptest.Server, sender *identity.Controller) testSession {
	t.Helper()
	k := srv.URL + "|" + sender.AID()
	if v, ok := testSessions.Load(k); ok {
		return v.(testSession)
	}
	ts, code, b := openSession(t, srv, sender)
	if code != http.StatusOK {
		t.Fatalf("opening a session for %s: %d %s", sender.AID(), code, b)
	}
	testSessions.Store(k, ts)
	return ts
}

// openSession opens a new first-contact session for sender on srv (POST
// /relay/session) and returns it, or the refusal.
func openSession(t *testing.T, srv *httptest.Server, sender *identity.Controller) (testSession, int, []byte) {
	t.Helper()
	esk, epk, err := relayauth.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	code, b := signedDo(t, srv, sender, relayauth.ActionSession, http.MethodPost, "/relay/session",
		map[string]string{"epk": base64.RawURLEncoding.EncodeToString(epk)})
	if code != http.StatusOK {
		return testSession{}, code, b
	}
	var out aghub.SessionResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	dec := func(s string) []byte {
		v, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("a session answer member is not base64url: %v", err)
		}
		return v
	}
	sid := dec(out.SID)
	key, err := relayauth.OpenSessionKey(esk, hubAIDOf(t, srv), sid, dec(out.Enc), dec(out.CT))
	if err != nil {
		t.Fatalf("the session key does not open: %v", err)
	}
	return testSession{sid: sid, key: key}, code, b
}

// accessOf is outer key 7 of an envelope as X-ANet-Access carries it; a
// kind-0 access for bytes that are not an envelope (a test of the hub's
// refusal sends those too).
func accessOf(envelope []byte) []byte {
	a := &seal.Access{Kind: seal.AccessKindSession}
	if outer, err := seal.ParseOuter(envelope); err == nil {
		a = outer.Access
	}
	raw, err := coredet.Marshal(a)
	if err != nil {
		panic(err)
	}
	return raw
}

// sessionSendRequest is a first-contact /relay/send of envelope under ss,
// with X-ANet-Home home when it is not empty, MACed now.
func sessionSendRequest(t *testing.T, srv *httptest.Server, ss testSession, envelope []byte, home string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/relay/send", bytes.NewReader(envelope))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", aghub.EnvelopeContentType)
	req.Header.Set("X-ANet-Wire", wireHeader)
	req.Header.Set(aghub.HeaderAccess, base64.RawURLEncoding.EncodeToString(accessOf(envelope)))
	if home != "" {
		req.Header.Set(relayauth.HeaderHome, home)
	}
	ts := uint64(time.Now().UnixMilli())
	mac, err := relayauth.SessionMAC(ss.key, ss.sid, ts, req.Method, req.URL.RequestURI(), home, envelope)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(relayauth.HeaderSession, relayauth.EncodeSessionID(ss.sid))
	req.Header.Set(relayauth.HeaderMAC, relayauth.EncodeMAC(mac))
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	return req
}

// relaySent is the decoded 200 of /relay/send.
type relaySent struct {
	Status         string `json:"status"`
	RID            string `json:"rid"`
	ViaHub         string `json:"via_hub"`
	RecipientQuiet bool   `json:"recipient_quiet"`
}

// polled is the decoded /relay/poll answer.
type polled struct {
	Messages []struct {
		ID       int64  `json:"id"`
		Envelope string `json:"envelope"`
	} `json:"messages"`
}

// relayPoll collects c's mailbox.
func relayPoll(t *testing.T, srv *httptest.Server, c *identity.Controller) polled {
	t.Helper()
	code, b := signedDo(t, srv, c, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("poll: %d %s", code, b)
	}
	var p polled
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// relayAck acks ids from c's mailbox.
func relayAck(t *testing.T, srv *httptest.Server, c *identity.Controller, ids ...int64) int {
	t.Helper()
	code, b := signedDo(t, srv, c, relayauth.ActionAck, http.MethodPost, "/relay/ack", map[string]any{"ids": ids})
	if code != http.StatusOK {
		t.Fatalf("ack: %d %s", code, b)
	}
	var out struct {
		Acked int `json:"acked"`
	}
	_ = json.Unmarshal(b, &out)
	return out.Acked
}

// mintKeySet signs an encryption key set for c with the given seq and
// one fresh key valid now.
func mintKeySet(t *testing.T, c *identity.Controller, seq uint64) ([]byte, *seal.KeyPair) {
	t.Helper()
	now := uint64(time.Now().UnixMilli())
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
	if err != nil {
		t.Fatal(err)
	}
	set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: c.AID(), Seq: seq,
		Keys: []seal.EncKey{kp.Public}, IssuedAt: now, Mbox: testMbox(t)}
	signed, err := seal.SignEncKeySet(set, c.Sign)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw, kp
}

// publishKeys posts a key set for c as a daemon that follows what the hub
// holds: prev_seq is the seq of the set srv serves for c (0 for none).
func publishKeys(t *testing.T, srv *httptest.Server, c *identity.Controller, raw []byte) (int, []byte) {
	t.Helper()
	return publishKeysPrev(t, srv, c, raw, storedKeySeq(t, srv, c.AID()))
}

// publishKeysPrev posts a key set for c with prev_seq prev (FS-H4). A set
// the hub took is what testEnvelope seals to c from then on.
func publishKeysPrev(t *testing.T, srv *httptest.Server, c *identity.Controller, raw []byte, prev uint64) (int, []byte) {
	t.Helper()
	code, b := signedDo(t, srv, c, relayauth.ActionKeys, http.MethodPost, "/agents/"+c.AID()+"/keys",
		map[string]any{"keys": base64.RawURLEncoding.EncodeToString(raw), "prev_seq": prev})
	if code == http.StatusOK {
		noteKeys(c.AID(), raw)
	}
	return code, b
}

// registerWithKeys registers c (register) and publishes a key set for it,
// which testEnvelope seals to c from then on: a recipient the hub queues
// mail for (forward-secrecy FS-H1).
func registerWithKeys(t *testing.T, srv *httptest.Server, c *identity.Controller, name string, caps []string) {
	t.Helper()
	register(t, srv, c, name, caps)
	raw, _ := mintKeySet(t, c, uint64(time.Now().UnixMilli()))
	if code, b := publishKeys(t, srv, c, raw); code != http.StatusOK {
		t.Fatalf("publish the key set of %s: %d %s", name, code, b)
	}
}

// ensureKeys publishes a key set for c when srv holds none for it, as a
// daemon does right after it registers: an agent is listed, and has a
// directory entry, only once it has one (sealed-sender SSR-H18).
func ensureKeys(t *testing.T, srv *httptest.Server, c *identity.Controller) {
	t.Helper()
	if storedKeySeq(t, srv, c.AID()) != 0 {
		return
	}
	raw, _ := mintKeySet(t, c, uint64(time.Now().UnixMilli()))
	if code, b := publishKeys(t, srv, c, raw); code != http.StatusOK {
		t.Fatalf("publish the key set of %s: %d %s", c.AID(), code, b)
	}
}

// storeAgentWithKeys puts a new agent with a key set straight into store,
// for a test of the store itself.
func storeAgentWithKeys(t *testing.T, store *aghub.Store, name string) *identity.Controller {
	t.Helper()
	c, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(c.AID(), name, nil, kel); err != nil {
		t.Fatal(err)
	}
	raw, _ := mintKeySet(t, c, uint64(time.Now().UnixMilli()))
	if _, err := store.PublishKeys(c.AID(), raw, 0, c.KEL(), time.Now()); err != nil {
		t.Fatal(err)
	}
	noteKeys(c.AID(), raw)
	return c
}

// withEncKeys puts the key set raw in a registration body for aid at srv,
// as a daemon does: base64url, with prev_seq the seq of the set srv holds.
func withEncKeys(t *testing.T, srv *httptest.Server, body map[string]any, aid string, raw []byte) map[string]any {
	t.Helper()
	body["enc_keys"] = base64.RawURLEncoding.EncodeToString(raw)
	body["prev_seq"] = storedKeySeq(t, srv, aid)
	noteKeys(aid, raw)
	return body
}

// storedKeySeq is the seq of the key set srv serves for aid, 0 for none.
func storedKeySeq(t *testing.T, srv *httptest.Server, aid string) uint64 {
	t.Helper()
	code, b := getJSON(t, srv.URL+"/agents/"+aid+"/keys")
	if code != http.StatusOK {
		return 0
	}
	var v aghub.KeysView
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(v.Keys)
	if err != nil {
		t.Fatalf("the served key set is not base64url: %v", err)
	}
	return keySetOf(t, raw).Seq
}

// keySetOf decodes a signed key set.
func keySetOf(t *testing.T, raw []byte) seal.EncKeySet {
	t.Helper()
	signed, err := seal.UnmarshalSignedEncKeySet(raw)
	if err != nil {
		t.Fatal(err)
	}
	var es seal.EncKeySet
	if err := coredet.UnmarshalStrict(signed.Set, &es); err != nil {
		t.Fatal(err)
	}
	return es
}

// publishedKIDs is the kid of the last key set each agent of these tests
// published, by AID: testEnvelope seals to it, so a well-formed send passes
// the hub's kid check (forward-secrecy FS-H1). Agents that published no set
// get a kid no set holds.
var publishedKIDs sync.Map

// noteKeys records the last key of the set raw as aid's (sets that do not
// decode are not recorded).
func noteKeys(aid string, raw []byte) {
	signed, err := seal.UnmarshalSignedEncKeySet(raw)
	if err != nil {
		return
	}
	var es seal.EncKeySet
	if coredet.UnmarshalStrict(signed.Set, &es) != nil || len(es.Keys) == 0 {
		return
	}
	publishedKIDs.Store(aid, es.Keys[len(es.Keys)-1].KID)
}

// publishedKID is the kid testEnvelope seals an envelope to to.
func publishedKID(to string) []byte {
	if k, ok := publishedKIDs.Load(to); ok {
		return k.([]byte)
	}
	return bytes.Repeat([]byte{7}, seal.KIDLen)
}

// sealFrom seals a real inner message from sender to the recipient key.
func sealFrom(t *testing.T, sender *identity.Controller, senderKeys []byte, to string, recipient *seal.EncKey, body []byte) []byte {
	t.Helper()
	kel, err := identity.MarshalKEL(sender.KEL())
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().UnixMilli())
	inner := &seal.SealedInner{
		From: sender.AID(), KeyStateSeq: sender.CurrentSeq(), To: to, Type: seal.TypeMessage,
		IX: "ix-wire2", MID: seal.NewMID(), TS: now, Exp: now + 14*24*3600*1000,
		Body: body, KEL: kel, Keys: senderKeys, Notices: [][]byte{{}}, // the hub does not read the notice
	}
	env, _, err := seal.Seal(inner, recipient, sender.Sign, seal.SealOpts{})
	if err != nil {
		t.Fatal(err)
	}
	env, err = seal.SetAccess(env, &seal.Access{Kind: seal.AccessKindSession})
	if err != nil {
		t.Fatal(err)
	}
	return env
}
