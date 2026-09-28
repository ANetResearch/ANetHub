package aghub_test

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// The fuzz harness (ANet docs/notes/0033-验证-模糊测试-hub.md).
//
// A fuzz target drives the real handler in process: no listener, no
// client, one ServeHTTP per request, so a worker spends its time in the
// hub rather than in the loopback stack. The hub is built once per worker
// (the setup before f.Fuzz) and keeps its state across inputs, so every
// property below is stated about one request against whatever state the
// earlier ones left, never about a fresh hub.
//
// Signatures are made at run time. A fuzz input carries the terms (a
// body, an amount, a time offset, which header to tamper with) and never
// a signature, so a corpus entry means the same thing to every worker and
// on every later run, and the fuzzer mutates the request rather than
// bytes that could only ever fail verification.

// fz is one hub under fuzzing.
type fz struct {
	store  *aghub.Store
	srv    *aghub.Server
	h      http.Handler
	hubAID string
	hub    *identity.Controller
	db     *sql.DB // a second connection, for reading invariants
	seq    atomic.Uint64
}

// newFZ builds a hub whose rate limits do not end the run: the fuzzer
// sends thousands of requests a second from one address and a handful of
// AIDs, which the default buckets and the per-signer replay share would
// turn into a stream of 429s that exercise nothing. The limits themselves
// have their own tests.
func newFZ(tb testing.TB) *fz {
	tb.Helper()
	dir := tb.TempDir()
	store, err := aghub.Open(dir)
	if err != nil {
		tb.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	s := aghub.NewServer(store)
	s.SetHubAID(id.AID)
	l := aghub.DefaultLimits()
	l.SendRate, l.SendBurst = 1e6, 1<<30
	l.RegisterPerMinute, l.RegisterBurst = 1e9, 1<<30
	l.KeysLookupPerMinute, l.KeysLookupBurst = 1e9, 1<<30
	l.MailboxMessages = 1 << 20
	if err := s.SetLimits(l); err != nil {
		tb.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { db.Close(); store.Close() })
	return &fz{store: store, srv: s, h: s.Handler(), hubAID: id.AID, hub: id.Ctrl, db: db}
}

// nonce is unique per request in this process. A signed request carries
// it in its query, so two inputs that are otherwise identical, signed in
// the same millisecond, are not one signature presented twice.
func (f *fz) nonce() string { return strconv.FormatUint(f.seq.Add(1), 10) }

// request builds a request with target as its request target. The target
// is set on the URL directly rather than parsed, so a fuzzed query cannot
// make the harness panic before the hub sees it.
func (f *fz) request(method, path, rawQuery string, body []byte) *http.Request {
	req := httptest.NewRequest(method, "http://hub.test/", bytes.NewReader(body))
	req.URL.Path = path
	req.URL.RawPath = ""
	req.URL.RawQuery = rawQuery
	req.RequestURI = req.URL.RequestURI()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ANet-Wire", "2")
	return req
}

// serve runs one request through the full handler chain.
func (f *fz) serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// sign sets relayauth v2 headers on req for body, signed by c for action
// at time ts.
func (f *fz) sign(req *http.Request, c *identity.Controller, action string, body []byte, ts uint64) {
	sig, seq := c.Sign(relayauth.PreimageV2(action, c.AID(), f.hubAID, ts, req.Method, req.URL.RequestURI(), body))
	req.Header.Set(relayauth.HeaderAID, c.AID())
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
}

// signedDo sends body to path as c, signed now. A nonce is added to the
// query unless the caller gave one.
func (f *fz) signedDo(c *identity.Controller, action, method, path, rawQuery string, body []byte) *httptest.ResponseRecorder {
	if rawQuery == "" {
		rawQuery = "fz=" + f.nonce()
	}
	req := f.request(method, path, rawQuery, body)
	f.sign(req, c, action, body, uint64(time.Now().UnixMilli()))
	return f.serve(req)
}

// agent incepts an identity and registers it, with an ADP card and, when
// withKeys, an encryption key set. It returns the controller and the key
// pair (nil without keys).
func (f *fz) agent(tb testing.TB, name string, caps []string, withKeys bool) (*identity.Controller, *seal.KeyPair) {
	tb.Helper()
	c, err := identity.Incept()
	if err != nil {
		tb.Fatal(err)
	}
	body := f.registration(tb, c, name, caps)
	var kp *seal.KeyPair
	if withKeys {
		var raw []byte
		raw, kp = fzKeySet(tb, c, 1, 0)
		body["enc_keys"] = base64.StdEncoding.EncodeToString(raw)
	}
	rec := f.register(c, fzJSON(tb, body))
	if rec.Code != http.StatusOK {
		tb.Fatalf("register %s: %d %s", name, rec.Code, rec.Body.Bytes())
	}
	return c, kp
}

// registration is a /register body for c with a signed ADP card.
func (f *fz) registration(tb testing.TB, c *identity.Controller, name string, caps []string) map[string]any {
	tb.Helper()
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		tb.Fatal(err)
	}
	return map[string]any{
		"aid": c.AID(), "name": name, "caps": caps,
		"kel":  base64.StdEncoding.EncodeToString(kel),
		"card": fzADPCard(tb, c, name, caps),
	}
}

// register posts raw to /register signed as c.
func (f *fz) register(c *identity.Controller, raw []byte) *httptest.ResponseRecorder {
	return f.signedDo(c, relayauth.ActionRegister, http.MethodPost, "/register", "", raw)
}

// fzADPCard is mintCard for a testing.TB.
func fzADPCard(tb testing.TB, c *identity.Controller, name string, caps []string) json.RawMessage {
	tb.Helper()
	if caps == nil {
		caps = []string{}
	}
	now := time.Now()
	card := &adp.AgentCard{
		SubjectDID: c.AID(), CardSchema: adp.CardSchema{Major: 1},
		Seq: uint64(now.UnixNano()), IssuedAt: now.Unix(),
		NotBefore:    now.Add(-time.Minute).Unix(),
		Capabilities: caps, CriticalExtensions: []string{}, Name: name,
	}
	// A card the signer cannot encode (fuzzed text that is not UTF-8) is
	// sent unsigned, which the hub must refuse.
	_ = card.Sign(c)
	return fzJSON(tb, card)
}

// fzJSON marshals v or fails.
func fzJSON(tb testing.TB, v any) []byte {
	tb.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// fzKeySet mints a signed encryption key set for c with sequence seq and
// one key valid from now-60s for the key lifetime, shifted by shiftMS.
func fzKeySet(tb testing.TB, c *identity.Controller, seq uint64, shiftMS int64) ([]byte, *seal.KeyPair) {
	tb.Helper()
	now := uint64(time.Now().UnixMilli())
	nb := uint64(int64(now-60_000) + shiftMS)
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, nb, nb+seal.KeyLifetimeMS)
	if err != nil {
		tb.Fatal(err)
	}
	set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: c.AID(), Seq: seq,
		Keys: []seal.EncKey{kp.Public}, IssuedAt: now}
	signed, err := seal.SignEncKeySet(set, c.Sign)
	if err != nil {
		tb.Fatal(err)
	}
	raw, err := signed.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	return raw, kp
}

// fzEnvelope is a structurally valid sealed envelope addressed to "to".
func fzEnvelope(tb testing.TB, to string, ct []byte) []byte {
	tb.Helper()
	if len(ct) == 0 {
		ct = []byte("ciphertext")
	}
	env := &seal.SealedEnvelope{
		V: seal.EnvelopeVersion, To: to, Suite: seal.SuiteX25519,
		KID: bytes.Repeat([]byte{7}, seal.KIDLen), Enc: bytes.Repeat([]byte{9}, 32), CT: ct,
	}
	b, err := env.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// fzA2ACard signs an A2A card for c built by a2aCardFor with the edits.
func fzA2ACard(tb testing.TB, c *identity.Controller, seq uint64, edits ...func(map[string]any)) json.RawMessage {
	tb.Helper()
	b, err := json.Marshal(a2aCardFor(c, seq, edits...))
	if err != nil {
		tb.Fatal(err)
	}
	out, err := a2acard.SignWithController(b, c, "https://hub.example.org/agents/"+c.AID()+"/jwks.json")
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

// fzA2ACardOrRaw is fzA2ACard for fuzzed contents: a card the signer
// refuses (a2acard.Sign accepts publish form only) is returned unsigned,
// which the hub must refuse in turn.
func fzA2ACardOrRaw(tb testing.TB, c *identity.Controller, seq uint64, edits ...func(map[string]any)) json.RawMessage {
	tb.Helper()
	b, err := json.Marshal(a2aCardFor(c, seq, edits...))
	if err != nil {
		tb.Fatal(err)
	}
	out, err := a2acard.SignWithController(b, c, "https://hub.example.org/agents/"+c.AID()+"/jwks.json")
	if err != nil {
		return b
	}
	return out
}

// allowed reports whether code is in the set, for "the answer is one of
// these" assertions.
func allowed(code int, set ...int) bool {
	for _, c := range set {
		if code == c {
			return true
		}
	}
	return false
}

// count runs a COUNT query on the invariant connection.
func (f *fz) count(tb testing.TB, q string, args ...any) int64 {
	tb.Helper()
	var n int64
	if err := f.db.QueryRow(q, args...).Scan(&n); err != nil {
		tb.Fatalf("%s: %v", q, err)
	}
	return n
}

// balance reads an account's balance from the store.
func (f *fz) balance(tb testing.TB, aid string) int64 {
	tb.Helper()
	n, err := f.store.Balance(aid)
	if err != nil {
		tb.Fatalf("balance of %s: %v", aid, err)
	}
	return n
}

// ledgerInvariants are the states the ledger must never be in, whatever
// the requests before:
//
//   - every amount column holds an INTEGER (SQLite turns an overflowing
//     sum into a REAL, which makes the row unreadable [redteam:si9]);
//   - no agent account is negative (the hub's own row is the issuer and
//     may be);
//   - what is due to and owed by peers is not negative;
//   - every account's entries add up to its balance (what `anet
//     reconcile` checks);
//   - the published supply agrees with itself: outstanding equals what
//     the agent rows add up to, and the signed issuance chain agrees.
func (f *fz) ledgerInvariants(tb testing.TB) {
	tb.Helper()
	for _, q := range []string{
		`SELECT COUNT(*) FROM credit_balance WHERE typeof(credits) <> 'integer'`,
		`SELECT COUNT(*) FROM credit_entry WHERE typeof(delta) <> 'integer'`,
		`SELECT COUNT(*) FROM credit_settled WHERE typeof(amount) <> 'integer' OR amount <= 0`,
		`SELECT COUNT(*) FROM hub_due WHERE typeof(amount) <> 'integer' OR amount < 0`,
		`SELECT COUNT(*) FROM hub_owed WHERE typeof(amount) <> 'integer' OR amount < 0`,
	} {
		if n := f.count(tb, q); n != 0 {
			tb.Fatalf("ledger invariant broken (%d rows): %s", n, q)
		}
	}
	if n := f.count(tb, `SELECT COUNT(*) FROM credit_balance WHERE aid <> ? AND credits < 0`, f.hubAID); n != 0 {
		tb.Fatalf("%d agent accounts are negative", n)
	}
	rows, err := f.db.Query(`SELECT b.aid, b.credits, COALESCE((SELECT SUM(delta) FROM credit_entry e WHERE e.aid = b.aid), 0)
	                           FROM credit_balance b WHERE b.aid <> ?`, f.hubAID)
	if err != nil {
		tb.Fatal(err)
	}
	for rows.Next() {
		var aid string
		var bal, sum int64
		if err := rows.Scan(&aid, &bal, &sum); err != nil {
			rows.Close()
			tb.Fatal(err)
		}
		if bal != sum {
			rows.Close()
			tb.Fatalf("account %s: balance %d, entries add up to %d", aid, bal, sum)
		}
	}
	rows.Close()
	sup, err := f.store.Supply(f.hubAID)
	if err != nil {
		tb.Fatalf("supply: %v", err)
	}
	if sup.Outstanding != sup.Balances {
		tb.Fatalf("supply: outstanding %d, agent balances %d", sup.Outstanding, sup.Balances)
	}
	if !sup.ChainAgrees {
		tb.Fatalf("supply: the issuance chain says %d outstanding, the ledger %d (%+v)",
			sup.ChainOutstanding, sup.Outstanding, sup)
	}
}

// clip bounds a fuzzed string, so one input cannot make a worker spend
// its time on megabyte fields the hub refuses by size anyway.
func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// clipB is clip for bytes.
func clipB(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// fzf formats for failure messages.
var fzf = fmt.Sprintf
