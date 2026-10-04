package aghub

// The rules of a kind-1 send that hold across its steps (sealed-sender
// SSR-H3, H3a, H3b; SI-16), and the deduplication of SI-10.

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"
)

// answer is what a client sees of a response: status, headers and body.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func answerOf(rec *httptest.ResponseRecorder) answer {
	return answer{rec.Code, rec.Header().Clone(), rec.Body.Bytes()}
}

func (a answer) same(b answer) bool {
	if a.status != b.status || !bytes.Equal(a.body, b.body) || len(a.header) != len(b.header) {
		return false
	}
	for k, v := range a.header {
		w := b.header[k]
		if len(v) != len(w) {
			return false
		}
		for i := range v {
			if v[i] != w[i] {
				return false
			}
		}
	}
	return true
}

// kind1Refusals are a credential refused for every reason step 2 and step 5
// know, each sent from its own address so that no address bucket runs out.
func kind1Refusals(t *testing.T, sc *relayScene) map[string]func(ip string) *httptest.ResponseRecorder {
	t.Helper()
	signed := func(mut func(b map[uint64]any), key ed25519.PrivateKey) grant {
		hp, _, _ := ed25519.GenerateKey(nil)
		b := map[uint64]any{0: seal.CapType, 1: sc.recip.aid, 2: sc.recip.mbox.Epoch, 3: bytes.Repeat([]byte{3}, 16),
			4: seal.CapClassContact, 5: uint64(sc.h.clock().Add(time.Hour).UnixMilli()), 6: []byte(hp)}
		mut(b)
		raw, err := coredet.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return rawGrant(raw, key)
	}
	stranger, _ := identitytest.Hub()
	bare := sc.h.bareAgent()
	revoked := sc.h.issue(sc.recip, seal.CapClassContact, time.Hour)
	if _, _, err := sc.h.store.RevokeCaps(sc.recip.aid, [][]byte{revoked.body.CapID}); err != nil {
		t.Fatal(err)
	}
	oldEpoch := sc.h.issue(sc.recip, seal.CapClassContact, time.Hour)
	_, other, _ := ed25519.GenerateKey(nil)
	// The owner moves to epoch 2 after oldEpoch was issued under epoch 1;
	// the credentials below are issued under 2.
	sc.h.publish(sc.recip, 2)
	good := sc.h.issue(sc.recip, seal.CapClassContact, time.Hour)
	expired := sc.h.issue(sc.recip, seal.CapClassContact, -10*time.Minute)
	send := func(env []byte, g grant) func(ip string) *httptest.ResponseRecorder {
		body := withCap(t, env, g)
		return func(ip string) *httptest.ResponseRecorder { return sc.h.send1(body, ip) }
	}
	wrongHolder := good
	_, wrongHolder.holder, _ = ed25519.GenerateKey(nil)
	return map[string]func(ip string) *httptest.ResponseRecorder{
		"an unknown owner": send(sc.env(), signed(func(b map[uint64]any) { b[1] = stranger.AID(); b[2] = uint64(2) }, other)),
		"an owner without a key set": send(sc.env(),
			signed(func(b map[uint64]any) { b[1] = bare.aid }, other)),
		"a body that does not decode": send(sc.env(), rawGrant([]byte{0x80}, sc.recip.mboxPriv)),
		"another type tag":            send(sc.env(), signed(func(b map[uint64]any) { b[0] = "anet.cap/9"; b[2] = uint64(2) }, sc.recip.mboxPriv)),
		"an old epoch":                send(sc.env(), oldEpoch),
		"a signature by another key":  send(sc.env(), signed(func(b map[uint64]any) { b[2] = uint64(2) }, other)),
		"an expiry that passed":       send(sc.env(), expired),
		"a revocation":                send(sc.env(), revoked),
		"a proof by another key":      send(sc.env(), wrongHolder),
		"another recipient":           send(envelope(t, sc.sender.aid, []byte("elsewhere")), good),
	}
}

// TestKind1RefusalsAreIdentical (SSR-H3, SI-16, M7): whatever refused a
// credential, the answer is the same status, the same headers and the same
// bytes, so an anonymous sender cannot tell an unknown recipient from a
// revoked credential.
func TestKind1RefusalsAreIdentical(t *testing.T) {
	sc := newScene(t)
	var first answer
	var firstName string
	i := 0
	for name, send := range kind1Refusals(t, sc) {
		i++
		got := answerOf(send("203.0.113." + strconv.Itoa(100+i)))
		if got.status != http.StatusForbidden || reasonOf(&httptest.ResponseRecorder{Body: bytes.NewBuffer(got.body)}) != "access_invalid" {
			t.Fatalf("%s: %d %s, want 403 access_invalid", name, got.status, got.body)
		}
		if firstName == "" {
			first, firstName = got, name
			continue
		}
		if !got.same(first) {
			t.Errorf("%s answers otherwise than %s:\n%d %v %s\n%d %v %s", name, firstName,
				got.status, got.header, got.body, first.status, first.header, first.body)
		}
	}
}

// TestKind1Step2ConstantVerifyCount (SSR-H3a, M45): every refusal of step 2
// costs exactly one Ed25519 verification, whether it came before the
// signature was checked or from the signature itself or after it.
func TestKind1Step2ConstantVerifyCount(t *testing.T) {
	sc := newScene(t)
	refusals := kind1Refusals(t, sc)
	var n int
	verifyEd25519 = func(pub ed25519.PublicKey, msg, sig []byte) bool {
		n++
		return ed25519.Verify(pub, msg, sig)
	}
	defer func() { verifyEd25519 = ed25519.Verify }()
	i := 0
	for name, send := range refusals {
		if name == "a proof by another key" || name == "another recipient" {
			continue // step 5: the credential passed step 2
		}
		i++
		n = 0
		if rec := send("203.0.113." + strconv.Itoa(150+i)); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if n != 1 {
			t.Errorf("%s: step 2 made %d Ed25519 verifications, want exactly 1", name, n)
		}
		// Refused at step 2 itself, before the body: a later step that
		// refuses the same credential would read the envelope first.
		if read := sc.h.read.Load(); read != 0 {
			t.Errorf("%s: refused after reading %d bytes of the body, want a refusal of step 2", name, read)
		}
	}
}

// TestAddrFailureBucket (SSR-H3b, M44): refused credentials debit their
// address's bucket after the 403, never a send that went through; an empty
// bucket answers 429 before anything about the recipient is looked at, the
// same bytes for a recipient that exists and one that does not; an IPv6
// client is one bucket per /64; and the bucket refills.
func TestAddrFailureBucket(t *testing.T) {
	sc := newScene(t)
	const ip = "198.51.100.77"
	key := rateKeyOfString(ip)
	forged := func() *httptest.ResponseRecorder {
		g := sc.contact
		_, g.holder, _ = ed25519.GenerateKey(nil)
		return sc.h.send1(withCap(t, sc.env(), g), ip)
	}
	good := func(to *relayAgent, g grant) *httptest.ResponseRecorder {
		return sc.h.send1(withCap(t, envelope(t, to.aid, []byte("good "+strconv.Itoa(sc.counter))), g), ip)
	}
	// A send that goes through takes nothing from the address.
	sc.counter++
	if rec := good(sc.recip, sc.contact); rec.Code != 200 {
		t.Fatalf("a good send: %d %s", rec.Code, rec.Body)
	}
	if got := sc.h.srv.relay.addrFailure.tokens(key, rateAddrFailure); got != rateAddrFailure.burst {
		t.Fatalf("a send that went through debited its address: %v", got)
	}
	// Thirty refusals, each a 403 and one token.
	for i := 0; i < int(rateAddrFailure.burst); i++ {
		if rec := forged(); rec.Code != http.StatusForbidden {
			t.Fatalf("refusal %d: %d %s", i, rec.Code, rec.Body)
		}
		if got, want := sc.h.srv.relay.addrFailure.tokens(key, rateAddrFailure), rateAddrFailure.burst-float64(i+1); got != want {
			t.Fatalf("after %d refusals the bucket holds %v, want %v", i+1, got, want)
		}
	}
	// Empty: 429, with Retry-After, and the same answer whoever the
	// recipient is, registered or not, credential good or not.
	nobody, _ := identitytest.Hub()
	other := sc.h.issue(sc.recip, seal.CapClassContact, time.Hour)
	var first answer
	for i, rec := range []*httptest.ResponseRecorder{
		forged(),
		good(sc.recip, other),
		sc.h.send1(withCap(t, envelope(t, nobody.AID(), []byte("x")), other), ip),
	} {
		expectRefusal(t, rec, http.StatusTooManyRequests, "rate_limited")
		if i == 0 {
			first = answerOf(rec)
		} else if !answerOf(rec).same(first) {
			t.Errorf("the 429 of an empty address bucket depends on the request: %s vs %s", rec.Body, first.body)
		}
	}
	// Another address is not affected; an IPv6 /64 is one address.
	if rec := sc.h.send1(withCap(t, sc.env(), other), "198.51.100.78"); rec.Code != 200 {
		t.Fatalf("another address: %d %s", rec.Code, rec.Body)
	}
	const v6a, v6b = "2001:db8:1:2::a", "2001:db8:1:2:ffff::b"
	for i := 0; i < int(rateAddrFailure.burst); i++ {
		g := sc.contact
		_, g.holder, _ = ed25519.GenerateKey(nil)
		if rec := sc.h.send1(withCap(t, sc.env(), g), v6a); rec.Code != http.StatusForbidden {
			t.Fatalf("v6 refusal %d: %d", i, rec.Code)
		}
	}
	expectRefusal(t, sc.h.send1(withCap(t, sc.env(), sc.contact), v6b), http.StatusTooManyRequests, "rate_limited")
	// It refills at a token a second.
	sc.h.advance(2 * time.Second)
	if rec := good(sc.recip, other); rec.Code != 200 {
		t.Fatalf("after the bucket refilled: %d %s", rec.Code, rec.Body)
	}
	// A first contact is never limited by the address bucket.
	if rec := sc.h.send0(sc.ss, sc.env(), kind0Opts{ip: v6b}); rec.Code != 200 {
		t.Fatalf("a first contact from an address with no refusals left: %d %s", rec.Code, rec.Body)
	}
}

// TestKind1WithSessionHeadersIsRefused (CORE-K15, M33): a send under a
// credential that also carries session headers is refused 400 bad_request,
// even with a valid session and MAC, and nothing is queued.
func TestKind1WithSessionHeadersIsRefused(t *testing.T) {
	sc := newScene(t)
	env := withCap(t, sc.env(), sc.contact)
	req := sc.h.kind0Request(sc.ss, env, kind0Opts{})
	req.Header.Set(HeaderAccess, kind1Request(t, env).Header.Get(HeaderAccess))
	expectRefusal(t, sc.h.serve(req, relayClientIP), http.StatusBadRequest, "bad_request")
	for _, h := range []string{relayauth.HeaderSession, relayauth.HeaderMAC} {
		req := kind1Request(t, env)
		req.Header.Set(h, "AAAAAAAAAAAAAAAAAAAAAA")
		expectRefusal(t, sc.h.serve(req, relayClientIP), http.StatusBadRequest, "bad_request")
	}
	if n := sc.h.rows(sc.recip.aid); n != 0 {
		t.Fatalf("%d rows queued", n)
	}
	// The control: the same envelope without the session headers.
	if got := decodeSent(t, sc.h.send1(env, "")); got.Status != RelayQueued {
		t.Fatalf("the control: %+v", got)
	}
}

// SI-10: the same envelope sent a hundred times at once for one recipient is
// one row, and every sender is told its rid.
func TestConcurrentSendsOfOneEnvelopeShareOneRow(t *testing.T) {
	sc := newScene(t)
	env := withCap(t, sc.env(), sc.contact)
	const n = 100
	rids := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := sc.h.send1(env, "")
			if rec.Code != 200 {
				t.Errorf("send %d: %d %s", i, rec.Code, rec.Body)
				return
			}
			rids[i] = decodeSent(t, rec).RID
		}(i)
	}
	wg.Wait()
	if rows := sc.h.rows(sc.recip.aid); rows != 1 {
		t.Fatalf("%d rows, want 1", rows)
	}
	for i := 1; i < n; i++ {
		if rids[i] != rids[0] {
			t.Fatalf("send %d was told %s, send 0 %s", i, rids[i], rids[0])
		}
	}
	// One send's token: the duplicates gave theirs back.
	if got := sc.h.srv.relay.caps.tokens(capKey(&sc.contact.body), rateContactCap); got != rateContactCap.burst-1 {
		t.Errorf("the credential's bucket holds %v, want %v", got, rateContactCap.burst-1)
	}
}

// SI-10, SSR-H2: a copy that passed step 7 while the first was still being
// queued finds the first one's row in the queueing transaction. It is
// answered duplicate with that rid, and gives back the token it took at
// step 8.
func TestARacedDuplicateGivesItsTokenBack(t *testing.T) {
	sc := newScene(t)
	env := withCap(t, sc.env(), sc.contact)
	key := capKey(&sc.contact.body)
	inTx, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	enqueueFault = func() error {
		once.Do(func() { close(inTx); <-release })
		return nil
	}
	defer func() { enqueueFault = nil }()
	first, second := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- sc.h.send1(env, "") }()
	<-inTx
	// The first holds its transaction open; the copy sees no row at step 7,
	// takes its token at step 8 and waits to queue.
	go func() { second <- sc.h.send1(env, "") }()
	for deadline := time.Now().Add(10 * time.Second); sc.h.srv.relay.caps.tokens(key, rateContactCap) > rateContactCap.burst-2; {
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("the copy never took its token")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	a, b := decodeSent(t, <-first), decodeSent(t, <-second)
	if a.Status != RelayQueued || b.Status != RelayDuplicate || b.RID != a.RID {
		t.Fatalf("first %+v, copy %+v; want queued, then duplicate with the same rid", a, b)
	}
	if got := sc.h.srv.relay.caps.tokens(key, rateContactCap); got != rateContactCap.burst-1 {
		t.Errorf("the credential's bucket holds %v, want %v: the copy kept its token", got, rateContactCap.burst-1)
	}
}
