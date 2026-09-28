package aghub_test

// [redteam:F36] Review of the fix: /register now caps a KEL at
// seal.MaxKELEvents / seal.MaxKELBytes and the JWKS is cached, but every
// other route that checks a signature against a KEL the hub holds still
// replayed it on each request, one Ed25519 verification per event, before
// looking at the signature. An unauthenticated POST /relay/poll naming an
// agent with a KEL at the cap and carrying a signature of zeros cost the
// hub the whole replay (some 40 ms, twenty-odd times a one-event agent's)
// and was answered 401; so did /x402/verify, /reviews and the taskboard
// challenge. The process now replays each KEL once (identity.ReplayCache,
// installed by Open), and a signature is checked against the key the KEL
// names before the KEL is replayed (kelreplay.go).

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// countReplays installs a replay cache that holds nothing, so that its
// misses count every KEL replay in the process, and puts back the one Open
// installed when the test ends.
func countReplays(t *testing.T) *identity.ReplayCache {
	t.Helper()
	c := identity.NewReplayCache(0)
	prev := identity.SetReplayCache(c)
	t.Cleanup(func() { identity.SetReplayCache(prev) })
	return c
}

func replays(c *identity.ReplayCache) uint64 {
	_, misses := c.Stats()
	return misses
}

// putAgent stores c as registered, the way /register leaves it, without
// the replays /register makes.
func putAgent(t *testing.T, store *aghub.Store, c *identity.Controller) {
	t.Helper()
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(c.AID(), "n", nil, kel); err != nil {
		t.Fatal(err)
	}
}

func flipped(sig []byte) []byte {
	out := append([]byte(nil), sig...)
	out[0] ^= 1
	return out
}

// A request whose signature is no good is refused without the hub
// replaying the KEL it names, on each route that checks a signature
// against a KEL the hub holds and answers strangers; a good signature is
// still verified against the replayed KEL.
func TestABadSignatureDoesNotReplayTheKELItNames(t *testing.T) {
	srv, store := newHubWithStore(t)
	hub := hubAIDOf(t, srv)
	long := bigKELController(t, seal.MaxKELBytes/2)
	long2 := bigKELController(t, seal.MaxKELBytes/2)
	payee, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*identity.Controller{long, long2, payee} {
		putAgent(t, store, c)
	}
	counter := countReplays(t)

	t.Run("relay poll", func(t *testing.T) {
		raw := []byte(`{}`)
		req := newRequest(t, srv, http.MethodPost, "/relay/poll", raw)
		signV2(t, req, long, relayauth.ActionPoll, hub, raw, time.Now())
		sig, _ := relayauth.DecodeSig(req.Header.Get(relayauth.HeaderSig))
		req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(flipped(sig)))
		before := replays(counter)
		if code, b, _ := send(t, req); code != http.StatusUnauthorized {
			t.Fatalf("poll with a bad signature: %d %s", code, b)
		}
		if n := replays(counter) - before; n != 0 {
			t.Fatalf("a poll with a bad signature replayed %d KELs", n)
		}
		before = replays(counter)
		if code, b := signedDo(t, srv, long, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{}); code != 200 {
			t.Fatalf("poll with a good signature: %d %s", code, b)
		}
		if replays(counter) == before {
			t.Fatal("a good signature was accepted without the KEL being replayed")
		}
	})

	t.Run("x402 verify", func(t *testing.T) {
		a := signedAuth(t, long, payee.AID(), 5, hub, "ix-bad-sig")
		a.Envelope.Sig = flipped(a.Envelope.Sig)
		own := payment.CreditNetwork(hub)
		before := replays(counter)
		_, vr := verifyCall(t, srv, creditPayload(t, a, payee.AID(), own), requirementsFor(payee.AID(), 5, own))
		if vr.IsValid || vr.InvalidReason != payment.ReasonInvalidSignature {
			t.Fatalf("an authorization with a bad signature: %+v", vr)
		}
		if n := replays(counter) - before; n != 0 {
			t.Fatalf("/x402/verify of a bad signature replayed %d KELs", n)
		}
	})

	t.Run("review upload", func(t *testing.T) {
		reqCID, _ := anetcid.Sum([]byte("request"))
		resCID, _ := anetcid.Sum([]byte("result"))
		for i, bad := range []string{"receipt", "review"} {
			ix := "ix-bad-" + strconv.Itoa(i)
			rc := &evidence.Receipt{InteractionID: ix, RequesterAID: long2.AID(), ProviderAID: long.AID(),
				RequestCID: reqCID, ResultCID: resCID, CompletedAt: 1000}
			if err := rc.Sign(long); err != nil {
				t.Fatal(err)
			}
			rcid, _ := rc.CID()
			rv := &evidence.Review{InteractionID: ix, SubjectAID: long.AID(), ReviewerAID: long2.AID(),
				Rating: 5, ReceiptCID: rcid, CreatedAt: 2000}
			if err := rv.Sign(long2); err != nil {
				t.Fatal(err)
			}
			if bad == "receipt" {
				rc.Envelope.Sig = flipped(rc.Envelope.Sig)
			} else {
				rv.Envelope.Sig = flipped(rv.Envelope.Sig)
			}
			rcB, _ := rc.Marshal()
			rvB, _ := rv.Marshal()
			before := replays(counter)
			code, b := post(t, srv.URL+"/reviews", map[string]string{
				"receipt": base64.StdEncoding.EncodeToString(rcB), "review": base64.StdEncoding.EncodeToString(rvB)})
			if code != http.StatusBadRequest {
				t.Fatalf("a review whose %s signature is bad: %d %s", bad, code, b)
			}
			if n := replays(counter) - before; n != 0 {
				t.Fatalf("a review whose %s signature is bad replayed %d KELs", bad, n)
			}
		}
	})

	t.Run("taskboard challenge", func(t *testing.T) {
		ts := uint64(time.Now().UnixMilli())
		sig, seq := long.Sign(relayauth.Preimage("task.create", long.AID(), ts))
		before := replays(counter)
		if err := store.VerifyAgentChallenge("task.create", long.AID(), ts, seq,
			base64.StdEncoding.EncodeToString(flipped(sig))); err == nil {
			t.Fatal("a challenge with a bad signature verified")
		}
		if n := replays(counter) - before; n != 0 {
			t.Fatalf("a challenge with a bad signature replayed %d KELs", n)
		}
		if err := store.VerifyAgentChallenge("task.create", long.AID(), ts, seq,
			base64.StdEncoding.EncodeToString(sig)); err != nil {
			t.Fatalf("a good challenge: %v", err)
		}
	})
}

// A process with a hub store replays each KEL once: Open installs a replay
// cache, and a signer's requests after its first are checked against the
// KEL it replayed to then.
func TestAStoredKELIsReplayedOnceNotOnEveryRequest(t *testing.T) {
	srv, store := newHubWithStore(t)
	if installed := identity.SetReplayCache(nil); installed == nil {
		t.Fatal("opening a hub store installed no replay cache")
	} else {
		identity.SetReplayCache(installed)
	}
	long := bigKELController(t, seal.MaxKELBytes/2)
	putAgent(t, store, long)
	c := identity.NewReplayCache(1 << 20)
	prev := identity.SetReplayCache(c)
	t.Cleanup(func() { identity.SetReplayCache(prev) })
	for i := 0; i < 10; i++ {
		if code, b := signedDo(t, srv, long, relayauth.ActionPoll, http.MethodPost, "/relay/poll",
			map[string]any{"limit": 1 + i}); code != 200 {
			t.Fatalf("poll %d: %d %s", i, code, b)
		}
	}
	if hits, misses := c.Stats(); misses != 1 || hits < 9 {
		t.Fatalf("10 signed polls: %d replays, %d answered from the cache; want 1 and at least 9", misses, hits)
	}
}
