package federation

import (
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"
)

// A /fed/v2/keys request signed outside the ±MaxSkew window is refused,
// in both directions, and the same request signed now is answered.
func TestAKeyLookupOutsideTheSkewWindowIsRefused(t *testing.T) {
	r := newRig(t)
	r.bKeys.sets["aid:bob"] = [2][]byte{[]byte("ks"), []byte("kel")}
	at := func(when time.Time) int {
		req, _ := http.NewRequest(http.MethodGet, r.bSrv.URL+"/fed/v2/keys/aid:bob", nil)
		ts := uint64(when.UnixMilli())
		sig, seq := r.aid.Sign(relayauth.PreimageV2(actionFedKeys, r.aid.AID, r.bid.AID, ts,
			http.MethodGet, req.URL.RequestURI(), nil))
		req.Header.Set(relayauth.HeaderAID, r.aid.AID)
		req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
		req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
		req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	skew := time.Duration(relayauth.MaxSkewMillis) * time.Millisecond
	if code := at(time.Now().Add(-skew - time.Minute)); code != http.StatusUnauthorized {
		t.Errorf("signed before the window: %d, want 401", code)
	}
	if code := at(time.Now().Add(skew + time.Minute)); code != http.StatusUnauthorized {
		t.Errorf("signed after the window: %d, want 401", code)
	}
	if code := at(time.Now()); code != http.StatusOK {
		t.Fatalf("control: signed now: %d, want 200", code)
	}
}

// The replay set is bounded: when it is full of live entries a new
// signature is refused as busy rather than an entry evicted, a repeated
// signature is still refused as a replay, and an expired entry frees its
// place at the next sweep, which runs at most once a second.
func TestTheKeyLookupReplaySetIsBounded(t *testing.T) {
	g := newReplayGuard()
	g.max = 2
	now := int64(1_000_000)
	if err := g.admit("hub-a", []byte("sig-1"), now+10, now); err != nil {
		t.Fatal(err)
	}
	if err := g.admit("hub-a", []byte("sig-2"), now+1000, now); err != nil {
		t.Fatal(err)
	}
	if err := g.admit("hub-a", []byte("sig-3"), now+1000, now); !errors.Is(err, errReplayGuardFull) {
		t.Fatalf("a third signature into a full set: %v, want errReplayGuardFull", err)
	}
	if err := g.admit("hub-a", []byte("sig-2"), now+1000, now); !errors.Is(err, errRequestReplayed) {
		t.Fatalf("a repeated signature: %v, want errRequestReplayed", err)
	}
	// sig-1's window has ended, but the last sweep was less than a second
	// ago, so the set is not walked again yet.
	if err := g.admit("hub-a", []byte("sig-3"), now+2000, now+11); !errors.Is(err, errReplayGuardFull) {
		t.Fatalf("within a second of the last sweep: %v, want errReplayGuardFull", err)
	}
	// A second later the sweep runs and sig-1's place is reused.
	if err := g.admit("hub-a", []byte("sig-3"), now+3000, now+1001); err != nil {
		t.Fatalf("after the next sweep: %v", err)
	}
}

// A forwarded envelope is held to the same exact size limit as one sent
// by a local agent. The forward body cap leaves room for the JSON around
// the payload, so the payload itself is checked after decoding.
func TestAForwardedEnvelopeOverTheLimitIsRefused(t *testing.T) {
	r := newRig(t)
	within := fedEnv(t, "aid:bob", "fits")
	r.b.SetMaxEnvelope(int64(len(within)))
	if code, out := postRaw(t, r, signedEnvelope(t, r, func(e *Envelope, p []byte) []byte { return within })); code != http.StatusAccepted {
		t.Fatalf("an envelope at the limit: %d %v", code, out)
	}
	over := fedEnv(t, "aid:bob", "one byte more than fits")
	code, out := postRaw(t, r, signedEnvelope(t, r, func(e *Envelope, p []byte) []byte { return over }))
	if code != http.StatusRequestEntityTooLarge || out["error"] != "TOO_LARGE" {
		t.Fatalf("an envelope over the limit: %d %v, want 413 TOO_LARGE", code, out)
	}
	if got := r.bLocal.delivered(); len(got) != 1 {
		t.Fatalf("%d envelopes enqueued, want only the one within the limit", len(got))
	}
}
