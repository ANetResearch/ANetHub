package aghub

// [redteam:F4] Regression for the si2 red-team PoC
// TestRedteamX1_OneRegisteredAgentFillsTheReplayCacheAndStopsEveryonesRelay:
// one registered AID signing polls with timestamps far in the future kept
// the global relayauth v2 replay cache full, and the hub answered every
// other agent's /relay/send and /relay/poll with 503. The cache is now
// bounded per signer, and at its global bound refuses only signers holding
// an even share, so the attacker stops only itself.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// Scaled: the global bound is 64 and one signer's share 16 (the mechanism
// is the production one; only the constants differ). Four attacker AIDs
// fill the whole cache with future-dated polls, the first of them also
// tries to go past its share; an unrelated agent's /relay/send and a third
// agent's /relay/poll are still served.
func TestOneRegisteredAgentFillingTheReplayCacheStopsOnlyItself(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(store)
	s.SetHubAID(id.AID)
	const scaledMax, scaledPerSigner = 64, 16
	s.replay = newReplayCache(scaledMax, scaledPerSigner)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	mk := func() *identity.Controller {
		c, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		kel, _ := identity.MarshalKEL(c.KEL())
		if err := store.PutAgent(c.AID(), "n", nil, kel); err != nil {
			t.Fatal(err)
		}
		return c
	}
	attackers := []*identity.Controller{mk(), mk(), mk(), mk()}
	victim, recip := mk(), mk()

	do := func(c *identity.Controller, action, path string, body any, at time.Time) (int, string, http.Header) {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ANet-Wire", "2")
		ts := uint64(at.UnixMilli())
		sig, seq := c.Sign(relayauth.PreimageV2(action, c.AID(), id.AID, ts, req.Method, req.URL.RequestURI(), raw))
		req.Header.Set(relayauth.HeaderAID, c.AID())
		req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
		req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
		req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}

	// Each poll is a fresh signature 4m50s in the future, inside the skew
	// window, so each entry would live about 10 minutes.
	future := time.Now().Add(4*time.Minute + 50*time.Second)
	n := 0
	for a, c := range attackers {
		for i := 0; i < scaledPerSigner; i++ {
			n++
			if code, b, _ := do(c, relayauth.ActionPoll, "/relay/poll",
				map[string]any{"limit": 1 + i}, future.Add(time.Duration(n)*time.Millisecond)); code != 200 {
				t.Fatalf("attacker %d poll %d: %d %s", a, i, code, b)
			}
		}
	}
	if entries, _ := s.replay.size(); entries != scaledMax {
		t.Fatalf("the attackers hold %d entries, want the whole cache (%d)", entries, scaledMax)
	}
	// Past its share an attacker is refused, and told when to come back.
	code, b, h := do(attackers[0], relayauth.ActionPoll, "/relay/poll",
		map[string]any{"limit": 99}, future.Add(time.Second))
	if code != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
		t.Fatalf("attacker past its share: %d %s (Retry-After %q), want 429 with Retry-After",
			code, b, h.Get("Retry-After"))
	}

	env := &seal.SealedEnvelope{V: seal.EnvelopeVersion, To: recip.AID(), Suite: seal.SuiteX25519,
		KID: bytes.Repeat([]byte{7}, seal.KIDLen), Enc: bytes.Repeat([]byte{9}, 32), CT: []byte("ct")}
	envB, _ := env.Marshal()
	if code, b, _ := do(victim, relayauth.ActionSend, "/relay/send",
		map[string]any{"to_aid": recip.AID(), "envelope": base64.StdEncoding.EncodeToString(envB)}, time.Now()); code != 200 {
		t.Fatalf("victim send into a cache the attackers filled: %d %s", code, b)
	}
	if code, b, _ := do(recip, relayauth.ActionPoll, "/relay/poll", map[string]any{}, time.Now()); code != 200 ||
		!bytes.Contains([]byte(b), []byte(`"id":`)) {
		t.Fatalf("recipient poll into a cache the attackers filled: %d %s", code, b)
	}
}
