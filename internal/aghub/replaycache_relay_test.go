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
		req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
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

// [redteam:F4] Review of the fix: the replay cache is shared out by signer,
// and a signer is whoever passes the signature check, which /register makes
// against the KEL it is handed. A stranger the hub would not take passed it
// with a fresh AID on every attempt, was then refused 403, and left a signer
// in the cache each time: signers the stranger could never have joined as,
// each lowering everyone's even share. The admission gate (PAY-A1 step 4)
// refuses a newcomer the hub would not take before its signature is
// checked: on a closed hub one that is not on the list, on an open hub one
// without a good proof of work. Neither leaves anything in the cache.
func TestAStrangerAtAClosedHubLeavesNothingInTheReplayCache(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	s := NewServer(store)
	s.SetHubAID(id.AID)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	register := func(c *identity.Controller, extra map[string]any, ip string) (int, string) {
		kel, _ := identity.MarshalKEL(c.KEL())
		body := map[string]any{"aid": c.AID(), "name": "n", "kel": base64.RawURLEncoding.EncodeToString(kel)}
		for k, v := range extra {
			body[k] = v
		}
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/register", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
		req.Header.Set("X-Real-IP", ip)
		ts := uint64(time.Now().UnixMilli())
		sig, seq := c.Sign(relayauth.PreimageV2(relayauth.ActionRegister, c.AID(), id.AID, ts, req.Method, req.URL.RequestURI(), raw))
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
		return resp.StatusCode, string(b)
	}
	badPow := map[string]any{"pow": map[string]any{
		"seed": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "nonce": "AA"}}
	for _, mode := range []string{AdmissionClosed, AdmissionOpen} {
		if err := store.SetAdmissionMode(mode); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			c, err := identity.Incept()
			if err != nil {
				t.Fatal(err)
			}
			for _, extra := range []map[string]any{nil, badPow} {
				if code, b := register(c, extra, "198.51.100."+strconv.Itoa(i)); code != http.StatusForbidden {
					t.Fatalf("%s hub, a stranger registering with %v: %d %s", mode, extra, code, b)
				}
			}
		}
	}
	if entries, signers := s.replay.size(); entries != 0 || signers != 0 {
		t.Fatalf("80 refused registrations left %d entries of %d signers in the replay cache", entries, signers)
	}

	// An admitted newcomer registers, and its signature is kept.
	c, _ := identity.Incept()
	if _, err := store.Admit(c.AID(), 0, "", false); err != nil {
		t.Fatal(err)
	}
	if code, b := register(c, nil, "203.0.113.1"); code != http.StatusOK {
		t.Fatalf("an admitted newcomer: %d %s", code, b)
	}
	if entries, signers := s.replay.size(); entries != 1 || signers != 1 {
		t.Fatalf("the admitted registration left %d entries of %d signers, want 1 and 1", entries, signers)
	}
}
