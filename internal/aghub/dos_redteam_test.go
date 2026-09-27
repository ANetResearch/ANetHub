package aghub_test

// dos_redteam_test.go — adversarial review, lens=dos (A2A-DESIGN §20 F).
//
// Finding: the hub applies no bound on the number of KEL events it accepts
// and stores for an agent, other than the 1 MiB /register body cap. The
// message path bounds a carried KEL to seal.MaxKELEvents (256) / MaxKELBytes
// (64 KiB) precisely because "a KEL is replayed on every receive, one
// Ed25519 verification per event" (§3.1). The hub has no analogue: a single
// registered AID can store a KEL of ~2,900 events (under 1 MiB), and the
// UNAUTHENTICATED endpoint GET /agents/{aid}/jwks.json replays that whole
// KEL on every request (a2acard.JWKS -> identity.Replay), turning a tiny
// unauthenticated GET into hundreds of milliseconds of hub CPU. Nothing in
// front caches it (deploy/nginx-hub.conf has no proxy_cache), and the ETag
// only helps a caller who cooperates with If-None-Match.

import (
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"
)

// bigKELController builds a valid KEL (icp + drt events, all self-signed;
// drt does not change the signing key) whose CoreDet encoding reaches at
// least targetBytes. An attacker mints these offline: each event is one
// cheap signature. Size is sampled every 64 events to keep the builder
// linear rather than re-marshalling the whole KEL each step.
func bigKELController(t *testing.T, targetBytes int) *identity.Controller {
	t.Helper()
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	for {
		for i := 0; i < 64; i++ {
			if err := c.Delegate(pub, 1); err != nil {
				t.Fatal(err)
			}
		}
		b, err := identity.MarshalKEL(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		if len(b) >= targetBytes {
			return c
		}
	}
}

func jwksDuration(t *testing.T, url string) (int, time.Duration) {
	t.Helper()
	st := time.Now()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode, time.Since(st)
}

// TestRedteamHubKELReplayAmplification asserts the attack succeeds: the hub
// accepts and stores a KEL far past the message-path cap, and serves it
// (replaying every event) on an unauthenticated GET. The assertion "attack
// succeeded == defect exists": register(200) with events > seal.MaxKELEvents
// and bytes > seal.MaxKELBytes, and the unauthenticated jwks call costs far
// more than a one-event agent's (linear in the attacker-chosen KEL length).
func TestRedteamHubKELReplayAmplification(t *testing.T) {
	srv := newHub(t)

	// Comfortably past the message-path cap while keeping the builder quick;
	// still under maxRegisterBody = 1<<20 (base64(kel) ~= 4/3 * kel bytes).
	attacker := bigKELController(t, 300<<10)
	bigKEL := attacker.KEL()
	kelB, _ := identity.MarshalKEL(bigKEL)
	t.Logf("attacker KEL: %d events, %d bytes (message-path caps: %d events / %d bytes)",
		len(bigKEL), len(kelB), seal.MaxKELEvents, seal.MaxKELBytes)

	// The hub accepts the oversized KEL: no event/byte cap on this path.
	registerLegacy(t, srv, attacker, "big", nil)

	if len(bigKEL) <= seal.MaxKELEvents || len(kelB) <= seal.MaxKELBytes {
		t.Fatalf("test did not build a KEL past the message-path cap")
	}

	// A one-event agent for the baseline.
	small, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	registerLegacy(t, srv, small, "small", nil)

	// Warm both (build+cache path), then measure fresh (no If-None-Match).
	code, _ := jwksDuration(t, srv.URL+"/agents/"+small.AID()+"/jwks.json")
	if code != http.StatusOK {
		t.Fatalf("small jwks: %d", code)
	}
	code, _ = jwksDuration(t, srv.URL+"/agents/"+attacker.AID()+"/jwks.json")
	if code != http.StatusOK {
		t.Fatalf("attacker jwks: %d", code)
	}

	const n = 5
	var small5, big5 time.Duration
	for i := 0; i < n; i++ {
		_, d := jwksDuration(t, srv.URL+"/agents/"+small.AID()+"/jwks.json")
		small5 += d
		_, d = jwksDuration(t, srv.URL+"/agents/"+attacker.AID()+"/jwks.json")
		big5 += d
	}
	ratio := float64(big5) / float64(small5)
	t.Logf("unauthenticated GET /jwks.json avg: small=%v big=%v => %.1fx CPU per request",
		small5/n, big5/n, ratio)

	// Attack succeeded: one small unauthenticated GET costs many times the
	// CPU of a normal agent's, scaling with the attacker-chosen KEL length,
	// with no cap and no cache in front. 5x is a conservative floor for a
	// ~2,900-event KEL against a 1-event one (observed ~50x+).
	if ratio < 5 {
		t.Fatalf("expected the oversized-KEL jwks to cost >=5x a small one; got %.1fx", ratio)
	}
}
