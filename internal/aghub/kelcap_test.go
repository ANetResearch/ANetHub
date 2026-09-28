package aghub_test

// [redteam:F36] Regression for the dos red-team PoC
// TestRedteamHubKELReplayAmplification: the hub stored any KEL that fitted
// the 1 MiB /register body (about 2,900 events), and the unauthenticated
// GET /agents/{aid}/jwks.json replayed all of it on every request, one
// Ed25519 verification per event — a small GET cost the hub 100x the CPU
// of a normal agent's. /register now applies the caps every sender applies
// to a KEL it is handed (seal.MaxKELEvents, seal.MaxKELBytes), key-set
// reads and writes refuse a key history stored before those caps, and the
// JWKS is cached by the hash of the stored KEL (kelcap_internal_test.go).

import (
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"
)

// bigKELController builds a valid KEL (icp + drt events, all self-signed;
// drt does not change the signing key) whose CoreDet encoding reaches at
// least targetBytes. An attacker mints these offline: each event is one
// cheap signature. Size is sampled every 16 events to keep the builder
// linear rather than re-marshalling the whole KEL each step.
func bigKELController(t *testing.T, targetBytes int) *identity.Controller {
	t.Helper()
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	for {
		for i := 0; i < 16; i++ {
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

// A KEL past the message-path cap is refused at /register, so nothing
// unauthenticated can be made to replay it; a KEL under the cap, with
// many events, is still accepted.
func TestARegistrationWithAKELPastTheMessagePathCapIsRefused(t *testing.T) {
	srv := newHub(t)

	attacker := bigKELController(t, seal.MaxKELBytes+1)
	kelB, _ := identity.MarshalKEL(attacker.KEL())
	if len(kelB) <= seal.MaxKELBytes {
		t.Fatalf("test did not build a KEL past the cap: %d bytes", len(kelB))
	}
	code, b := registerWithCard(t, srv, attacker, "big", nil, nil)
	if code != http.StatusBadRequest || !strings.Contains(string(b), "kel too long") {
		t.Fatalf("register with a %d-event, %d-byte KEL: %d %s, want 400 kel too long",
			len(attacker.KEL()), len(kelB), code, b)
	}
	if code, _ := getJSON(t, srv.URL+"/agents/"+attacker.AID()+"/jwks.json"); code != http.StatusNotFound {
		t.Fatalf("the refused agent's JWKS: %d, want 404 (not registered)", code)
	}

	// Under the cap, a long KEL registers and its JWKS is served.
	long := bigKELController(t, seal.MaxKELBytes/2)
	registerLegacy(t, srv, long, "long", nil)
	if code, b := getJSON(t, srv.URL+"/agents/"+long.AID()+"/jwks.json"); code != http.StatusOK {
		t.Fatalf("JWKS of a KEL under the cap: %d %s", code, b)
	}
}

// A key history stored before /register capped it (a hub upgraded in
// place) is neither served nor used: GET keys and the JWKS answer 404, a
// new key set is refused, and nothing replays it on an unauthenticated
// read.
func TestAKeyHistoryStoredBeforeTheCapIsNotServed(t *testing.T) {
	srv, store := newHubWithStore(t)
	legacy := bigKELController(t, seal.MaxKELBytes+1)
	kelB, _ := identity.MarshalKEL(legacy.KEL())
	if err := store.PutAgent(legacy.AID(), "legacy", nil, kelB); err != nil {
		t.Fatal(err)
	}
	raw, _ := mintKeySet(t, legacy, uint64(time.Now().UnixMilli()))
	if _, err := store.PublishKeys(legacy.AID(), raw, legacy.KEL(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, b := getJSON(t, srv.URL+"/agents/"+legacy.AID()+"/jwks.json"); code != http.StatusNotFound {
		t.Fatalf("JWKS of a stored KEL past the cap: %d %s, want 404", code, b)
	}
	if code, b := getJSON(t, srv.URL+"/agents/"+legacy.AID()+"/keys"); code != http.StatusNotFound {
		t.Fatalf("keys of an agent whose stored KEL is past the cap: %d %s, want 404", code, b)
	}
	raw2, _ := mintKeySet(t, legacy, uint64(time.Now().UnixMilli())+1)
	if code, b := publishKeys(t, srv, legacy, raw2); code != http.StatusBadRequest {
		t.Fatalf("publishing keys against a stored KEL past the cap: %d %s, want 400", code, b)
	}
}
