package federation

// Red-team (lens=hubfed): peerKEL pins a peer hub's KEL on first fetch of
// /hub/identity without verifying the KEL actually replays to the
// configured peer AID. It only checks the self-reported "aid" JSON field.
//
// Every other KEL ingestion point in the tree verifies replay->AID at the
// point of ingestion (aghub.hRegister via aidFromKEL, daemon
// fetchRecipientKeys via mergeKEL/VerifyEncKeySet, aghub.AdmitFedCard and
// AdmitFedA2ACard via identity.Replay + subject check, reputation
// kelMatches). federation.Service.peerKEL does not: it trusts the served
// "aid" string and stores whatever KEL bytes came with it.
//
// This test stands up a fake peer server whose /hub/identity claims to be
// the configured peer AID but serves a DIFFERENT identity's KEL. The hub
// pins and returns it. The test asserts the attack succeeded: PeerKEL
// returns a KEL that does NOT belong to the configured peer.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

func TestRedteamPeerKELPinsMismatchedKEL(t *testing.T) {
	// The hub running the federation service.
	idSelf, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The identity this hub is CONFIGURED to peer with.
	idVictim, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A third, unrelated identity whose KEL the fake peer will serve while
	// claiming to be idVictim.
	idStranger, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if idVictim.AID == idStranger.AID {
		t.Fatal("victim and stranger AIDs collided; regenerate")
	}

	// The fake peer server: /hub/identity claims to be the victim AID but
	// hands back the stranger's KEL bytes.
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		strangerKEL := base64.StdEncoding.EncodeToString(idStranger.KEL)
		_, _ = w.Write([]byte(`{"aid":"` + idVictim.AID + `","kel":"` + strangerKEL + `"}`))
	}))
	defer fake.Close()

	svc, err := New(t.TempDir(),
		Config{Delivery: "allowlist", Peers: []Peer{{AID: idVictim.AID, Endpoint: fake.URL}}},
		idSelf, newFakeLocal())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	kel, err := svc.PeerKEL(idVictim.AID)
	if err != nil {
		t.Fatalf("PeerKEL returned an error (the guard would have caught the mismatch): %v", err)
	}
	states, err := identity.Replay(kel)
	if err != nil {
		t.Fatalf("pinned KEL does not replay: %v", err)
	}
	got := states[len(states)-1].AID

	// Attack success: the hub pinned, and now serves as the configured
	// peer's key history, a KEL that belongs to somebody else. Nothing at
	// ingestion checked that the served KEL replays to the peer AID.
	if got == idVictim.AID {
		t.Fatalf("no defect: the pinned KEL belongs to the configured peer %s", idVictim.AID)
	}
	if got != idStranger.AID {
		t.Fatalf("unexpected: pinned KEL replays to %s, want the stranger %s", got, idStranger.AID)
	}
	t.Logf("DEFECT CONFIRMED: PeerKEL(%s) returned a KEL that replays to %s; "+
		"peerKEL pinned it on the served \"aid\" field alone, with no replay->AID check",
		idVictim.AID, got)
}
