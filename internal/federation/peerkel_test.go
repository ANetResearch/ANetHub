package federation

// [redteam:F34] Regression for the hubfed red-team PoC
// TestRedteamPeerKELPinsMismatchedKEL: peerKEL pinned a peer hub's KEL on
// the first fetch of /hub/identity after comparing only the "aid" string
// the peer served, never replaying the KEL. A peer (or anyone in the middle
// of an http:// endpoint on that first fetch) could have this hub pin, and
// publish under the peer's AID, somebody else's key history; every later
// check of the peer's signatures then failed against it, with no way back
// but editing the database. The KEL must now replay to the configured peer
// AID before it is pinned, and a pin written before that check is dropped
// when the service starts.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// peerIdentityServer answers /hub/identity with aid and the KEL that
// kel holds when the request arrives.
func peerIdentityServer(t *testing.T, aid string, kel *atomic.Pointer[[]byte]) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"aid":"` + aid + `","kel":"` + base64.StdEncoding.EncodeToString(*kel.Load()) + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func threeHubIdentities(t *testing.T) (self, peer, stranger *hubid.Identity) {
	t.Helper()
	var ids [3]*hubid.Identity
	for i := range ids {
		id, err := hubid.LoadOrIncept(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	if ids[1].AID == ids[2].AID {
		t.Fatal("peer and stranger AIDs collided")
	}
	return ids[0], ids[1], ids[2]
}

func pinnedPeerKELs(t *testing.T, svc *Service) int {
	t.Helper()
	var n int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM fed_peer_kel`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A peer serving its configured AID with another identity's KEL is not
// pinned; once it serves its own KEL, that one is.
func TestAPeerKELIsPinnedOnlyWhenItReplaysToThePeer(t *testing.T) {
	idSelf, idPeer, idStranger := threeHubIdentities(t)
	var served atomic.Pointer[[]byte]
	strangerKEL := idStranger.KEL
	served.Store(&strangerKEL)
	fake := peerIdentityServer(t, idPeer.AID, &served)

	svc, err := New(t.TempDir(),
		Config{Delivery: "allowlist", Peers: []Peer{{AID: idPeer.AID, Endpoint: fake.URL}}},
		idSelf, newFakeLocal())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	if kel, err := svc.PeerKEL(idPeer.AID); err == nil {
		states, _ := identity.Replay(kel)
		t.Fatalf("PeerKEL accepted a KEL that replays to %s for the peer %s",
			states[len(states)-1].AID, idPeer.AID)
	}
	if n := pinnedPeerKELs(t, svc); n != 0 {
		t.Fatalf("a KEL that does not prove the peer's AID was pinned (%d rows)", n)
	}

	peerKEL := idPeer.KEL
	served.Store(&peerKEL)
	kel, err := svc.PeerKEL(idPeer.AID)
	if err != nil {
		t.Fatalf("the peer's own KEL: %v", err)
	}
	states, err := identity.Replay(kel)
	if err != nil || states[len(states)-1].AID != idPeer.AID {
		t.Fatalf("pinned KEL replays to %v (%v), want %s", states, err, idPeer.AID)
	}
	if n := pinnedPeerKELs(t, svc); n != 1 {
		t.Fatalf("the peer's own KEL was not pinned (%d rows)", n)
	}
}

// A pin written before the check (another identity's KEL under the peer's
// AID) is dropped when the service opens, and the next use fetches and
// pins the peer's own KEL.
func TestAMisPinnedPeerKELIsDroppedWhenTheServiceOpens(t *testing.T) {
	idSelf, idPeer, idStranger := threeHubIdentities(t)
	var served atomic.Pointer[[]byte]
	peerKEL := idPeer.KEL
	served.Store(&peerKEL)
	fake := peerIdentityServer(t, idPeer.AID, &served)
	cfg := Config{Delivery: "allowlist", Peers: []Peer{{AID: idPeer.AID, Endpoint: fake.URL}}}
	dir := t.TempDir()

	svc, err := New(dir, cfg, idSelf, newFakeLocal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.db.Exec(`INSERT INTO fed_peer_kel (aid, kel, fetched_at) VALUES (?,?,0)`,
		idPeer.AID, idStranger.KEL); err != nil {
		t.Fatal(err)
	}
	svc.Close()

	svc, err = New(dir, cfg, idSelf, newFakeLocal())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if n := pinnedPeerKELs(t, svc); n != 0 {
		t.Fatalf("the mis-pinned KEL survived reopening (%d rows)", n)
	}
	kel, err := svc.PeerKEL(idPeer.AID)
	if err != nil {
		t.Fatal(err)
	}
	if states, err := identity.Replay(kel); err != nil || states[len(states)-1].AID != idPeer.AID {
		t.Fatalf("after reopening, PeerKEL replays to %v (%v), want %s", states, err, idPeer.AID)
	}
}
