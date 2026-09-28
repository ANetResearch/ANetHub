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
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	// The failed fetch holds the next one off for peerKELRetry
	// (TestAPeerKELThatFailsIsNotFetchedOnEveryUse); let that pass.
	svc.kelFetches[idPeer.AID].refused = time.Now().Add(-peerKELRetry)
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

// A peer KEL that is not pinned used to be fetched again on every use, and
// a use can be an unauthenticated GET /agents/{peer}/kel on the kernel: a
// peer serving a KEL that does not prove its AID turned each such request
// into an outbound fetch and a replay of whatever the peer served. The
// fetches of one peer's KEL are now made one at a time, the next one waits
// peerKELRetry after the peer served such a KEL, and a KEL that is
// somebody else's is refused on its inception, before the rest of it is
// replayed [redteam:F34].
func TestAPeerKELThatFailsIsNotFetchedOnEveryUse(t *testing.T) {
	idSelf, idPeer, _ := threeHubIdentities(t)
	stranger, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		if err := stranger.Rotate(uint64(i + 1)); err != nil {
			t.Fatal(err)
		}
	}
	strangerKEL, _ := identity.MarshalKEL(stranger.KEL())
	var served atomic.Pointer[[]byte]
	served.Store(&strangerKEL)
	var fetches atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		_, _ = w.Write([]byte(`{"aid":"` + idPeer.AID + `","kel":"` + base64.StdEncoding.EncodeToString(*served.Load()) + `"}`))
	}))
	defer fake.Close()
	svc, err := New(t.TempDir(),
		Config{Delivery: "allowlist", Peers: []Peer{{AID: idPeer.AID, Endpoint: fake.URL}}},
		idSelf, newFakeLocal())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	counter := identity.NewReplayCache(0) // holds nothing: its misses count every replay
	prev := identity.SetReplayCache(counter)
	defer identity.SetReplayCache(prev)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.PeerKEL(idPeer.AID); err == nil {
				t.Error("a KEL that does not prove the peer's AID was accepted")
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 20; i++ {
		if _, err := svc.PeerKEL(idPeer.AID); err == nil {
			t.Fatal("a KEL that does not prove the peer's AID was accepted")
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("40 uses of a peer whose KEL failed to pin fetched it %d times, want 1", n)
	}
	if _, misses := counter.Stats(); misses != 1 {
		t.Fatalf("refusing a 31-event KEL of somebody else replayed %d times, want 1 (its inception)", misses)
	}

	// After the wait, the next use fetches again, and the peer's own KEL
	// is pinned.
	peerKEL := idPeer.KEL
	served.Store(&peerKEL)
	svc.kelFetches[idPeer.AID].refused = time.Now().Add(-peerKELRetry)
	if _, err := svc.PeerKEL(idPeer.AID); err != nil {
		t.Fatalf("after the retry wait: %v", err)
	}
	if n := pinnedPeerKELs(t, svc); n != 1 || fetches.Load() != 2 {
		t.Fatalf("after the retry wait: %d pinned, %d fetches; want 1 and 2", n, fetches.Load())
	}
}

// A pinned peer KEL whose key is not 32 bytes (a pin written before peerKEL
// replayed what it pinned) does not stop the service from opening: the
// replay at open refuses it, rather than panicking in ed25519.Verify
// (ANetCore identity.Replay), and it is dropped [redteam:F34].
func TestAPinnedPeerKELWithAMalformedKeyIsDroppedNotAPanic(t *testing.T) {
	idSelf, idPeer, _ := threeHubIdentities(t)
	short := []identity.SignedEvent{{Event: identity.KeyEvent{Type: identity.Inception,
		Keys: [][]byte{make([]byte, 31)}, Threshold: 1}, Sig: make([]byte, 64)}}
	blob, err := identity.MarshalKEL(short)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Delivery: "allowlist", Peers: []Peer{{AID: idPeer.AID, Endpoint: "http://127.0.0.1:1"}}}
	dir := t.TempDir()
	svc, err := New(dir, cfg, idSelf, newFakeLocal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.db.Exec(`INSERT INTO fed_peer_kel (aid, kel, fetched_at) VALUES (?,?,0)`, idPeer.AID, blob); err != nil {
		t.Fatal(err)
	}
	svc.Close()
	svc, err = New(dir, cfg, idSelf, newFakeLocal())
	if err != nil {
		t.Fatalf("reopening over a malformed pin: %v", err)
	}
	defer svc.Close()
	if n := pinnedPeerKELs(t, svc); n != 0 {
		t.Fatalf("the malformed pin survived reopening (%d rows)", n)
	}
}

// A peer that is down holds nothing off, so a use after it is back pins
// its KEL at once (a merchant's retry of a settlement completes); but the
// uses waiting while a fetch fails get its failure, rather than each
// fetching again behind it [redteam:F34].
//
// The peer fails the fetch once all the uses are waiting on it. A use that
// asks after a fetch has ended is not waiting on it and fetches anew; with
// the failure sent after a fixed 300 ms, a use slow to ask — its lookup of
// a pinned KEL opens an SQLite connection, which on a loaded host can take
// longer — was that, and made a second fetch.
func TestUsesWaitingOnAFailingPeerKELFetchShareItsFailure(t *testing.T) {
	idSelf, idPeer, _ := threeHubIdentities(t)
	const uses = 20
	var asked atomic.Int32
	allAsked := make(chan struct{})
	testHookPeerKELAsked = func() {
		if asked.Add(1) == uses {
			close(allAsked)
		}
	}
	t.Cleanup(func() { testHookPeerKELAsked = nil })
	var down atomic.Bool
	down.Store(true)
	var fetches atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if down.Load() {
			select {
			case <-allAsked:
			case <-time.After(10 * time.Second):
				t.Error("the uses did not all ask for the KEL")
			}
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"aid":"` + idPeer.AID + `","kel":"` + base64.StdEncoding.EncodeToString(idPeer.KEL) + `"}`))
	}))
	defer fake.Close()
	svc, err := New(t.TempDir(),
		Config{Delivery: "allowlist", Peers: []Peer{{AID: idPeer.AID, Endpoint: fake.URL}}},
		idSelf, newFakeLocal())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	var wg sync.WaitGroup
	for i := 0; i < uses; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.PeerKEL(idPeer.AID); err == nil {
				t.Error("a KEL was pinned from a peer that is down")
			}
		}()
	}
	wg.Wait()
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d uses waiting on one failing fetch fetched %d times, want 1", uses, n)
	}
	down.Store(false)
	if _, err := svc.PeerKEL(idPeer.AID); err != nil {
		t.Fatalf("the first use after the peer is back: %v", err)
	}
	if n := pinnedPeerKELs(t, svc); n != 1 {
		t.Fatalf("the peer's KEL was not pinned once it was back (%d rows)", n)
	}
}
