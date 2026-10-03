package federation

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// A hub's own requests to a peer are hub requests: they state the wire
// (core CORE-V1), so a peer's wire3.Contract lets them through, and the
// peer's /hub/identity, which now also states the wire, still reads.
func TestPeerRequestsStateTheWire(t *testing.T) {
	idSelf, idPeer, _ := threeHubIdentities(t)
	var mu sync.Mutex
	var seen []string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get(wire3.Header))
		mu.Unlock()
		wire3.Contract(idPeer.Handler()).ServeHTTP(w, r)
	}))
	t.Cleanup(peer.Close)

	svc, err := New(t.TempDir(),
		Config{Delivery: "allowlist", Peers: []Peer{{AID: idPeer.AID, Endpoint: peer.URL}}},
		idSelf, newFakeLocal())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if _, err := svc.PeerKEL(idPeer.AID); err != nil {
		t.Fatalf("the peer's /hub/identity: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no request reached the peer")
	}
	for _, v := range seen {
		if v != "3" {
			t.Fatalf("a request to the peer declared %s %q", wire3.Header, v)
		}
	}
}
