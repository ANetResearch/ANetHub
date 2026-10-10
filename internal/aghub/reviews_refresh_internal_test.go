package aghub

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"

	"github.com/ANetResearch/ANetHub/internal/federation"
)

// TestAPeerReviewUnderANewKeyFetchesTheKeyHistoryAgain (KEL H-34): a peer
// that rotated attests its reviews under its new key at once. The first
// pass of its review stream that meets one fetches the peer's key history
// again and admits it, instead of holding it until the next 10-minute
// fetch; a second rotation within the minute waits (once a minute per
// peer).
func TestAPeerReviewUnderANewKeyFetchesTheKeyHistoryAgain(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	discover := func(nd, peer *fedNode) *federation.Service {
		fed, err := federation.New(t.TempDir(), federation.Config{Delivery: "allowlist", Discovery: "allowlist",
			Witness: "off", Home: nd.http.URL, Peers: []federation.Peer{{AID: peer.hubAID, Endpoint: peer.http.URL}}}, nd.hubID)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fed.Close() })
		fed.SetDirectory(FedDirectory{S: nd.store, PeerKEL: fed.PeerKEL})
		nd.store.SetPeerKELRefresher(fed.RefreshPeerKEL)
		nd.wire(fed)
		return fed
	}
	fedA := discover(a, b)
	discover(b, a)
	if kel, err := fedA.PeerKEL(b.hubAID); err != nil || len(kel) != 1 {
		t.Fatalf("A pins B's key history: %d events, %v", len(kel), err)
	}
	rotate := func() {
		t.Helper()
		if err := identitytest.Rotate(b.hubID.Ctrl, uint64(time.Now().UnixMilli())); err != nil {
			t.Fatal(err)
		}
		kel, err := identity.MarshalKEL(b.hubID.Ctrl.KEL())
		if err != nil {
			t.Fatal(err)
		}
		b.hubID.KEL = kel // what B's /hub/identity serves from now on
	}
	attest := func(ix string) *ReviewKit {
		t.Helper()
		subject, reviewer := b.bareAgent(), b.bareAgent()
		if err := b.store.SetVisibility(subject.aid, VisibilityFederated); err != nil {
			t.Fatal(err)
		}
		kit := NewReviewKitForTest(t, subject.c, reviewer.c, ix, 4)
		raw, _ := json.Marshal(kit.Body(t))
		up, rf := decodeReviewUpload(raw)
		if rf != nil {
			t.Fatalf("the upload: %+v", rf)
		}
		stored, att, err := b.store.attest(reviewer.aid, up, reviewDay(b.store.now()))
		if err != nil {
			t.Fatal(err)
		}
		if err := b.store.StoreReview(stored, up.receiptRaw, up.reviewRaw, att); err != nil {
			t.Fatal(err)
		}
		return kit
	}
	held := func(k *ReviewKit) bool {
		var n int
		if err := a.store.db.QueryRow(`SELECT COUNT(*) FROM fed_review WHERE ix_commit=?`, k.IXCommit()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	time.Sleep(2 * time.Millisecond) // the rotation's time comes after the inception's
	rotate()
	k1 := attest("ix-after-a-rotation")
	admitted, refused := fedA.SyncOnce(context.Background())
	if admitted != 1 || refused != 0 || !held(k1) {
		t.Fatalf("one pass of B's stream: admitted %d, refused %d; want the review attested under B's new key", admitted, refused)
	}
	fetches := b.hitsOf("/hub/identity")
	time.Sleep(2 * time.Millisecond)
	rotate()
	k2 := attest("ix-after-a-second-rotation")
	admitted, refused = fedA.SyncOnce(context.Background())
	if admitted != 0 || refused != 1 || held(k2) {
		t.Fatalf("a second rotation within the minute: admitted %d, refused %d; want it held for now", admitted, refused)
	}
	if n := b.hitsOf("/hub/identity") - fetches; n != 0 {
		t.Fatalf("B's key history was fetched %d more times within the minute", n)
	}
}
