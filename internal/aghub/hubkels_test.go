package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// KEL H-16: GET /hub/kels serves this hub's key history first and then the
// pinned peers' in the order of their AIDs, each base64url and replaying to
// its AID, cacheable for 5 minutes. A hub without federation serves its own.
func TestHubKELsServesOwnAndPinned(t *testing.T) {
	srv, _ := newHubWithStore(t)
	own := hubAIDOf(t, srv)
	read := func() ([]aghub.HubKELEntry, http.Header) {
		t.Helper()
		resp, err := http.Get(srv.URL + "/hub/kels")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out aghub.HubKELsView
		if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&out) != nil {
			t.Fatalf("GET /hub/kels: %d", resp.StatusCode)
		}
		for _, h := range out.Hubs {
			raw, err := base64.RawURLEncoding.DecodeString(h.KEL)
			if err != nil {
				t.Fatalf("%s: not base64url", h.AID)
			}
			kel, err := identity.UnmarshalKEL(raw)
			if err != nil {
				t.Fatal(err)
			}
			states, err := identity.Replay(kel)
			if err != nil || states[len(states)-1].AID != h.AID {
				t.Fatalf("%s: does not replay to its AID", h.AID)
			}
		}
		return out.Hubs, resp.Header
	}
	hubs, h := read()
	if len(hubs) != 1 || hubs[0].AID != own {
		t.Fatalf("without federation: %+v", hubs)
	}
	if h.Get("Cache-Control") != "max-age=300" || h.Get("X-ANet-Wire") != "3" {
		t.Errorf("headers: %v", h)
	}
	var peers []*identity.Controller
	for i := 0; i < 3; i++ {
		p, err := identitytest.Hub()
		if err != nil {
			t.Fatal(err)
		}
		peers = append(peers, p)
	}
	serverOf(t, srv).SetHubKELSet(func() ([]aghub.HubKEL, error) {
		var out []aghub.HubKEL
		for _, p := range peers {
			kel, err := identity.MarshalKEL(p.KEL())
			if err != nil {
				return nil, err
			}
			out = append(out, aghub.HubKEL{AID: p.AID(), KEL: kel})
		}
		return out, nil
	})
	hubs, _ = read()
	if len(hubs) != 4 || hubs[0].AID != own {
		t.Fatalf("with three peers: %d hubs, first %s", len(hubs), hubs[0].AID)
	}
	for i := 2; i < len(hubs); i++ {
		if hubs[i-1].AID >= hubs[i].AID {
			t.Errorf("the peers are not in the order of their AIDs")
		}
	}
}

// KEL H-34, core CORE-L8: what a peer hub signed is verified under its key
// history as of the object's own time. A receipt and a clearing statement
// the peer signed before it rotated still verify after the rotation; ones
// its retired key signed with a later time do not. One signed under a key
// state past the pinned history has the history fetched again once.
func TestHubSignedObjectsVerifiedAtSigningTime(t *testing.T) {
	srv, ourStore := newHubWithStore(t)
	ourAID := hubAIDOf(t, srv)
	peer, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	payee, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, payee, "Payee", nil)
	oldKey := restoreCopy(t, peer)
	before := time.Now().UnixMilli()
	receipt := func(id string, at int64, signer identity.Signer) *payment.Receipt {
		r := &payment.Receipt{AuthID: id, Payer: "did:anet:their-user", PayTo: payee.AID(), Amount: 5,
			Network: payment.CreditNetwork(peer.AID()), SettleAt: at}
		if err := r.Sign(signer); err != nil {
			t.Fatal(err)
		}
		return r
	}
	signedBefore := receipt("before-rotation", before, peer)
	time.Sleep(2 * time.Millisecond)
	rotAt := uint64(time.Now().UnixMilli())
	if err := identitytest.Rotate(peer, rotAt); err != nil {
		t.Fatal(err)
	}
	// The receipt signed before the rotation clears after it.
	if err := ourStore.ClearFromPeer(peer.AID(), peer.KEL(), signedBefore); err != nil {
		t.Fatalf("a receipt signed before the peer's rotation: %v", err)
	}
	// The retired key's receipt dated after the rotation does not.
	forged := receipt("after-rotation", int64(rotAt)+1, oldKey)
	if err := ourStore.ClearFromPeer(peer.AID(), peer.KEL(), forged); err == nil {
		t.Fatal("the retired key's receipt dated after the rotation cleared")
	}
	discharge := &payment.Receipt{AuthID: "clear:before", Payer: peer.AID(), PayTo: ourAID, Amount: 5,
		Network: payment.CreditNetwork(peer.AID()), SettleAt: before}
	if err := discharge.Sign(oldKey); err != nil {
		t.Fatal(err)
	}
	if err := ourStore.SettleOwed(ourAID, peer.AID(), peer.KEL(), discharge); err != nil {
		t.Fatalf("a statement signed before the peer's rotation: %v", err)
	}
}

// restoreCopy is a second controller of c's identity as it is now.
func restoreCopy(t *testing.T, c *identity.Controller) *identity.Controller {
	t.Helper()
	b, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	cp, err := identity.Restore(b)
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

// KEL H-36: the store signs through an identity.Signer. Handed a snapshot of
// the hub identity, it signs the notices it states under the key state the
// snapshot names, and they verify against the hub's key history.
func TestStoreSignsThroughASigner(t *testing.T) {
	id := aghub.HubIdentityForTest(t)
	store, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetHubKey(identity.SnapshotOf(id.Ctrl))
	agent, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(agent.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(agent.AID(), "agent", nil, kel); err != nil {
		t.Fatal(err)
	}
	n, why, err := store.NoticeFor(agent.AID())
	if err != nil || why != "" {
		t.Fatalf("notice: %q %v", why, err)
	}
	hubKELs := func(aid string) ([]identity.SignedEvent, bool) { return id.Ctrl.KEL(), aid == id.AID }
	if err := identity.VerifyNotice(n, agent.KEL(), hubKELs, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatalf("the notice the snapshot signed: %v", err)
	}
}
