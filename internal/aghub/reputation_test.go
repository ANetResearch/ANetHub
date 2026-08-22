package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// A rating that crosses a hub boundary must arrive as evidence, not as a
// number a peer computed.
func TestReputationCrossesHubsAsEvidence(t *testing.T) {
	// The hub where the work happened, and where the review was uploaded.
	home, homeStore := newHubWithStore(t)
	provider, requester := twoAgents(t)
	register(t, home, provider, "Provider", []string{"work.do"})
	register(t, home, requester, "Requester", nil)
	setVisibility(t, home, provider, aghub.VisibilityFederated)
	uploadInterlockedReview(t, home, provider, requester, 5, "excellent")

	// The stream a peer would pull.
	revs, next, err := homeStore.ReviewsSince(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 1 {
		t.Fatalf("the stream carried %d reviews, want 1", len(revs))
	}
	if next == 0 {
		t.Error("the cursor did not advance, so a peer would re-fetch for ever")
	}
	// It carries the objects, not a verdict. A stream that shipped an
	// average would be asking the peer to trust this hub's arithmetic.
	fr := revs[0]
	if fr.Receipt == "" || fr.Review == "" || fr.ProviderKEL == "" || fr.ReviewerKEL == "" {
		t.Fatalf("the stream did not carry the evidence: %+v", fr)
	}

	// The peer admits it, re-checking the interlock itself.
	_, peerStore := newHubWithStore(t)
	if err := peerStore.AdmitFedReview("did:anet:home-hub", fr); err != nil {
		t.Fatalf("a genuine federated review was refused: %v", err)
	}
	rep, err := peerStore.ReputationOf(provider.AID())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Local.Reviews != 0 {
		t.Error("a federated review was counted as local")
	}
	if len(rep.Peers) != 1 || rep.Peers[0].Reviews != 1 || rep.Peers[0].Avg != 5 {
		t.Fatalf("peers = %+v", rep.Peers)
	}
	if rep.Peers[0].Hub != "did:anet:home-hub" {
		t.Errorf("the source hub was lost: %q", rep.Peers[0].Hub)
	}
	// Combined exists, and says how concentrated it is. One source means
	// concentration 1, which is exactly what a reader needs to see.
	if rep.Combined.Reviews != 1 || rep.Combined.Avg != 5 {
		t.Errorf("combined = %+v", rep.Combined)
	}
	if rep.Concentration != 1 {
		t.Errorf("concentration = %v, want 1", rep.Concentration)
	}

	// Replaying the same review must not double the count.
	if err := peerStore.AdmitFedReview("did:anet:home-hub", fr); err != nil {
		t.Fatalf("a replayed review should be a no-op: %v", err)
	}
	rep, _ = peerStore.ReputationOf(provider.AID())
	if rep.Combined.Reviews != 1 {
		t.Errorf("a replay inflated the rating: %d reviews", rep.Combined.Reviews)
	}
}

// A peer can withhold. It must not be able to invent.
func TestAPeerCannotInventARating(t *testing.T) {
	home, homeStore := newHubWithStore(t)
	provider, requester := twoAgents(t)
	register(t, home, provider, "Provider", []string{"work.do"})
	register(t, home, requester, "Requester", nil)
	setVisibility(t, home, provider, aghub.VisibilityFederated)
	uploadInterlockedReview(t, home, provider, requester, 5, "excellent")
	revs, _, err := homeStore.ReviewsSince(0, 0)
	if err != nil || len(revs) != 1 {
		t.Fatal(err)
	}
	good := revs[0]

	_, peerStore := newHubWithStore(t)

	t.Run("the rating raised in transit", func(t *testing.T) {
		// The rating lives inside the reviewer's signature, so changing
		// it means the object no longer verifies. Nothing subtler is
		// available to a relaying hub.
		tampered := good
		raw, err := base64.StdEncoding.DecodeString(good.Review)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 0xff
		tampered.Review = base64.StdEncoding.EncodeToString(raw)
		if err := peerStore.AdmitFedReview("did:anet:liar", tampered); err == nil {
			t.Error("a tampered review was admitted")
		}
	})

	t.Run("key histories supplied by the peer", func(t *testing.T) {
		// A peer that could hand us its own KEL for both parties could
		// sign an entire interaction into existence. The AIDs the objects
		// name are checked against the histories supplied.
		impostor, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		kel, err := identity.MarshalKEL(impostor.KEL())
		if err != nil {
			t.Fatal(err)
		}
		swapped := good
		swapped.ProviderKEL = base64.StdEncoding.EncodeToString(kel)
		if err := peerStore.AdmitFedReview("did:anet:liar", swapped); err == nil {
			t.Error("a review was admitted against a key history that is not the provider's")
		}
	})

	t.Run("a review for an agent registered here", func(t *testing.T) {
		// Otherwise a peer could inflate one of our own agents by
		// claiming to hold ratings for it.
		if err := homeStore.AdmitFedReview("did:anet:liar", good); err == nil {
			t.Error("a peer's review for a locally registered agent was admitted")
		}
	})
}

// The published figure has to show where it came from.
func TestReputationIsPublishedBySource(t *testing.T) {
	home, homeStore := newHubWithStore(t)
	provider, requester := twoAgents(t)
	register(t, home, provider, "Provider", []string{"work.do"})
	register(t, home, requester, "Requester", nil)
	setVisibility(t, home, provider, aghub.VisibilityFederated)
	uploadInterlockedReview(t, home, provider, requester, 4, "fine")
	revs, _, err := homeStore.ReviewsSince(0, 0)
	if err != nil || len(revs) == 0 {
		t.Fatal(err)
	}

	peer, peerStore := newHubWithStore(t)
	if err := peerStore.AdmitFedReview("did:anet:home", revs[0]); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(peer.URL + "/agents/" + provider.AID() + "/reputation")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Reputation aghub.Reputation `json:"reputation"`
		Note       string           `json:"note"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Reputation.Peers) != 1 {
		t.Fatalf("the breakdown is missing: %+v", out.Reputation)
	}
	// The caveat ships with the number. A pooled rating without it is the
	// misleading thing this design set out not to publish.
	if out.Note == "" {
		t.Error("the aggregate is published with no word on what it does not prove")
	}
}

// The custodian's own signature has to be checkable, by the same route
// as everyone else's.
//
// Everything this hub signs — settlements, redemption receipts, vouchers
// — is worthless to a holder who cannot look up the key. For a while the
// hub published every agent's key history and not its own, which made
// "you can verify what the custodian did" true of the objects and false
// of the system. A live run found it; no unit test could, because the
// fake hub registered itself and the real one did not.
func TestTheHubPublishesItsOwnKeyHistory(t *testing.T) {
	srv := newHub(t)
	hubAID := hubAIDOf(t, srv)
	resp, err := http.Get(srv.URL + "/agents/" + hubAID + "/kel")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the hub will not publish its own key: %d", resp.StatusCode)
	}
	var out struct {
		KEL  string `json:"kel"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(out.KEL)
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.UnmarshalKEL(raw)
	if err != nil {
		t.Fatalf("the published key history does not parse: %v", err)
	}
	states, err := identity.Replay(kel)
	if err != nil {
		t.Fatalf("the published key history does not replay: %v", err)
	}
	if got := states[len(states)-1].AID; got != hubAID {
		t.Errorf("the hub published somebody else's key history: %s", got)
	}
	if out.Role != "hub" {
		t.Errorf("role = %q — a reader should be able to tell this is the custodian", out.Role)
	}
}
