package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// otherHub is a hub identity of its own, as a federation peer has.
func otherHub(t *testing.T) *hubid.Identity {
	t.Helper()
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A rating that crosses a hub boundary must arrive as evidence, not as a
// number a peer computed.
func TestReputationCrossesHubsAsEvidence(t *testing.T) {
	// The hub where the work happened, and where the review was uploaded.
	home, homeStore := newHubWithStore(t)
	homeID := aghub.HubIdentityForTest(t)
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
	// It carries the objects and the home hub's attestation, not a
	// verdict. A stream that shipped an average would be asking the peer
	// to trust this hub's arithmetic.
	fr := revs[0]
	if fr.Format != aghub.FormatReviewV2 || fr.Receipt == "" || fr.Review == "" || fr.Attestation == "" ||
		fr.ProviderKEL == "" || fr.FedSeq != uint64(next) {
		t.Fatalf("the stream did not carry the evidence: %+v", fr)
	}

	// The peer admits it, checking every signature itself.
	_, peerStore := newHubWithStore(t)
	if err := peerStore.AdmitFedReview(homeID.AID, homeID.Ctrl.KEL(), fr); err != nil {
		t.Fatalf("a genuine federated review was refused: %v", err)
	}
	rep, err := peerStore.ReputationOf(provider.AID())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Local.Reviews != 0 {
		t.Error("a federated review was counted as local")
	}
	if len(rep.Peers) != 1 || rep.Peers[0].Reviews != 1 || rep.Peers[0].Avg != 5 || rep.Peers[0].Reviewers != 1 {
		t.Fatalf("peers = %+v", rep.Peers)
	}
	if rep.Peers[0].Hub != homeID.AID {
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
	if err := peerStore.AdmitFedReview(homeID.AID, homeID.Ctrl.KEL(), fr); err != nil {
		t.Fatalf("a replayed review should be a no-op: %v", err)
	}
	rep, _ = peerStore.ReputationOf(provider.AID())
	if rep.Combined.Reviews != 1 {
		t.Errorf("a replay inflated the rating: %d reviews", rep.Combined.Reviews)
	}
	// And another peer passing on the same interaction does not count it
	// again: an interaction is reviewed once, wherever (PAY-V3).
	other := otherHub(t)
	again := aghub.FedEntryForTest(t, other.Ctrl, reviewOf(t, fr), aghub.TodayForTest(), 1)
	if err := peerStore.AdmitFedReview(other.AID, other.Ctrl.KEL(), again); !errors.Is(err, aghub.ErrReviewExists) {
		t.Errorf("the same interaction from a second peer: %v, want ErrReviewExists", err)
	}
}

// reviewOf rebuilds a kit-like view of a stream entry's review for
// re-attesting it: the same receipt and review bytes.
func reviewOf(t *testing.T, e aghub.FedReviewEntry) *aghub.ReviewKit {
	t.Helper()
	return aghub.KitFromEntryForTest(t, e)
}

// A peer can withhold. It must not be able to invent.
func TestAPeerCannotInventARating(t *testing.T) {
	home, homeStore := newHubWithStore(t)
	homeID := aghub.HubIdentityForTest(t)
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
	admit := func(e aghub.FedReviewEntry) error {
		return peerStore.AdmitFedReview(homeID.AID, homeID.Ctrl.KEL(), e)
	}
	flip := func(t *testing.T, b64 string) string {
		raw, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 0xff
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	t.Run("the rating raised in transit", func(t *testing.T) {
		// The rating lives inside the review key's signature, so changing
		// it means the object no longer verifies. Nothing subtler is
		// available to a relaying hub.
		tampered := good
		tampered.Review = flip(t, good.Review)
		if err := admit(tampered); err == nil {
			t.Error("a tampered review was admitted")
		}
	})

	t.Run("the attestation changed in transit", func(t *testing.T) {
		tampered := good
		tampered.Attestation = flip(t, good.Attestation)
		if err := admit(tampered); err == nil {
			t.Error("a review under a tampered attestation was admitted")
		}
	})

	t.Run("an attestation by another hub", func(t *testing.T) {
		// Who signed the attestation must be the peer the stream came
		// from: the review is counted in that peer's column.
		other := otherHub(t)
		e := aghub.FedEntryForTest(t, other.Ctrl, reviewOf(t, good), aghub.TodayForTest(), 1)
		if err := admit(e); err == nil {
			t.Error("a review attested by a hub other than the peer was admitted")
		}
	})

	t.Run("key histories supplied by the peer", func(t *testing.T) {
		// A peer that could hand us any KEL for the provider could sign an
		// entire interaction into existence. The AID the receipt names is
		// checked against the history supplied.
		impostor, err := aghub.NewAgentForTest()
		if err != nil {
			t.Fatal(err)
		}
		kel, err := identity.MarshalKEL(impostor.KEL())
		if err != nil {
			t.Fatal(err)
		}
		swapped := good
		swapped.ProviderKEL = base64.RawURLEncoding.EncodeToString(kel)
		if err := admit(swapped); err == nil {
			t.Error("a review was admitted against a key history that is not the provider's")
		}
	})

	t.Run("a review of OUR agent stays in the peer's column", func(t *testing.T) {
		// A peer's review of an agent registered here, of another
		// interaction (one uploaded at the peer), is admitted, and that
		// is the correction. Refusing it looked prudent and cost real
		// function: an agent working across hubs could never accumulate a
		// rating for the half of its work that crossed. A peer cannot
		// forge a review of our agent — the anchor is our agent's own
		// signature over a receipt — so what arrives is a genuine
		// interaction or nothing.
		//
		// What contains the risk is where it lands.
		peer := otherHub(t)
		before, err := homeStore.ReputationOf(provider.AID())
		if err != nil {
			t.Fatal(err)
		}
		k := makeEvidence(t, provider, requester, "ix-at-the-peer", 3, "")
		if err := homeStore.AdmitFedReview(peer.AID, peer.Ctrl.KEL(), aghub.FedEntryForTest(t, peer.Ctrl, k, aghub.TodayForTest(), 7)); err != nil {
			t.Fatalf("a genuine cross-hub review of our own agent was refused: %v", err)
		}
		after, err := homeStore.ReputationOf(provider.AID())
		if err != nil {
			t.Fatal(err)
		}
		if after.Local.Reviews != before.Local.Reviews {
			t.Errorf("a peer's review moved the LOCAL count: %d → %d",
				before.Local.Reviews, after.Local.Reviews)
		}
		if len(after.Peers) != 1 || after.Peers[0].Hub != peer.AID {
			t.Fatalf("it did not land in the peer's column: %+v", after.Peers)
		}
		if after.Combined.Reviews != before.Combined.Reviews+1 {
			t.Errorf("combined = %d, want %d", after.Combined.Reviews, before.Combined.Reviews+1)
		}
		// The interaction reviewed here cannot come back as a peer's.
		if err := homeStore.AdmitFedReview(peer.AID, peer.Ctrl.KEL(),
			aghub.FedEntryForTest(t, peer.Ctrl, reviewOf(t, good), aghub.TodayForTest(), 8)); !errors.Is(err, aghub.ErrReviewExists) {
			t.Errorf("an interaction reviewed here, from a peer: %v, want ErrReviewExists", err)
		}
	})
}

// The published figure has to show where it came from:
// {aid, local: {reviews, avg, reviewers}, peers: [{hub, reviews, avg,
// reviewers}], combined: {reviews, avg}, concentration} (hub-payment-privacy
// §2.5).
func TestReputationIsPublishedBySource(t *testing.T) {
	home, homeStore := newHubWithStore(t)
	homeID := aghub.HubIdentityForTest(t)
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
	if err := peerStore.AdmitFedReview(homeID.AID, homeID.Ctrl.KEL(), revs[0]); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(peer.URL + "/agents/" + provider.AID() + "/reputation")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"aid", "local", "peers", "combined", "concentration"} {
		if _, ok := raw[m]; !ok {
			t.Errorf("the reputation has no %q", m)
		}
	}
	var out aghub.Reputation
	b, _ := json.Marshal(raw)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.AID != provider.AID() || len(out.Peers) != 1 || out.Peers[0].Reviewers != 1 || out.Peers[0].Avg != 4 {
		t.Fatalf("the breakdown is missing: %+v", out)
	}
}

// The custodian's own signature has to be checkable, by the same route
// as everyone else's.
//
// Everything this hub signs — settlements, redemption receipts
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
		KEL        string `json:"kel"`
		Registered bool   `json:"registered"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(out.KEL)
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
	if !out.Registered {
		t.Error("registered = false: the hub's own history is not a departed agent's")
	}
}

// A cross-hub interaction must be reviewable at all.
//
// It was not. The reviewer banks at one hub and the provider at another,
// so "are both parties registered here" — the only question the upload
// path asked — was false for every interaction that crossed a boundary.
// Federation was producing work that nothing could rate, and the shape of
// the bug is familiar: each half was correct and nobody had walked the
// line between them.
func TestAnInteractionThatCrossedAHubCanStillBeReviewed(t *testing.T) {
	// hub1 is where the reviewer banks; the provider lives on hub2 and
	// hub1 knows it only as a federated card.
	hub1, store1 := newHubWithStore(t)
	provider, requester := twoAgents(t)
	register(t, hub1, requester, "Requester", nil)

	// The provider's card reaches hub1 the way federation delivers it.
	entry := a2aEntry(t, provider, signA2A(t, provider, a2aCardFor(provider, 1)))
	entry.Home = "https://hub2.example"
	if err := store1.AdmitFedA2ACard("did:anet:hub2", entry); err != nil {
		t.Fatal(err)
	}

	// The requester reviews the work it had done on the other hub.
	if code, b := uploadReview(t, hub1, makeEvidence(t, provider, requester, "ix-crossed", 5, "")); code != 200 {
		t.Fatalf("a cross-hub interaction could not be reviewed: %d %s", code, b)
	}

	// hub1 holds it and will serve it, because it is first-hand: its own
	// user said it. That is different from forwarding what a peer said,
	// which the one-hop rule still forbids.
	rep, err := store1.ReputationOf(provider.AID())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Local.Reviews != 1 || rep.Local.Avg != 5 {
		t.Errorf("hub1 did not record its own user's review: %+v", rep.Local)
	}

	// And a stranger who never registered anywhere still cannot be
	// reviewed — the widening is "known to this hub", not "anyone".
	stranger, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := uploadReview(t, hub1, makeEvidence(t, stranger, requester, "ix-stranger", 5, "")); code == 200 {
		t.Error("a review of a provider this hub has never heard of was accepted")
	}
}
