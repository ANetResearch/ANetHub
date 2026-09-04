package aghub_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// The federation sync stream has to carry the fact that a card stopped
// being published.
//
// /fed/v1/cards is an increment ordered by fed_seq: a peer asks for what
// changed after the cursor it holds. Deregistration deleted the
// agent_card row and narrowing a visibility left the row outside the
// query's WHERE, and in both cases a row that stops matching produces no
// entry — so a peer already past that row learned nothing, kept the card,
// and went on publishing an agent its home hub no longer publishes.
//
// These tests drive both sides of the real seam: the store that serves
// CardsSince and a second store admitting what it serves. A fake on
// either end would have to be told what a withdrawal is, which is exactly
// what is being checked.

const testHome = "https://home.example"

// homePeerAID is the AID a consuming store files the learned cards under.
const homePeerAID = "did:anet:home-hub"

// fedHub is a hub plus its store, because these tests act as both the
// agent (over HTTP) and the sync stream a peer reads (on the store).
type fedHub struct {
	srv   *httptest.Server
	store *aghub.Store
}

func newFedHub(t *testing.T) *fedHub {
	t.Helper()
	srv, store := newHubWithStore(t)
	return &fedHub{srv: srv, store: store}
}

func openPeerStore(t *testing.T) *aghub.Store {
	t.Helper()
	st, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// publishesFed reports whether a store still offers a peer-learned agent
// in its directory.
func publishesFed(t *testing.T, st *aghub.Store, aid string) bool {
	t.Helper()
	agents, err := st.FederatedAgents("")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range agents {
		if a.AID == aid {
			return true
		}
	}
	return false
}

// withdrawalOf returns the AID a sync entry withdraws, or "" when the
// entry is an ordinary card.
func withdrawalOf(t *testing.T, fc aghub.FedCard) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fc.Card, &m); err != nil {
		t.Fatalf("sync entry is not JSON: %s", fc.Card)
	}
	if m["action"] != "withdraw" {
		return ""
	}
	// A withdrawal must not carry the card it withdraws. The hub keeps
	// that copy to go on serving a narrowed agent locally; sending it to
	// a peer would publish the card in the same message that says to stop
	// publishing it.
	if _, hasCard := m["card"]; hasCard {
		t.Errorf("a withdrawal carried the card it withdraws: %s", fc.Card)
	}
	aid, _ := m["agent_id"].(string)
	return aid
}

// federate registers an agent and opts it into federation.
func federate(t *testing.T, hub *fedHub, c *identity.Controller, name string, caps []string) {
	t.Helper()
	register(t, hub.srv, c, name, caps)
	setVisibility(t, hub.srv, c, aghub.VisibilityFederated)
}

// An agent that leaves must stop being published by the hubs that learned
// about it here.
func TestLeavingWithdrawsTheCardFromEveryPeer(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	federate(t, hub, agent, "Mover", []string{"work.do"})

	cards, cursor, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 {
		t.Fatalf("setup: %d cards on the stream, want 1", len(cards))
	}
	peer := openPeerStore(t)
	if err := peer.AdmitFedCard(homePeerAID, cards[0]); err != nil {
		t.Fatal(err)
	}
	if !publishesFed(t, peer, agent.AID()) {
		t.Fatal("setup: the peer did not take the card")
	}

	if code, b := leave(t, hub.srv, agent); code != 200 {
		t.Fatalf("deregister: %d %s", code, b)
	}

	after, _, err := hub.store.CardsSince(cursor, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 {
		t.Fatalf("leaving produced %d sync entries after the peer's cursor, want 1 — "+
			"a deleted row is invisible to a peer that has read past it", len(after))
	}
	if got := withdrawalOf(t, after[0]); got != agent.AID() {
		t.Fatalf("the entry withdraws %q, want %q: %s", got, agent.AID(), after[0].Card)
	}
	// The SQL that selects withdrawals alongside published cards matches
	// on this exact prefix. If the encoding stops starting here the query
	// stops finding them and the defect returns without a symptom.
	if !bytes.HasPrefix(after[0].Card, []byte(`{"action":"withdraw"`)) {
		t.Errorf("a withdrawal no longer starts with the prefix CardsSince selects on: %s", after[0].Card)
	}

	if err := peer.AdmitFedCard(homePeerAID, after[0]); err != nil {
		t.Fatalf("the peer refused the withdrawal: %v", err)
	}
	if publishesFed(t, peer, agent.AID()) {
		t.Error("the peer still publishes an agent that left its home hub")
	}
	// Leaving gives up the routing, so the home hub stops serving the
	// card too. Keeping the row on the stream must not turn into keeping
	// the departed agent's card on this hub's own endpoints.
	if raw, cerr := hub.store.AgentCard(agent.AID()); cerr != nil || len(raw) > 0 {
		t.Errorf("the hub still serves a departed agent's card: %s %v", raw, cerr)
	}
	if code, b := getJSON(t, hub.srv.URL+"/agents/"+agent.AID()+"/card"); code != 404 {
		t.Errorf("GET /agents/{aid}/card after leaving = %d %s, want 404", code, b)
	}
	// And the withdrawal cannot be undone from outside. Setting a
	// visibility on an agent that is no longer registered must not put
	// its card back on the stream.
	if err := hub.store.SetVisibility(agent.AID(), aghub.VisibilityFederated); err == nil {
		t.Error("a departed agent's visibility could still be set, which would " +
			"republish the card it withdrew")
	}
}

// Narrowing a visibility is the other way a card stops being published,
// and it has to reach the peers the same way.
func TestNarrowingVisibilityWithdrawsTheCard(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	federate(t, hub, agent, "Shy", []string{"work.do"})

	cards, cursor, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 {
		t.Fatalf("setup: %d cards on the stream, want 1", len(cards))
	}
	peer := openPeerStore(t)
	if err := peer.AdmitFedCard(homePeerAID, cards[0]); err != nil {
		t.Fatal(err)
	}

	setVisibility(t, hub.srv, agent, aghub.VisibilityHubLocal)

	after, _, err := hub.store.CardsSince(cursor, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 {
		t.Fatalf("narrowing the visibility produced %d sync entries after the peer's "+
			"cursor, want 1 — the peer keeps publishing a card it may no longer "+
			"publish", len(after))
	}
	if got := withdrawalOf(t, after[0]); got != agent.AID() {
		t.Fatalf("the entry withdraws %q, want %q: %s", got, agent.AID(), after[0].Card)
	}
	if err := peer.AdmitFedCard(homePeerAID, after[0]); err != nil {
		t.Fatalf("the peer refused the withdrawal: %v", err)
	}
	if publishesFed(t, peer, agent.AID()) {
		t.Error("the peer still publishes a card its home hub has un-published")
	}

	// hub-local means "do not tell other hubs", not "stop being an agent
	// here". The card is withheld from peers and still served locally.
	raw, err := hub.store.AgentCard(agent.AID())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Error("narrowing the visibility took the agent's card away from its own hub")
	}
	if code, b := getJSON(t, hub.srv.URL+"/agents/"+agent.AID()+"/card"); code != 200 {
		t.Errorf("GET /agents/{aid}/card after narrowing = %d %s", code, b)
	}
	if n := agentsServing(t, hub.srv, "work.do"); n != 1 {
		t.Errorf("narrowing the visibility removed the agent from its own directory (%d)", n)
	}
}

// Opting IN has to reach a peer whose cursor is already past the row.
func TestWideningVisibilityReachesAPeerPastTheCursor(t *testing.T) {
	hub := newFedHub(t)
	quiet, loud := twoAgents(t)
	register(t, hub.srv, quiet, "Quiet", []string{"work.do"})
	federate(t, hub, loud, "Loud", []string{"work.do"})

	// A peer syncs to the end of the stream. Only the federated agent is
	// on it, so the cursor is now past the other agent's card row.
	cards, cursor, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 {
		t.Fatalf("setup: %d cards on the stream, want 1", len(cards))
	}

	setVisibility(t, hub.srv, quiet, aghub.VisibilityFederated)

	after, _, err := hub.store.CardsSince(cursor, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 {
		t.Fatalf("opting into federation produced %d entries after the peer's cursor, "+
			"want 1 — a visibility change that leaves fed_seq alone is invisible to "+
			"every peer that has read past the row", len(after))
	}
	if got := withdrawalOf(t, after[0]); got != "" {
		t.Fatalf("opting in produced a withdrawal for %q: %s", got, after[0].Card)
	}
	var m map[string]any
	if err := json.Unmarshal(after[0].Card, &m); err != nil {
		t.Fatal(err)
	}
	if m["subject_did"] != quiet.AID() {
		t.Errorf("the entry carries %v, want the card of %s", m["subject_did"], quiet.AID())
	}
	// A peer must be able to admit it, which needs the key history the
	// entry carries.
	peer := openPeerStore(t)
	if err := peer.AdmitFedCard(homePeerAID, after[0]); err != nil {
		t.Fatalf("the peer could not admit the newly federated card: %v", err)
	}
	if !publishesFed(t, peer, quiet.AID()) {
		t.Error("the peer did not take the newly federated card")
	}
}

// A hub may retract what it published, and nothing else.
func TestOnlyTheHubThatPublishedACardCanWithdrawIt(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	federate(t, hub, agent, "Mover", []string{"work.do"})

	cards, cursor, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil || len(cards) != 1 {
		t.Fatalf("setup: %d cards %v", len(cards), err)
	}
	peer := openPeerStore(t)
	if err := peer.AdmitFedCard(homePeerAID, cards[0]); err != nil {
		t.Fatal(err)
	}

	if code, b := leave(t, hub.srv, agent); code != 200 {
		t.Fatalf("deregister: %d %s", code, b)
	}
	after, _, err := hub.store.CardsSince(cursor, 100, testHome)
	if err != nil || len(after) != 1 {
		t.Fatalf("setup: %d withdrawals %v", len(after), err)
	}

	// A hub that never published this card replays the withdrawal. If
	// this took effect, any peer could clear any other peer's agents out
	// of this directory.
	if err := peer.AdmitFedCard("did:anet:stranger-hub", after[0]); err != nil {
		t.Fatalf("the replayed withdrawal errored rather than being ignored: %v", err)
	}
	if !publishesFed(t, peer, agent.AID()) {
		t.Fatal("a hub that never published this card removed it from the directory")
	}

	if err := peer.AdmitFedCard(homePeerAID, after[0]); err != nil {
		t.Fatal(err)
	}
	if publishesFed(t, peer, agent.AID()) {
		t.Error("the home hub's own withdrawal did not take effect")
	}
}

// A card no peer was ever offered is removed, not announced.
//
// A withdrawal names an AID. Emitting one for a hub-local agent would
// publish, in the act of leaving, exactly what the hub-local tier exists
// to keep unpublished.
func TestAHubLocalAgentIsNotNamedWhenItLeaves(t *testing.T) {
	hub := newFedHub(t)
	private, public := twoAgents(t)
	register(t, hub.srv, private, "Private", []string{"work.do"})
	federate(t, hub, public, "Public", []string{"work.do"})

	if code, b := leave(t, hub.srv, private); code != 200 {
		t.Fatalf("deregister: %d %s", code, b)
	}

	entries, _, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	for _, fc := range entries {
		if strings.Contains(string(fc.Card), private.AID()) {
			t.Errorf("a hub-local agent's AID reached the federation stream on its "+
				"way out: %s", fc.Card)
		}
	}
	// The agent that did federate is still on the stream, so the check
	// above is not passing because the stream is empty.
	if len(entries) != 1 {
		t.Fatalf("%d entries on the stream, want the one federated card", len(entries))
	}
}

// A republished card must not quietly cancel a withdrawal no peer has
// read yet.
func TestRepublishingACardDoesNotCancelAStandingWithdrawal(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	federate(t, hub, agent, "Shy", []string{"work.do"})

	_, cursor, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	setVisibility(t, hub.srv, agent, aghub.VisibilityHubLocal)
	// The node re-registers — a restart, a capability change — before the
	// peer's next sync round.
	register(t, hub.srv, agent, "Shy", []string{"work.do", "work.more"})

	after, _, err := hub.store.CardsSince(cursor, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 {
		t.Fatalf("%d entries after the peer's cursor, want the standing withdrawal", len(after))
	}
	if got := withdrawalOf(t, after[0]); got != agent.AID() {
		t.Fatalf("republishing a card cancelled a withdrawal the peer had not read: %s",
			after[0].Card)
	}

	// And the hub still serves the card it just accepted.
	raw, err := hub.store.AgentCard(agent.AID())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "work.more") {
		t.Errorf("the republished card is not the one the hub serves: %s", raw)
	}
}

// A withdrawal for an agent registered here can only touch the
// peer-learned copy, never the local registry.
func TestAPeerWithdrawalCannotUnregisterALocalAgent(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	federate(t, hub, agent, "Local", []string{"work.do"})

	cards, cursor, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil || len(cards) != 1 {
		t.Fatalf("setup: %d cards %v", len(cards), err)
	}
	// Build a real withdrawal on a second hub for the same AID, then feed
	// it back to the hub the agent actually lives on.
	other := newFedHub(t)
	federate(t, other, agent, "Local", []string{"work.do"})
	if code, b := leave(t, other.srv, agent); code != 200 {
		t.Fatalf("deregister on the other hub: %d %s", code, b)
	}
	stolen, _, err := other.store.CardsSince(0, 100, "https://other.example")
	if err != nil || len(stolen) != 1 {
		t.Fatalf("setup: %d withdrawals %v", len(stolen), err)
	}

	if err := hub.store.AdmitFedCard("did:anet:other-hub", stolen[0]); err != nil {
		t.Fatalf("the withdrawal errored rather than being ignored: %v", err)
	}
	if n := agentsServing(t, hub.srv, "work.do"); n != 1 {
		t.Fatalf("a peer's withdrawal removed an agent registered here (%d)", n)
	}
	still, _, err := hub.store.CardsSince(cursor, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(still) != 0 {
		t.Errorf("a peer's withdrawal changed this hub's own stream: %v", still)
	}
}

// A card cannot be made to read as a withdrawal.
//
// The ADP pre-image covers the card struct, so unknown JSON keys ride
// along in the stored bytes without being signed. If a withdrawal were
// recognised by its action alone, an agent could publish a card carrying
// "action":"withdraw" and somebody else's agent_id, and every peer that
// synced this hub would drop the card it named.
func TestACardCannotForgeAWithdrawal(t *testing.T) {
	hub := newFedHub(t)
	attacker, victim := twoAgents(t)
	federate(t, hub, victim, "Victim", []string{"work.do"})

	// The attacker's own signed card, with two keys added that the
	// signature does not cover. Raw values are kept byte-intact so the
	// card still verifies.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(mintCard(t, attacker, "Attacker", []string{"work.do"}), &obj); err != nil {
		t.Fatal(err)
	}
	obj["action"] = json.RawMessage(`"withdraw"`)
	obj["agent_id"] = json.RawMessage(`"` + victim.AID() + `"`)
	forged, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if code, b := registerWithCard(t, hub.srv, attacker, "Attacker", []string{"work.do"},
		forged); code != 200 {
		t.Fatalf("register: %d %s", code, b)
	}
	setVisibility(t, hub.srv, attacker, aghub.VisibilityFederated)

	// The effect is what is asserted, not how the bytes are classified: a
	// peer syncs everything this hub publishes and must come out holding
	// both cards.
	entries, _, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("%d entries on the stream, want both cards", len(entries))
	}
	peer := openPeerStore(t)
	for _, fc := range entries {
		if err := peer.AdmitFedCard(homePeerAID, fc); err != nil {
			t.Fatalf("the peer refused an entry: %v", err)
		}
	}
	if !publishesFed(t, peer, victim.AID()) {
		t.Error("one agent's card removed another agent from a peer's directory")
	}
	if !publishesFed(t, peer, attacker.AID()) {
		t.Error("the card carrying the extra keys did not reach the peer as a card")
	}
	// And this hub still holds it as a card of its own.
	raw, err := hub.store.AgentCard(attacker.AID())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Error("the hub stopped serving a card because of an unsigned key inside it")
	}
}
