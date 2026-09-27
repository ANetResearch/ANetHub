package aghub_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
)

// Federation of A2A cards, GET /fed/v2/cards (A2A-DESIGN §10.6): the
// stream a hub serves, admission of what a peer serves, withdrawals, the
// home of a federated agent, and v1 alongside v2.

// relayAt points a card's relay interface at hub.
func relayAt(hub string) func(map[string]any) {
	return func(card map[string]any) {
		card["supportedInterfaces"].([]any)[0].(map[string]any)["url"] = hub + "/relay"
	}
}

// a2aEntry is a stream entry carrying card with c's KEL.
func a2aEntry(t *testing.T, c *identity.Controller, card json.RawMessage) aghub.FedA2ACard {
	t.Helper()
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return aghub.FedA2ACard{Format: federation.FormatA2ACard, Card: card, KEL: kel, Home: testHome}
}

// fedRegistry is the registry a store answers with its federated cards.
func fedRegistry(t *testing.T, st *aghub.Store, q aghub.RegistryQuery) map[string]aghub.A2AAgentEntry {
	t.Helper()
	q.Federated = true
	entries, _, err := st.A2ARegistry(q)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]aghub.A2AAgentEntry{}
	for _, e := range entries {
		out[e.AID] = e
	}
	return out
}

// a2aStream reads a hub's A2A card stream after cursor.
func a2aStream(t *testing.T, st *aghub.Store, cursor int64) ([]aghub.FedA2ACard, int64) {
	t.Helper()
	entries, next, err := st.A2ACardsSince(cursor, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	return entries, next
}

// withdrawnAID is the AID a withdrawal entry names, and its reason.
func withdrawnAID(t *testing.T, e aghub.FedA2ACard) (aid, reason string) {
	t.Helper()
	if e.Format != federation.FormatWithdrawal {
		t.Fatalf("entry format %q, want a withdrawal", e.Format)
	}
	var w struct {
		Action  string          `json:"action"`
		AgentID string          `json:"agent_id"`
		Reason  string          `json:"reason"`
		Card    json.RawMessage `json:"card"`
	}
	if err := json.Unmarshal(e.Card, &w); err != nil || w.Action != "withdraw" {
		t.Fatalf("withdrawal entry: %s", e.Card)
	}
	if len(w.Card) > 0 || len(e.KEL) > 0 || len(e.Keys) > 0 {
		t.Errorf("a withdrawal carries a card, KEL or keys: %+v", e)
	}
	return w.AgentID, w.Reason
}

// An agent's A2A card, once it opts into federation, reaches a peer hub
// over /fed/v2/cards: it is listed in the peer's registry with the home
// hub it lives on, served by the peer's card endpoint, found by skill,
// named in /agents from the card, and its key set is answered by the
// peer's /agents/{aid}/keys. Before the agent opts in, nothing travels.
func TestAnA2ACardFederatesToAPeersRegistry(t *testing.T) {
	a, b := federatedHubs(t, false, true)
	agent, _ := twoAgents(t)
	card := signA2A(t, agent, a2aCardFor(agent, 1, relayAt(b.srv.URL),
		withSkills([]string{"echo", "Echo", "text"})))
	if got := registerA2A(t, b.srv, agent, "Agent", nil, card); got.CardStatus != aghub.CardStatusOK {
		t.Fatalf("register at B: %+v", got)
	}
	ctx := context.Background()

	// hub-local by default: the card does not travel.
	a.fed.SyncOnce(ctx)
	if _, listed := fedRegistry(t, a.store, aghub.RegistryQuery{})[agent.AID()]; listed {
		t.Fatal("a hub-local agent's A2A card reached the peer")
	}

	setVisibility(t, b.srv, agent, aghub.VisibilityFederated)
	a.fed.SyncOnce(ctx)
	l := registry(t, a.srv, "?skill=echo")
	var entry *aghub.A2AAgentEntry
	for i := range l.Agents {
		if l.Agents[i].AID == agent.AID() {
			entry = &l.Agents[i]
		}
	}
	if entry == nil {
		t.Fatalf("the federated card is not in A's registry: %v", registryAIDs(l))
	}
	if entry.HomeHub != b.srv.URL || entry.CardVerification != aghub.CardVerificationOK || entry.VerifiedAt == "" {
		t.Fatalf("A's entry: homeHub %q verification %q verifiedAt %q", entry.HomeHub, entry.CardVerification, entry.VerifiedAt)
	}
	// The card A serves is the agent's statement: it verifies against the
	// agent's KEL and makes the statement the agent signed.
	resolve := func(string) ([]identity.SignedEvent, error) { return agent.KEL(), nil }
	want, err := a2acard.Verify(card, resolve, uint64(time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	code, served := getJSON(t, a.srv.URL+"/a2a/v1/agents/"+agent.AID()+"/card")
	if code != http.StatusOK {
		t.Fatalf("A's card endpoint: %d %s", code, served)
	}
	for _, raw := range [][]byte{entry.Card, served} {
		got, err := a2acard.Verify(raw, resolve, uint64(time.Now().UnixMilli()))
		if err != nil || got.PayloadHash != want.PayloadHash {
			t.Fatalf("the card at A does not verify as the agent's: %v", err)
		}
	}
	// /agents names the agent from its card, with its home.
	if v := directoryEntry(t, a.srv, "echo", agent.AID()); v == nil || v.Name != "Test Agent" || v.HomeHub != b.srv.URL {
		t.Fatalf("A's /agents entry: %+v", v)
	}
	// B still answers for its own agent with its own origin.
	if l := registry(t, b.srv, ""); len(l.Agents) != 1 || l.Agents[0].HomeHub != b.srv.URL {
		t.Fatalf("B's registry: %+v", l)
	}

	// A key set published later moves the card on the stream, and the
	// peer answers key lookups from it.
	ks, _ := mintKeySet(t, agent, 1)
	if code, body := publishKeys(t, b.srv, agent, ks); code != http.StatusOK {
		t.Fatalf("publish keys: %d %s", code, body)
	}
	a.fed.SyncOnce(ctx)
	code, body := getJSON(t, a.srv.URL+"/agents/"+agent.AID()+"/keys")
	if code != http.StatusOK {
		t.Fatalf("keys at A: %d %s", code, body)
	}
	var view aghub.KeysView
	_ = json.Unmarshal(body, &view)
	if got, _ := base64.StdEncoding.DecodeString(view.KeySet); !bytes.Equal(got, ks) {
		t.Fatal("A answered with another key set")
	}
}

// A card entry is admitted only if the card verifies against the entry's
// KEL for the AID that KEL replays to, and passes the params.seq
// high-water rule against the card held; a refused entry changes nothing.
func TestAFederatedA2ACardThatDoesNotVerifyIsRefused(t *testing.T) {
	peer := openPeerStore(t)
	agent, other := twoAgents(t)
	good := signA2A(t, agent, a2aCardFor(agent, 5))

	for _, tc := range []struct {
		name  string
		entry aghub.FedA2ACard
		code  a2acard.Code
	}{
		{"edited after signing", a2aEntry(t, agent, editSigned(t, good, func(m map[string]any) { m["name"] = "Forged" })),
			a2acard.CodeInvalidSignature},
		{"another agent's KEL", a2aEntry(t, other, good), a2acard.CodeBindingMismatch},
		{"signed by another agent", a2aEntry(t, agent, signA2A(t, other, a2aCardFor(agent, 5))), a2acard.CodeBindingMismatch},
		{"unsigned", a2aEntry(t, agent, editSigned(t, good, func(m map[string]any) { delete(m, "signatures") })),
			a2acard.CodeUnsigned},
	} {
		err := peer.AdmitFedA2ACard(homePeerAID, tc.entry)
		if !a2acard.IsCode(err, tc.code) {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
	malformed := a2aEntry(t, agent, good)
	malformed.KEL = []byte("not a kel")
	if err := peer.AdmitFedA2ACard(homePeerAID, malformed); err == nil {
		t.Error("an entry whose KEL does not decode was admitted")
	}
	unknown := a2aEntry(t, agent, good)
	unknown.Format = "a2a-card/9"
	if err := peer.AdmitFedA2ACard(homePeerAID, unknown); err == nil {
		t.Error("an entry in an unknown format was admitted")
	}
	if len(fedRegistry(t, peer, aghub.RegistryQuery{})) != 0 {
		t.Fatal("a refused entry was listed")
	}

	if err := peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, agent, good)); err != nil {
		t.Fatalf("the good card: %v", err)
	}
	for _, tc := range []struct {
		name string
		card json.RawMessage
		code a2acard.Code
	}{
		{"lower seq", signA2A(t, agent, a2aCardFor(agent, 4)), a2acard.CodeSeqRollback},
		{"same seq, other payload", signA2A(t, agent, a2aCardFor(agent, 5, func(m map[string]any) { m["name"] = "Other" })),
			a2acard.CodeSeqFork},
	} {
		if err := peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, agent, tc.card)); !a2acard.IsCode(err, tc.code) {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
	got, err := peer.VerifiedA2ACard(agent.AID(), true)
	if err != nil || !bytes.Equal(got, good) {
		t.Fatalf("the held card changed: %s %v", got, err)
	}
	if got, _ := peer.VerifiedA2ACard(agent.AID(), false); got != nil {
		t.Error("a federated card was served by a hub whose discovery is off")
	}
	// Same card again: unchanged, still admitted.
	if err := peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, agent, good)); err != nil {
		t.Fatalf("the same card again: %v", err)
	}
}

// The KEL in a card entry may only extend the one held (§3.8): a card
// over the pre-rotation KEL, or over a forked one, is refused even though
// it verifies against the KEL it came with.
func TestAFederatedA2ACardCannotRollBackOrForkTheKEL(t *testing.T) {
	peer := openPeerStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := agent.Export()
	before, _ := identity.Restore(blob)
	forked, _ := identity.Restore(blob)
	if err := agent.Rotate(uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, agent, signA2A(t, agent, a2aCardFor(agent, 1)))); err != nil {
		t.Fatalf("the rotated card: %v", err)
	}
	err = peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, before, signA2A(t, before, a2aCardFor(before, 2))))
	if !errors.Is(err, identity.ErrKELRollback) {
		t.Fatalf("a newer card over the pre-rotation KEL: %v, want a rollback refusal", err)
	}
	if err := forked.Rotate(uint64(time.Now().UnixMilli()) + 7); err != nil {
		t.Fatal(err)
	}
	err = peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, forked, signA2A(t, forked, a2aCardFor(forked, 3))))
	if !errors.Is(err, identity.ErrKELFork) {
		t.Fatalf("a card over a forked KEL: %v, want a fork refusal", err)
	}
	// The agent itself, rotating further, still goes through.
	if err := agent.Rotate(uint64(time.Now().UnixMilli()) + 11); err != nil {
		t.Fatal(err)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, agent, signA2A(t, agent, a2aCardFor(agent, 4)))); err != nil {
		t.Fatalf("an extending KEL was refused: %v", err)
	}
}

// Where a federated agent lives is what its card's relay interface says
// when that disagrees with the entry's home, and the disagreement is
// logged; a card with no relay interface is homed where the entry says.
func TestAFederatedA2ACardsHomeIsTheCardsRelayInterface(t *testing.T) {
	peer := openPeerStore(t)
	agent, direct := twoAgents(t)
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	// a2aCardFor's relay interface is https://hub.example.org/relay; the
	// entry says testHome.
	if err := peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, agent, signA2A(t, agent, a2aCardFor(agent, 1)))); err != nil {
		t.Fatal(err)
	}
	noRelay := func(card map[string]any) {
		card["supportedInterfaces"] = []any{map[string]any{
			"url": "https://direct.example/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
		}}
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, direct, signA2A(t, direct, a2aCardFor(direct, 1, noRelay)))); err != nil {
		t.Fatal(err)
	}
	reg := fedRegistry(t, peer, aghub.RegistryQuery{})
	if got := reg[agent.AID()].HomeHub; got != "https://hub.example.org" {
		t.Errorf("home of a card whose relay interface disagrees with the entry: %q, want the card's", got)
	}
	if got := reg[direct.AID()].HomeHub; got != testHome {
		t.Errorf("home of a card with no relay interface: %q, want the entry's %q", got, testHome)
	}
	if got := peer.HomeHubOf(agent.AID()); got != "https://hub.example.org" {
		t.Errorf("HomeHubOf: %q", got)
	}
	if !strings.Contains(logged.String(), "https://hub.example.org") || !strings.Contains(logged.String(), testHome) {
		t.Errorf("the disagreement was not logged: %q", logged.String())
	}
}

// Narrowing the visibility withdraws the card from the stream; the peer
// that taught the card delists it (another peer's withdrawal does
// nothing), keeps its high-water mark, and relists it when the agent opts
// in again, which also takes the withdrawal off the stream. Leaving
// withdraws too.
func TestAWithdrawnA2ACardLeavesThePeersRegistry(t *testing.T) {
	hub := newFedHub(t)
	peer := openPeerStore(t)
	agent, _ := twoAgents(t)
	registerA2A(t, hub.srv, agent, "Agent", nil, signA2A(t, agent, a2aCardFor(agent, 1)))
	if entries, _ := a2aStream(t, hub.store, 0); len(entries) != 0 {
		t.Fatalf("a hub-local agent's card is on the stream: %+v", entries)
	}
	setVisibility(t, hub.srv, agent, aghub.VisibilityFederated)
	entries, cursor := a2aStream(t, hub.store, 0)
	if len(entries) != 1 || entries[0].Format != federation.FormatA2ACard || entries[0].Home != testHome {
		t.Fatalf("stream after opting in: %+v", entries)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, entries[0]); err != nil {
		t.Fatal(err)
	}
	ks, _ := mintKeySet(t, agent, 1)
	if code, body := publishKeys(t, hub.srv, agent, ks); code != http.StatusOK {
		t.Fatalf("publish keys: %d %s", code, body)
	}
	entries, cursor = a2aStream(t, hub.store, cursor)
	if len(entries) != 1 || !bytes.Equal(entries[0].Keys, ks) {
		t.Fatalf("a new key set did not move the card: %+v", entries)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, entries[0]); err != nil {
		t.Fatal(err)
	}

	setVisibility(t, hub.srv, agent, aghub.VisibilityHubLocal)
	entries, cursor = a2aStream(t, hub.store, cursor)
	if len(entries) != 1 {
		t.Fatalf("narrowing: %+v", entries)
	}
	if aid, reason := withdrawnAID(t, entries[0]); aid != agent.AID() || reason != "visibility-narrowed" {
		t.Fatalf("withdrawal names %q for %q", aid, reason)
	}
	withdrawal := entries[0]
	if err := peer.AdmitFedA2ACard("did:anet:other-hub", withdrawal); err != nil {
		t.Fatal(err)
	}
	if _, listed := fedRegistry(t, peer, aghub.RegistryQuery{})[agent.AID()]; !listed {
		t.Fatal("a peer that did not teach the card withdrew it")
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, withdrawal); err != nil {
		t.Fatal(err)
	}
	if _, listed := fedRegistry(t, peer, aghub.RegistryQuery{})[agent.AID()]; listed {
		t.Fatal("the withdrawn card is still listed")
	}
	if _, _, err := peer.FedA2ACardKeys(agent.AID()); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("the withdrawn card's key set is still served: %v", err)
	}
	if agents, _ := peer.FederatedAgents(""); len(agents) != 0 {
		t.Errorf("the withdrawn card is still in /agents: %+v", agents)
	}
	// The mark outlives the withdrawal: an older card is still refused.
	older := a2aEntry(t, agent, signA2A(t, agent, a2aCardFor(agent, 0)))
	if err := peer.AdmitFedA2ACard(homePeerAID, older); !a2acard.IsCode(err, a2acard.CodeSeqRollback) {
		t.Fatalf("an older card after the withdrawal: %v, want SEQ_ROLLBACK", err)
	}

	// Opting in again puts the card past the withdrawal, and the
	// withdrawal leaves the stream.
	setVisibility(t, hub.srv, agent, aghub.VisibilityPublic)
	entries, cursor = a2aStream(t, hub.store, cursor)
	if len(entries) != 1 || entries[0].Format != federation.FormatA2ACard {
		t.Fatalf("opting in again: %+v", entries)
	}
	if all, _ := a2aStream(t, hub.store, 0); len(all) != 1 || all[0].Format != federation.FormatA2ACard {
		t.Fatalf("the full stream after opting in again: %+v", all)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, entries[0]); err != nil {
		t.Fatal(err)
	}
	if _, listed := fedRegistry(t, peer, aghub.RegistryQuery{})[agent.AID()]; !listed {
		t.Fatal("the card published again was not relisted")
	}

	if code, body := leave(t, hub.srv, agent); code != http.StatusOK {
		t.Fatalf("deregister: %d %s", code, body)
	}
	entries, _ = a2aStream(t, hub.store, cursor)
	if len(entries) != 1 {
		t.Fatalf("leaving: %+v", entries)
	}
	if aid, reason := withdrawnAID(t, entries[0]); aid != agent.AID() || reason != "deregistered" {
		t.Fatalf("withdrawal names %q for %q", aid, reason)
	}
}

// A rotation that retires the key a card was signed with delists the card
// here and withdraws it from the stream; the card re-signed under the new
// key goes out again, and the peer takes the new bytes over the extended
// KEL.
func TestARotationWithdrawsTheCardUntilItIsResigned(t *testing.T) {
	hub := newFedHub(t)
	peer := openPeerStore(t)
	agent, _ := twoAgents(t)
	unsigned := a2aCardFor(agent, 1)
	registerA2A(t, hub.srv, agent, "Agent", nil, signA2A(t, agent, unsigned))
	setVisibility(t, hub.srv, agent, aghub.VisibilityFederated)
	entries, cursor := a2aStream(t, hub.store, 0)
	if len(entries) != 1 {
		t.Fatalf("stream: %+v", entries)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, entries[0]); err != nil {
		t.Fatal(err)
	}

	if err := agent.Rotate(uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	registerA2A(t, hub.srv, agent, "Agent", nil, nil)
	entries, cursor = a2aStream(t, hub.store, cursor)
	if len(entries) != 1 {
		t.Fatalf("after the rotation: %+v", entries)
	}
	if aid, reason := withdrawnAID(t, entries[0]); aid != agent.AID() || reason != "card-no-longer-verifies" {
		t.Fatalf("withdrawal names %q for %q", aid, reason)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, entries[0]); err != nil {
		t.Fatal(err)
	}

	resigned := signA2A(t, agent, unsigned)
	if got := registerA2A(t, hub.srv, agent, "Agent", nil, resigned); got.CardStatus != aghub.CardStatusUnchanged {
		t.Fatalf("the re-signed card: %+v", got)
	}
	entries, _ = a2aStream(t, hub.store, cursor)
	if len(entries) != 1 || entries[0].Format != federation.FormatA2ACard {
		t.Fatalf("after re-signing: %+v", entries)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, entries[0]); err != nil {
		t.Fatalf("the re-signed card at the peer: %v", err)
	}
	if got, _ := peer.VerifiedA2ACard(agent.AID(), true); !bytes.Equal(got, resigned) {
		t.Fatal("the peer kept the card signed under the retired key")
	}
}

// An agent registered here speaks for itself: a peer's copy of its card is
// refused for now, which holds the sync cursor (federation.ErrRefusedForNow).
func TestAFederatedA2ACardOfALocalAgentIsRefusedForNow(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	registerA2A(t, hub.srv, agent, "Agent", nil, nil)
	err := hub.store.AdmitFedA2ACard(homePeerAID, a2aEntry(t, agent, signA2A(t, agent, a2aCardFor(agent, 1))))
	if !errors.Is(err, federation.ErrRefusedForNow) {
		t.Fatalf("a peer's card of a local agent: %v, want refused for now", err)
	}
}

// v1 and v2 run side by side: an agent that registered an ADP card and an
// A2A card is on both streams, a peer admits both, and its directory lists
// the agent once, from the A2A card.
func TestTheADPAndA2ACardStreamsCoexist(t *testing.T) {
	hub := newFedHub(t)
	peer := openPeerStore(t)
	agent, _ := twoAgents(t)
	body := registerBody(t, agent, "ADP name", []string{"adp.cap"})
	body["card"] = mintCard(t, agent, "ADP name", []string{"adp.cap"})
	body["a2a_card"] = signA2A(t, agent, a2aCardFor(agent, 1))
	if code, b := signedDo(t, hub.srv, agent, relayauth.ActionRegister, http.MethodPost, "/register", body); code != http.StatusOK {
		t.Fatalf("register: %d %s", code, b)
	}
	setVisibility(t, hub.srv, agent, aghub.VisibilityFederated)

	v1, _, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil || len(v1) != 1 {
		t.Fatalf("v1 stream: %+v %v", v1, err)
	}
	v2, _ := a2aStream(t, hub.store, 0)
	if len(v2) != 1 {
		t.Fatalf("v2 stream: %+v", v2)
	}
	if err := peer.AdmitFedCard(homePeerAID, v1[0]); err != nil {
		t.Fatal(err)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, v2[0]); err != nil {
		t.Fatal(err)
	}
	agents, err := peer.FederatedAgents("")
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].Name != "Test Agent" || strings.Join(agents[0].Caps, ",") != "echo" {
		t.Fatalf("the peer's directory: %+v, want one entry from the A2A card", agents)
	}
	if byADP, _ := peer.FederatedAgents("adp.cap"); len(byADP) != 0 {
		t.Errorf("the ADP card answered for an agent with an A2A card: %+v", byADP)
	}
	if bySkill, _ := peer.FederatedAgents("echo"); len(bySkill) != 1 {
		t.Errorf("the A2A card's skill id does not find the agent: %+v", bySkill)
	}
}
