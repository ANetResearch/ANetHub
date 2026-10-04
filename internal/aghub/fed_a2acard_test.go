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
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
)

// Federation of A2A cards, GET /fed/v2/cards (A2A-DESIGN §10.6): the
// stream a hub serves, admission of what a peer serves, withdrawals, the
// key set that travels with a card, and the home of a federated agent.

const testHome = "https://home.example"

// homePeerAID is the AID a consuming store files the learned cards under.
const homePeerAID = "did:anet:home-hub"

// fedHub is a hub plus its store, because these tests act as both the
// agent (over HTTP) and the stream a peer reads (on the store).
type fedHub struct {
	srv   *httptest.Server
	store *aghub.Store
}

func newFedHub(t *testing.T) *fedHub {
	t.Helper()
	srv, store := newHubWithStore(t)
	return &fedHub{srv: srv, store: store}
}

// openPeerStore is a second hub's store, admitting what the first serves.
func openPeerStore(t *testing.T) *aghub.Store {
	t.Helper()
	st, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// federate registers c at hub with a signed A2A card naming caps as its
// skills, and opts it into federation. It returns the card.
func federate(t *testing.T, hub *fedHub, c *identity.Controller, name string, caps []string) json.RawMessage {
	t.Helper()
	card := signA2A(t, c, a2aCardNamed(c, 1, name, caps))
	if got := registerA2A(t, hub.srv, c, name, nil, card); got.CardStatus != aghub.CardStatusOK {
		t.Fatalf("register %s: %+v", name, got)
	}
	setVisibility(t, hub.srv, c, aghub.VisibilityFederated)
	return card
}

// a2aCardNamed is a2aCardFor with the card's name and one skill per
// capability id.
func a2aCardNamed(c *identity.Controller, seq uint64, name string, caps []string) map[string]any {
	var skills [][]string
	for _, id := range caps {
		skills = append(skills, []string{id, id, "test"})
	}
	return a2aCardFor(c, seq, withSkills(skills...), func(card map[string]any) { card["name"] = name })
}

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
// named in /agents from the card, and its key history and key set travel
// with the entry in the peer's registry (sealed-sender SSR-H18), not by the
// peer's /agents/{aid}/keys, which answers for its own agents only. Before
// the agent opts in, nothing travels.
func TestAnA2ACardFederatesToAPeersRegistry(t *testing.T) {
	a, b := federatedHubs(t, true)
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
	// peer's registry entry carries it.
	ks, _ := mintKeySet(t, agent, 1)
	if code, body := publishKeys(t, b.srv, agent, ks); code != http.StatusOK {
		t.Fatalf("publish keys: %d %s", code, body)
	}
	a.fed.SyncOnce(ctx)
	entry = nil
	for _, e := range registry(t, a.srv, "?skill=echo").Agents {
		if e.AID == agent.AID() {
			entry = &e
		}
	}
	kel, _ := identity.MarshalKEL(agent.KEL())
	if entry == nil || entry.Keys != base64.RawURLEncoding.EncodeToString(ks) ||
		entry.KEL != base64.RawURLEncoding.EncodeToString(kel) {
		t.Fatalf("A's registry entry does not carry the agent's key history and key set: %+v", entry)
	}
	if code, body := getJSON(t, a.srv.URL+"/agents/"+agent.AID()+"/keys"); code != http.StatusNotFound {
		t.Fatalf("keys at A of an agent registered at B: %d %s, want 404", code, body)
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
	agent, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := agent.Export()
	before, _ := identity.Restore(blob)
	forked, _ := identity.Restore(blob)
	if err := identitytest.Rotate(agent, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, agent, signA2A(t, agent, a2aCardFor(agent, 1)))); err != nil {
		t.Fatalf("the rotated card: %v", err)
	}
	err = peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, before, signA2A(t, before, a2aCardFor(before, 2))))
	if !errors.Is(err, identity.ErrKELRollback) {
		t.Fatalf("a newer card over the pre-rotation KEL: %v, want a rollback refusal", err)
	}
	if err := identitytest.Rotate(forked, uint64(time.Now().UnixMilli())+7); err != nil {
		t.Fatal(err)
	}
	err = peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, forked, signA2A(t, forked, a2aCardFor(forked, 3))))
	if !errors.Is(err, identity.ErrKELFork) {
		t.Fatalf("a card over a forked KEL: %v, want a fork refusal", err)
	}
	// The agent itself, rotating further, still goes through.
	if err := identitytest.Rotate(agent, uint64(time.Now().UnixMilli())+11); err != nil {
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

	if err := identitytest.Rotate(agent, uint64(time.Now().UnixMilli())); err != nil {
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

// An agent this hub knows only by the A2A card a peer publishes can be
// reviewed by a user here, the review goes out on /fed/v1/reviews, and
// the agent is named from the card. Once the peer withdraws the card, the consent it stood for is
// gone and the review is no longer served.
func TestReviewsOfAnAgentKnownByItsA2ACardTravel(t *testing.T) {
	hub, store := newHubWithStore(t)
	provider, requester := twoAgents(t)
	register(t, hub, requester, "Requester", nil)
	if err := store.AdmitFedA2ACard(homePeerAID,
		a2aEntry(t, provider, signA2A(t, provider, a2aCardFor(provider, 1)))); err != nil {
		t.Fatal(err)
	}
	uploadInterlockedReview(t, hub, provider, requester, 5, "crossed")
	revs, _, err := store.ReviewsSince(0, 0)
	if err != nil || len(revs) != 1 {
		t.Fatalf("the review stream carried %d reviews (%v), want 1", len(revs), err)
	}
	if got := store.GraphNodeFor(provider.AID()).Name; got != "Test Agent" {
		t.Errorf("the agent is named %q, want its card's name", got)
	}

	w, err := json.Marshal(map[string]string{"action": "withdraw", "agent_id": provider.AID()})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdmitFedA2ACard(homePeerAID,
		aghub.FedA2ACard{Format: federation.FormatWithdrawal, Card: w}); err != nil {
		t.Fatal(err)
	}
	if revs, _, _ := store.ReviewsSince(0, 0); len(revs) != 0 {
		t.Errorf("a review of an agent whose card was withdrawn is still served: %d", len(revs))
	}
}

// A subject registered here is governed by its own visibility, whatever a
// peer's copy of its card left behind from before it registered: a
// hub-local agent's reviews stay here.
func TestAPeersStaleCardDoesNotPublishALocalAgentsReviews(t *testing.T) {
	hub, store := newHubWithStore(t)
	provider, requester := twoAgents(t)
	if err := store.AdmitFedA2ACard(homePeerAID,
		a2aEntry(t, provider, signA2A(t, provider, a2aCardFor(provider, 1)))); err != nil {
		t.Fatal(err)
	}
	register(t, hub, provider, "Provider", []string{"work.do"}) // hub-local
	register(t, hub, requester, "Requester", nil)
	uploadInterlockedReview(t, hub, provider, requester, 4, "local")
	if revs, _, _ := store.ReviewsSince(0, 0); len(revs) != 0 {
		t.Fatalf("a hub-local agent's review was published: %d", len(revs))
	}
	setVisibility(t, hub, provider, aghub.VisibilityFederated)
	if revs, _, _ := store.ReviewsSince(0, 0); len(revs) != 1 {
		t.Fatalf("the review of an agent that opted in: %d, want 1", len(revs))
	}
}

// A peer-learned KEL follows the agent's rotation: the card re-signed
// after it arrives over the extended KEL, the extended KEL is the one
// this hub checks evidence against, and a receipt signed under the new
// key verifies.
func TestAPeerLearnedKELFollowsTheAgentsRotation(t *testing.T) {
	hub, store := newHubWithStore(t)
	provider, requester := twoAgents(t)
	register(t, hub, requester, "Requester", nil)
	unsigned := a2aCardFor(provider, 1)
	if err := store.AdmitFedA2ACard(homePeerAID, a2aEntry(t, provider, signA2A(t, provider, unsigned))); err != nil {
		t.Fatal(err)
	}
	if err := identitytest.Rotate(provider, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if err := store.AdmitFedA2ACard(homePeerAID, a2aEntry(t, provider, signA2A(t, provider, unsigned))); err != nil {
		t.Fatalf("the card re-signed after the rotation: %v", err)
	}
	after, _ := identity.MarshalKEL(provider.KEL())
	if got, err := store.AnyKEL(provider.AID()); err != nil || !bytes.Equal(got, after) {
		t.Fatalf("AnyKEL served the KEL before the rotation (%v)", err)
	}
	body := makeEvidence(t, provider, requester, "ix-rotated", 5, "")
	if code, b := post(t, hub.URL+"/reviews", body); code != http.StatusOK {
		t.Fatalf("a receipt signed under the rotated key: %d %s", code, b)
	}
}

// A card no peer was ever offered is removed, not announced. A withdrawal
// names an AID, and emitting one for a hub-local agent would publish, in
// the act of leaving, exactly what the hub-local tier exists to keep
// unpublished.
func TestAHubLocalAgentIsNotNamedWhenItLeaves(t *testing.T) {
	hub := newFedHub(t)
	private, public := twoAgents(t)
	registerA2A(t, hub.srv, private, "Private", nil, signA2A(t, private, a2aCardFor(private, 1)))
	federate(t, hub, public, "Public", []string{"work.do"})
	if code, b := leave(t, hub.srv, private); code != http.StatusOK {
		t.Fatalf("deregister: %d %s", code, b)
	}
	entries, _ := a2aStream(t, hub.store, 0)
	for _, e := range entries {
		if strings.Contains(string(e.Card), private.AID()) {
			t.Errorf("a hub-local agent's AID reached the federation stream on its way out: %s", e.Card)
		}
	}
	// The agent that did federate is still on the stream, so the check
	// above is not passing because the stream is empty.
	if len(entries) != 1 || entries[0].Format != federation.FormatA2ACard {
		t.Fatalf("the stream: %+v, want the one federated card", entries)
	}
}

// A card registered again must not quietly cancel a withdrawal no peer has
// read yet: while the agent stays hub-local the withdrawal stands, and the
// hub still lists the card it just accepted.
func TestRepublishingACardDoesNotCancelAStandingWithdrawal(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	federate(t, hub, agent, "Shy", []string{"work.do"})
	_, cursor := a2aStream(t, hub.store, 0)
	setVisibility(t, hub.srv, agent, aghub.VisibilityHubLocal)
	// The node re-registers — a restart, a capability change — before the
	// peer's next sync round.
	more := signA2A(t, agent, a2aCardNamed(agent, 2, "Shy", []string{"work.do", "work.more"}))
	if got := registerA2A(t, hub.srv, agent, "Shy", nil, more); got.CardStatus != aghub.CardStatusOK {
		t.Fatalf("re-register: %+v", got)
	}
	after, _ := a2aStream(t, hub.store, cursor)
	if len(after) != 1 {
		t.Fatalf("%d entries after the peer's cursor, want the standing withdrawal: %+v", len(after), after)
	}
	if aid, _ := withdrawnAID(t, after[0]); aid != agent.AID() {
		t.Fatalf("re-registering a card cancelled a withdrawal the peer had not read: %s", after[0].Card)
	}
	if d := directoryEntry(t, hub.srv, "work.more", agent.AID()); d == nil {
		t.Error("the card registered again is not the one the hub lists")
	}
}

// A withdrawal for an agent registered here can only touch the
// peer-learned copy, never the local registry or this hub's own stream.
func TestAPeerWithdrawalCannotUnregisterALocalAgent(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	federate(t, hub, agent, "Local", []string{"work.do"})
	_, cursor := a2aStream(t, hub.store, 0)
	// A real withdrawal of the same AID from a second hub, fed back to the
	// hub the agent actually lives on.
	other := newFedHub(t)
	federate(t, other, agent, "Local", []string{"work.do"})
	if code, b := leave(t, other.srv, agent); code != http.StatusOK {
		t.Fatalf("deregister on the other hub: %d %s", code, b)
	}
	stolen, _ := a2aStream(t, other.store, 0)
	if len(stolen) != 1 || stolen[0].Format != federation.FormatWithdrawal {
		t.Fatalf("setup: %+v", stolen)
	}
	if err := hub.store.AdmitFedA2ACard("did:anet:other-hub", stolen[0]); err != nil {
		t.Fatalf("the withdrawal errored rather than being ignored: %v", err)
	}
	if n := agentsServing(t, hub.srv, "work.do"); n != 1 {
		t.Fatalf("a peer's withdrawal removed an agent registered here (%d)", n)
	}
	if l := registry(t, hub.srv, ""); len(l.Agents) != 1 {
		t.Fatalf("a peer's withdrawal delisted an agent registered here: %+v", l.Agents)
	}
	if still, _ := a2aStream(t, hub.store, cursor); len(still) != 0 {
		t.Errorf("a peer's withdrawal changed this hub's own stream: %+v", still)
	}
}

// A federating agent's key set travels with its card, a new key set moves
// the card to the head of the stream, and the pulling hub stores the set
// only when it verifies for the card's subject and comes from the peer
// that taught the card; another AID's set is ignored, and the card itself
// is still admitted.
func TestKeysTravelWithTheCardAndAreVerifiedOnArrival(t *testing.T) {
	hub := newFedHub(t)
	agent, stranger := twoAgents(t)
	federate(t, hub, agent, "Keyed", []string{"work.do"})
	k1, _ := mintKeySet(t, agent, 1)
	if code, body := publishKeys(t, hub.srv, agent, k1); code != http.StatusOK {
		t.Fatalf("publish: %d %s", code, body)
	}
	entries, cursor := a2aStream(t, hub.store, 0)
	if len(entries) != 1 || !bytes.Equal(entries[0].Keys, k1) {
		t.Fatalf("the card entry does not carry the key set: %+v", entries)
	}
	peer := openPeerStore(t)
	if err := peer.AdmitFedA2ACard(homePeerAID, entries[0]); err != nil {
		t.Fatal(err)
	}
	stored := func() []byte {
		ks, _, _ := peer.FedA2ACardKeys(agent.AID())
		return ks
	}
	if !bytes.Equal(stored(), k1) {
		t.Fatal("the peer did not store the verified key set")
	}

	// A new set moves the card past the cursor a peer holds.
	k2, _ := mintKeySet(t, agent, 2)
	if code, body := publishKeys(t, hub.srv, agent, k2); code != http.StatusOK {
		t.Fatalf("publish 2: %d %s", code, body)
	}
	after, _ := a2aStream(t, hub.store, cursor)
	if len(after) != 1 || !bytes.Equal(after[0].Keys, k2) {
		t.Fatalf("a new key set did not reach the stream: %+v", after)
	}
	if err := peer.AdmitFedA2ACard(homePeerAID, after[0]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored(), k2) {
		t.Fatal("the peer kept the older set")
	}

	foreign, _ := mintKeySet(t, stranger, 99)
	swapped := after[0]
	swapped.Keys = foreign
	if err := peer.AdmitFedA2ACard(homePeerAID, swapped); err != nil {
		t.Fatalf("the card itself was refused: %v", err)
	}
	if !bytes.Equal(stored(), k2) {
		t.Error("another AID's key set was stored under this card")
	}
	// Only the peer that taught the card may update it: a valid, newer
	// set on the same card from a different peer is not stored.
	k3, _ := mintKeySet(t, agent, 3)
	fromOther := after[0]
	fromOther.Keys = k3
	if err := peer.AdmitFedA2ACard("did:anet:other-hub", fromOther); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored(), k2) {
		t.Fatal("a peer that did not teach the card replaced its key set")
	}
	// The federation seam carries the set both ways.
	views, _, err := aghub.FedDirectory{S: hub.store}.A2ACardsSince(cursor, 100, testHome)
	if err != nil || len(views) != 1 || !bytes.Equal(views[0].Keys, k2) {
		t.Fatalf("FedDirectory.A2ACardsSince dropped the key set: %+v %v", views, err)
	}
	other := openPeerStore(t)
	if err := (aghub.FedDirectory{S: other}).AdmitFedA2ACard(homePeerAID, views[0]); err != nil {
		t.Fatal(err)
	}
	if ks, _, _ := other.FedA2ACardKeys(agent.AID()); !bytes.Equal(ks, k2) {
		t.Fatal("FedDirectory.AdmitFedA2ACard dropped the key set")
	}
}

// The consumer rule on a peer's card stream (§3.1): a set below the stored
// seq is a rollback, a set with the stored seq and different content is a
// fork, and the stored set sent again under a broken signature does not
// replace the stored one; all three are ignored. They come from the peer
// that taught the card, so none is refused for coming from the wrong peer,
// and the card itself is still admitted.
func TestAPeerCannotForkOrCorruptAStoredKeySet(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	federate(t, hub, agent, "Keyed", []string{"work.do"})
	k2, _ := mintKeySet(t, agent, 2)
	if code, body := publishKeys(t, hub.srv, agent, k2); code != http.StatusOK {
		t.Fatalf("publish: %d %s", code, body)
	}
	entries, _ := a2aStream(t, hub.store, 0)
	if len(entries) != 1 {
		t.Fatalf("stream: %+v", entries)
	}
	peer := openPeerStore(t)
	if err := peer.AdmitFedA2ACard(homePeerAID, entries[0]); err != nil {
		t.Fatal(err)
	}
	stored := func() []byte {
		ks, _, _ := peer.FedA2ACardKeys(agent.AID())
		return ks
	}
	if !bytes.Equal(stored(), k2) {
		t.Fatal("setup: the peer did not store the set")
	}
	k1, _ := mintKeySet(t, agent, 1)
	fork, _ := mintKeySet(t, agent, 2) // same seq, other keys, validly signed
	for name, keys := range map[string][]byte{
		"a lower seq (a rollback)":                k1,
		"a fork (same seq, other content)":        fork,
		"the stored set under a broken signature": tamperSig(t, k2),
	} {
		e := entries[0]
		e.Keys = keys
		if err := peer.AdmitFedA2ACard(homePeerAID, e); err != nil {
			t.Fatalf("%s: the card itself was refused: %v", name, err)
		}
		if !bytes.Equal(stored(), k2) {
			t.Errorf("%s replaced the stored set", name)
		}
	}
}

// A peer's limits are not this hub's: an entry whose KEL is larger than a
// registration here could carry is refused before it is decoded.
func TestAFederatedA2ACardWithAnOversizedKELIsRefused(t *testing.T) {
	peer := openPeerStore(t)
	agent, _ := twoAgents(t)
	e := a2aEntry(t, agent, signA2A(t, agent, a2aCardFor(agent, 1)))
	e.KEL = append(e.KEL, make([]byte, 1<<20)...)
	if err := peer.AdmitFedA2ACard(homePeerAID, e); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("an oversized KEL: %v, want refused on size", err)
	}
}
