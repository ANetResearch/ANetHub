package aghub_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// fedDelivery adapts a store to federation.LocalDelivery the way
// cmd/anet-hub does, including the error mapping.
type fedDelivery struct{ s *aghub.Store }

func (d fedDelivery) HasAgent(aid string) bool { _, err := d.s.AgentKEL(aid); return err == nil }
func (d fedDelivery) Enqueue(to string, env []byte) (int64, error) {
	id, err := d.s.RelayEnqueue(to, env)
	switch {
	case errors.Is(err, aghub.ErrMailboxFull):
		return 0, fmt.Errorf("%w: %v", federation.ErrMailboxFull, err)
	case errors.Is(err, aghub.ErrBadEnvelope):
		return 0, fmt.Errorf("%w: %v", federation.ErrBadEnvelope, err)
	}
	return id, err
}

// fedHubNode is one hub with its federation service, wired as main.go
// and wire_federation.go wire them.
type fedHubNode struct {
	srv   *httptest.Server
	store *aghub.Store
	s     *aghub.Server
	id    *hubid.Identity
	fed   *federation.Service
	dir   string
	h     http.Handler
}

// twoFederatedHubs starts hubs A and B peered for delivery. keyLookup
// controls whether A installs the federated key lookup.
func twoFederatedHubs(t *testing.T, keyLookup bool) (a, b *fedHubNode) {
	t.Helper()
	return federatedHubs(t, keyLookup, false)
}

// federatedHubs is twoFederatedHubs, with the discovery sub-plane on as
// well when discovery is set: each hub publishes its directory with its
// own URL as home, pulls the other's (n.fed.SyncOnce), and lists what it
// learned, as wire_federation.go wires it.
func federatedHubs(t *testing.T, keyLookup, discovery bool) (a, b *fedHubNode) {
	t.Helper()
	mk := func() *fedHubNode {
		n := &fedHubNode{dir: t.TempDir()}
		n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n.h.ServeHTTP(w, r)
		}))
		t.Cleanup(n.srv.Close)
		store, err := aghub.Open(n.dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		id, err := hubid.LoadOrIncept(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		store.SetHubKey(id.Ctrl)
		n.store, n.id = store, id
		n.s = aghub.NewServer(store)
		n.s.SetHubAID(id.AID)
		testHubAID.Store(n.srv.URL, id.AID)
		testHubStores.Store(n.srv.URL, store)
		testHubServers.Store(n.srv.URL, n.s)
		return n
	}
	a, b = mk(), mk()
	wire := func(n, peer *fedHubNode, lookup bool) {
		cfg := federation.Config{Delivery: "allowlist",
			Peers: []federation.Peer{{AID: peer.id.AID, Endpoint: peer.srv.URL}}}
		if discovery {
			cfg.Discovery, cfg.Home = "allowlist", n.srv.URL
		}
		fed, err := federation.New(t.TempDir(), cfg, n.id, fedDelivery{n.store})
		if err != nil {
			t.Fatal(err)
		}
		if discovery {
			fed.SetDirectory(aghub.FedDirectory{S: n.store})
			n.s.SetFederatedDirectory(n.store.FederatedAgents)
		}
		t.Cleanup(func() { _ = fed.Close() })
		fed.SetKeySource(aghub.StoreKeySource{S: n.store})
		n.s.SetForwarder(fed.TryForward)
		if lookup {
			n.s.SetFederatedKeyLookup(fed.LookupKeys)
		}
		n.fed = fed
		mux := http.NewServeMux()
		mux.Handle("/hub/identity", n.id.Handler())
		mux.Handle("/fed/v1/", fed.Handler())
		mux.Handle("/fed/v2/", fed.Handler())
		mux.Handle("/", n.s.Handler())
		n.h = mux
	}
	wire(a, b, keyLookup)
	wire(b, a, keyLookup)
	return a, b
}

// A sender on hub A can fetch the key set of an agent registered on hub
// B with the default hub-local visibility, seal to it, and have the
// envelope forwarded; the agent is not listed at A and nothing about it is
// stored there ([C32]).
func TestAHubLocalAgentOnAPeerCanBeReachedEncrypted(t *testing.T) {
	a, b := twoFederatedHubs(t, true)
	recip, sender := twoAgents(t)
	register(t, b.srv, recip, "Provider", []string{"work.do"})
	register(t, a.srv, sender, "Requester", nil)
	recipKeys, kp := mintKeySet(t, recip, 1)
	if code, body := publishKeys(t, b.srv, recip, recipKeys); code != 200 {
		t.Fatalf("publish at B: %d %s", code, body)
	}

	code, body := getJSON(t, a.srv.URL+"/agents/"+recip.AID()+"/keys")
	if code != 200 {
		t.Fatalf("keys of a hub-local agent on a peer: %d %s", code, body)
	}
	var view aghub.KeysView
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(view.KeySet)
	if !bytes.Equal(raw, recipKeys) || view.AID != recip.AID() {
		t.Fatalf("hub A relayed a different key set: %+v", view)
	}
	// Nothing about the agent became part of A's directory.
	if listedContains(t, a.srv, recip.AID()) {
		t.Error("the looked-up agent is listed at A")
	}
	if _, _, err := a.store.FedCardKeys(recip.AID()); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("the lookup was stored at A: %v", err)
	}

	// Seal with what A served, send at A, collect at B.
	kelRaw, _ := base64.StdEncoding.DecodeString(view.KEL)
	events, _ := identity.UnmarshalKEL(kelRaw)
	signed, _ := seal.UnmarshalSignedEncKeySet(raw)
	set, err := seal.VerifyEncKeySet(signed, recip.AID(), events, uint64(time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := seal.SelectKey(set, uint64(time.Now().UnixMilli()))
	senderKeys, _ := mintKeySet(t, sender, 1)
	env := sealFrom(t, sender, senderKeys, recip.AID(), key, []byte("cross-hub task"))
	code, body, _ = relaySend(t, a.srv, sender, recip.AID(), env)
	if code != 200 || !strings.Contains(string(body), `"forwarded"`) {
		t.Fatalf("send at A for an agent on B: %d %s", code, body)
	}
	p := relayPoll(t, b.srv, recip)
	if len(p.Messages) != 1 {
		t.Fatalf("B's mailbox: %+v", p.Messages)
	}
	got, _ := base64.StdEncoding.DecodeString(p.Messages[0].Envelope)
	opened, err := seal.Open(got, recip.AID(), seal.StaticKeyRing{kp})
	if err != nil || string(opened.Inner.Body) != "cross-hub task" {
		t.Fatalf("open at the recipient: %v", err)
	}
	// Neither hub's relay table names the sender.
	for _, n := range []*fedHubNode{a, b} {
		db := openDB(t, n.dir)
		var hits int
		if err := db.QueryRow(`SELECT COUNT(*) FROM relay_message WHERE instr(CAST(to_aid AS BLOB), ?) > 0`,
			[]byte(sender.AID())).Scan(&hits); err != nil || hits != 0 {
			t.Errorf("a relay row names the sender: %d %v", hits, err)
		}
	}
}

// Without the federated lookup the same request is 404: the lookup, not
// some other path, is what serves a hub-local agent's keys to a peer.
func TestWithoutTheFederatedLookupAPeersHubLocalAgentHasNoKeys(t *testing.T) {
	a, b := twoFederatedHubs(t, false)
	recip, _ := twoAgents(t)
	register(t, b.srv, recip, "Provider", []string{"work.do"})
	k, _ := mintKeySet(t, recip, 1)
	if code, body := publishKeys(t, b.srv, recip, k); code != 200 {
		t.Fatalf("publish: %d %s", code, body)
	}
	if code, body := getJSON(t, a.srv.URL+"/agents/"+recip.AID()+"/keys"); code != http.StatusNotFound {
		t.Fatalf("without the lookup: %d %s, want 404", code, body)
	}
}

// A key set a peer serves is relayed only when it verifies for the AID
// that was asked for; another AID's valid set is not passed off as it.
func TestAPeersKeySetForAnotherAIDIsNotRelayed(t *testing.T) {
	srv := newHub(t)
	asked, other := twoAgents(t)
	otherKeys, _ := mintKeySet(t, other, 1)
	otherKEL, _ := identity.MarshalKEL(other.KEL())
	serverOf(t, srv).SetFederatedKeyLookup(func(_ context.Context, aid string, accept func(ks, kel []byte) error) ([]byte, []byte, string, error) {
		if err := accept(otherKeys, otherKEL); err != nil {
			return nil, nil, "", fmt.Errorf("peer answer refused: %w", err)
		}
		return otherKeys, otherKEL, "did:anet:peer", nil
	})
	if code, body := getJSON(t, srv.URL+"/agents/"+asked.AID()+"/keys"); code == http.StatusOK {
		t.Fatalf("another AID's key set was relayed: %s", body)
	}
}

// ---- keys and KELs in the card sync stream ----

// A federating agent's key set travels with its card, a new key set moves
// the card to the head of the stream, and the pulling hub stores the set
// only when it verifies for the card's subject.
func TestKeysTravelWithTheCardAndAreVerifiedOnArrival(t *testing.T) {
	hub := newFedHub(t)
	agent, stranger := twoAgents(t)
	federate(t, hub, agent, "Keyed", []string{"work.do"})
	k1, _ := mintKeySet(t, agent, 1)
	if code, body := publishKeys(t, hub.srv, agent, k1); code != 200 {
		t.Fatalf("publish: %d %s", code, body)
	}
	cards, cursor, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil || len(cards) != 1 {
		t.Fatalf("stream: %v %v", cards, err)
	}
	if cards[0].Keys != base64.StdEncoding.EncodeToString(k1) {
		t.Fatal("the card entry does not carry the key set")
	}
	peer := openPeerStore(t)
	if err := peer.AdmitFedCard(homePeerAID, cards[0]); err != nil {
		t.Fatal(err)
	}
	if ks, _, err := peer.FedCardKeys(agent.AID()); err != nil || !bytes.Equal(ks, k1) {
		t.Fatalf("the peer did not store the verified key set: %v", err)
	}

	// A new set moves the card past the cursor a peer holds.
	k2, _ := mintKeySet(t, agent, 2)
	if code, body := publishKeys(t, hub.srv, agent, k2); code != 200 {
		t.Fatalf("publish 2: %d %s", code, body)
	}
	after, _, err := hub.store.CardsSince(cursor, 100, testHome)
	if err != nil || len(after) != 1 || after[0].Keys != base64.StdEncoding.EncodeToString(k2) {
		t.Fatalf("a new key set did not reach the stream: %+v %v", after, err)
	}
	if err := peer.AdmitFedCard(homePeerAID, after[0]); err != nil {
		t.Fatal(err)
	}
	if ks, _, _ := peer.FedCardKeys(agent.AID()); !bytes.Equal(ks, k2) {
		t.Fatal("the peer kept the older set")
	}

	// A stale set, and another AID's set, are ignored; the card itself is
	// still admitted.
	stale := after[0]
	stale.Keys = base64.StdEncoding.EncodeToString(k1)
	if err := peer.AdmitFedCard(homePeerAID, stale); err != nil {
		t.Fatal(err)
	}
	if ks, _, _ := peer.FedCardKeys(agent.AID()); !bytes.Equal(ks, k2) {
		t.Fatal("a lower seq replaced the stored set")
	}
	foreign, _ := mintKeySet(t, stranger, 99)
	swapped := after[0]
	swapped.Keys = base64.StdEncoding.EncodeToString(foreign)
	if err := peer.AdmitFedCard(homePeerAID, swapped); err != nil {
		t.Fatal(err)
	}
	if ks, _, _ := peer.FedCardKeys(agent.AID()); !bytes.Equal(ks, k2) {
		t.Fatal("another AID's key set was stored under this card")
	}
	// Only the peer that taught the card may update it: a valid, newer
	// set on the same card from a different peer is not stored.
	k3, _ := mintKeySet(t, agent, 3)
	fromOther := after[0]
	fromOther.Keys = base64.StdEncoding.EncodeToString(k3)
	if err := peer.AdmitFedCard("did:anet:other-hub", fromOther); err != nil {
		t.Fatal(err)
	}
	if ks, _, _ := peer.FedCardKeys(agent.AID()); !bytes.Equal(ks, k2) {
		t.Fatal("a peer that did not teach the card replaced its key set")
	}
	// The federation seam carries the set both ways.
	views, _, err := aghub.FedDirectory{S: hub.store}.CardsSince(cursor, 100, testHome)
	if err != nil || len(views) != 1 || !bytes.Equal(views[0].Keys, k2) {
		t.Fatalf("FedDirectory.CardsSince dropped the key set: %+v %v", views, err)
	}
	other := openPeerStore(t)
	if err := (aghub.FedDirectory{S: other}).AdmitFedCard(homePeerAID, views[0].Card, views[0].KEL, views[0].Keys, testHome); err != nil {
		t.Fatal(err)
	}
	if ks, _, _ := other.FedCardKeys(agent.AID()); !bytes.Equal(ks, k2) {
		t.Fatal("FedDirectory.AdmitFedCard dropped the key set")
	}
}

// A card entry whose KEL is shorter than, or forked from, the KEL already
// held for the agent is refused (§3.8).
func TestAFederatedCardCannotRollBackOrForkTheKEL(t *testing.T) {
	hub := newFedHub(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := agent.Export()
	before, _ := identity.Restore(blob)
	forked, _ := identity.Restore(blob)
	federate(t, hub, agent, "Agent", []string{"work.do"})
	if err := agent.Rotate(uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	register(t, hub.srv, agent, "Agent", []string{"work.do"})
	cards, _, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil || len(cards) != 1 {
		t.Fatalf("stream: %v %v", cards, err)
	}
	peer := openPeerStore(t)
	if err := peer.AdmitFedCard(homePeerAID, cards[0]); err != nil {
		t.Fatalf("the rotated card: %v", err)
	}
	entryFor := func(c *identity.Controller) aghub.FedCard {
		kel, _ := identity.MarshalKEL(c.KEL())
		return aghub.FedCard{Card: mintCard(t, c, "Agent", []string{"work.do"}),
			KEL: base64.StdEncoding.EncodeToString(kel), Home: testHome}
	}
	err = peer.AdmitFedCard(homePeerAID, entryFor(before))
	if err == nil || !errors.Is(err, identity.ErrKELRollback) {
		t.Fatalf("a newer card over the pre-rotation KEL: %v, want a rollback refusal", err)
	}
	if err := forked.Rotate(uint64(time.Now().UnixMilli()) + 7); err != nil {
		t.Fatal(err)
	}
	err = peer.AdmitFedCard(homePeerAID, entryFor(forked))
	if err == nil || !errors.Is(err, identity.ErrKELFork) {
		t.Fatalf("a card over a forked KEL: %v, want a fork refusal", err)
	}
	// The agent itself, rotating further, still goes through.
	if err := agent.Rotate(uint64(time.Now().UnixMilli()) + 11); err != nil {
		t.Fatal(err)
	}
	if err := peer.AdmitFedCard(homePeerAID, entryFor(agent)); err != nil {
		t.Fatalf("an extending KEL was refused: %v", err)
	}
}
