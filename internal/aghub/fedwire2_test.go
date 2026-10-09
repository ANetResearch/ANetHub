package aghub_test

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

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

// twoFederatedHubs starts hubs A and B peered for delivery.
func twoFederatedHubs(t *testing.T) (a, b *fedHubNode) {
	t.Helper()
	return federatedHubs(t, false)
}

// federatedHubs is twoFederatedHubs, with the discovery sub-plane on as
// well when discovery is set: each hub publishes its directory with its
// own URL as home, pulls the other's (n.fed.SyncOnce), and lists what it
// learned, as wire_federation.go wires it.
func federatedHubs(t *testing.T, discovery bool) (a, b *fedHubNode) {
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
	wire := func(n, peer *fedHubNode) {
		cfg := federation.Config{Delivery: "allowlist",
			Peers: []federation.Peer{{AID: peer.id.AID, Endpoint: peer.srv.URL}}}
		if discovery {
			cfg.Discovery, cfg.Home = "allowlist", n.srv.URL
		}
		fed, err := federation.New(t.TempDir(), cfg, n.id)
		if err != nil {
			t.Fatal(err)
		}
		if discovery {
			fed.SetDirectory(aghub.FedDirectory{S: n.store})
			n.s.SetFederatedDirectory(n.store.FederatedAgents)
		}
		t.Cleanup(func() { _ = fed.Close() })
		fed.SetKernel(n.s)
		n.s.SetFederation(fed)
		// As wire_federation.go does: the peer's key history, which checks
		// the witness notice its directory entries carry.
		n.s.SetPeerKELResolver(fed.PeerKEL)
		n.fed = fed
		mux := http.NewServeMux()
		mux.Handle("/hub/identity", n.id.Handler())
		mux.Handle("/fed/v3/", fed.Handler())
		mux.Handle("/", n.s.Handler())
		n.h = wire3.Contract(mux)
	}
	wire(a, b)
	wire(b, a)
	return a, b
}

// A sender on hub A writes to an agent registered on hub B with the default
// hub-local visibility. It finds the agent's key set where a daemon does,
// in A's answer for the agent's directory bucket, which merges B's
// (sealed-sender SSR-W19), and the entry, opened with the AID, names B as
// the agent's home. Hub A serves nothing of the agent by its AID: not its
// keys (it answers only for its own agents, sealed-sender §2.7), not a
// listing, and it stores nothing about it ([C32]). The send at A that
// reaches B is TestASendAtAHubReachesAPeersAgent.
func TestAHubLocalAgentOnAPeerCanBeReachedEncrypted(t *testing.T) {
	a, b := twoFederatedHubs(t)
	recip, sender := twoAgents(t)
	register(t, b.srv, recip, "Provider", []string{"work.do"})
	register(t, a.srv, sender, "Requester", nil)
	recipKeys, kp := mintKeySet(t, recip, 1)
	if code, body := publishKeys(t, b.srv, recip, recipKeys); code != 200 {
		t.Fatalf("publish at B: %d %s", code, body)
	}
	if code, body := getJSON(t, a.srv.URL+"/agents/"+recip.AID()+"/keys"); code != http.StatusNotFound {
		t.Fatalf("keys of a peer's agent, asked at A: %d %s, want 404", code, body)
	}

	// The bucket, asked at A without naming the agent.
	h, err := dirbox.Hash(recip.AID())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, a.srv.URL+"/directory:bucket", strings.NewReader(`{"prefix":"","bits":0}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ANet-Wire", wireHeader)
	code, raw, _ := send(t, req)
	var out aghub.DirBucketResponse
	if code != http.StatusOK || json.Unmarshal(raw, &out) != nil || out.Partial {
		t.Fatalf("the bucket at A: %d %s", code, raw)
	}
	var entry *dirbox.DirEntry
	for _, e := range out.Entries {
		eh, _ := base64.RawURLEncoding.DecodeString(e.H)
		box, _ := base64.RawURLEncoding.DecodeString(e.Box)
		if de, err := dirbox.Open(recip.AID(), eh, box); err == nil && bytes.Equal(eh, h) {
			entry = de
		}
	}
	if entry == nil {
		t.Fatalf("A's bucket has no entry that opens for the agent registered at B: %s", raw)
	}
	if entry.Home != b.id.AID {
		t.Fatalf("the entry names home %s, want B %s", entry.Home, b.id.AID)
	}
	// Nothing about the agent became part of A's directory.
	if listedContains(t, a.srv, recip.AID()) {
		t.Error("the peer's agent is listed at A")
	}
	if _, _, err := a.store.FedA2ACardKeys(recip.AID()); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("something about the peer's agent was stored at A: %v", err)
	}

	// What the entry carries verifies as the recipient's, and is what it
	// published.
	events, err := identity.UnmarshalKEL(entry.KEL)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := seal.UnmarshalSignedEncKeySet(entry.Keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seal.VerifyEncKeySet(signed, recip.AID(), events, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entry.Keys, recipKeys) {
		t.Error("the entry's key set is not the one the agent published")
	}
	_ = kp
}

// A sender on hub A seals to an agent registered on hub B and sends at A;
// A forwards to B, the recipient's one home, and the recipient collects it
// there. Neither hub's relay table names the sender.
func TestASendAtAHubReachesAPeersAgent(t *testing.T) {
	a, b := twoFederatedHubs(t)
	recip, sender := twoAgents(t)
	register(t, b.srv, recip, "Provider", []string{"work.do"})
	register(t, a.srv, sender, "Requester", nil)
	recipKeys, kp := mintKeySet(t, recip, 1)
	if code, body := publishKeys(t, b.srv, recip, recipKeys); code != 200 {
		t.Fatalf("publish at B: %d %s", code, body)
	}
	set, err := seal.VerifyEncKeySet(mustSignedSet(t, recipKeys), recip.AID(), recip.KEL(), uint64(time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := seal.SelectKey(set, uint64(time.Now().UnixMilli()))
	senderKeys, _ := mintKeySet(t, sender, 1)
	env := sealFrom(t, sender, senderKeys, recip.AID(), key, []byte("cross-hub task"))
	code, body, _ := relaySend(t, a.srv, sender, recip.AID(), env)
	var out relaySent
	if code != 200 || json.Unmarshal(body, &out) != nil || out.Status != aghub.RelayQueued || out.ViaHub != b.id.AID || out.RID == "" {
		t.Fatalf("send at A for an agent on B: %d %s", code, body)
	}
	p := relayPoll(t, b.srv, recip)
	if len(p.Messages) != 1 {
		t.Fatalf("B's mailbox: %+v", p.Messages)
	}
	got, _ := base64.RawURLEncoding.DecodeString(p.Messages[0].Envelope)
	opened, err := seal.Open(got, recip.AID(), seal.StaticKeyRing{kp}, nil)
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

// mustSignedSet decodes a signed key set.
func mustSignedSet(t *testing.T, raw []byte) *seal.SignedEncKeySet {
	t.Helper()
	signed, err := seal.UnmarshalSignedEncKeySet(raw)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
