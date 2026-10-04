//go:build !no_federation

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// fedHub is one hub wired the way main wires it (wireMounts), behind a
// real listener so a peer can reach its /fed/v2/keys.
type fedHub struct {
	dir   string
	store *aghub.Store
	id    *hubid.Identity
	url   string
}

// newFedHubs starts two hubs that name each other as peers (delivery on,
// discovery off, so no background sync runs), wired from their
// federation.json files as the binary does (wireMounts).
func newFedHubs(t *testing.T) (a, b *fedHub) {
	t.Helper()
	mk := func() (*fedHub, *http.ServeMux) {
		dir := t.TempDir()
		store, err := aghub.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		id, err := hubid.LoadOrIncept(dir)
		if err != nil {
			t.Fatal(err)
		}
		root := http.NewServeMux()
		srv := httptest.NewServer(root)
		t.Cleanup(srv.Close)
		return &fedHub{dir: dir, store: store, id: id, url: srv.URL}, root
	}
	a, rootA := mk()
	b, rootB := mk()
	write := func(self, peer *fedHub) {
		cfg := federation.Config{Delivery: "allowlist", Discovery: "off", Witness: "off", Home: self.url,
			Peers: []federation.Peer{{AID: peer.id.AID, Endpoint: peer.url}}}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(self.dir, "federation.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(a, b)
	write(b, a)
	wire := func(h *fedHub, root *http.ServeMux) {
		srv0 := aghub.NewServer(h.store)
		srv0.SetHubAID(h.id.AID)
		root.Handle("/hub/identity", h.id.Handler())
		root.Handle("/", srv0.Handler())
		_, closers, err := wireMounts(&hubDeps{data: h.dir, store: h.store, hubID: h.id, srv0: srv0, root: root})
		t.Cleanup(func() {
			for i := len(closers) - 1; i >= 0; i-- {
				_ = closers[i]()
			}
			h.store.Close()
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	wire(a, rootA)
	wire(b, rootB)
	return a, b
}

// registerWithKeys registers a fresh agent at h with a published key set,
// as /register would leave it: an agent row and a key set that verifies
// under its KEL. Its card is not federated (discovery is off).
func registerWithKeys(t *testing.T, h *fedHub) string {
	t.Helper()
	c, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutAgent(c.AID(), "provider", nil, kel); err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().UnixMilli())
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := seal.SignEncKeySet(&seal.EncKeySet{Type: seal.EncKeySetType, AID: c.AID(), Seq: 1,
		Keys: []seal.EncKey{kp.Public}, IssuedAt: now, Mbox: seal.Mbox{Epoch: 1, Pub: mboxPub(t)}}, c.Sign)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.PublishKeys(c.AID(), raw, c.KEL(), time.Now()); err != nil {
		t.Fatal(err)
	}
	return c.AID()
}

// A hub serves GET /agents/{aid}/keys for its own agents only (sealed-sender
// §2.7, SSR-W16): the lookup it used to make at its peers, for anyone who
// asked, went with every lookup by AID, and a sender now reads a peer's agent
// from a directory bucket, which does not name it. Wired as main wires it, a
// hub answers 404 for an agent registered at its peer, and its peer 200.
func TestAHubServesKeysOnlyForItsOwnAgents(t *testing.T) {
	keysAt := func(h *fedHub, aid string) int {
		t.Helper()
		resp, err := http.Get(h.url + "/agents/" + aid + "/keys")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	a, b := newFedHubs(t)
	atB := registerWithKeys(t, b)
	if code := keysAt(a, atB); code != http.StatusNotFound {
		t.Fatalf("keys of the peer's agent, asked here: %d, want 404", code)
	}
	if code := keysAt(b, atB); code != http.StatusOK {
		t.Fatalf("the peer's own agent, asked at the peer: %d, want 200", code)
	}
}

// mboxPub is a fresh Ed25519 public key for a test key set's mailbox signing
// key.
func mboxPub(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
