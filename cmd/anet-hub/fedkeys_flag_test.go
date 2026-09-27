//go:build !no_federation

package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
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
// federation.json files as the binary does. The flags are parsed by
// defineFlags, so what reaches wireMounts is what the binary would see.
func newFedHubs(t *testing.T, argsA []string) (a, b *fedHub) {
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
	wire := func(h *fedHub, root *http.ServeMux, args []string) {
		fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
		f := defineFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		srv0 := aghub.NewServer(h.store)
		srv0.SetHubAID(h.id.AID)
		root.Handle("/hub/identity", h.id.Handler())
		root.Handle("/", srv0.Handler())
		_, closers, err := wireMounts(&hubDeps{data: h.dir, store: h.store, hubID: h.id, srv0: srv0, root: root,
			noFedKeyLookup: *f.testNoFedKeyLookup})
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
	wire(a, rootA, argsA)
	wire(b, rootB, nil)
	return a, b
}

// registerWithKeys registers a fresh agent at h with a published key set,
// as /register would leave it: an agent row and a key set that verifies
// under its KEL. Its card is not federated (discovery is off).
func registerWithKeys(t *testing.T, h *fedHub) string {
	t.Helper()
	c, err := identity.Incept()
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
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now+seal.KeyLifetimeMS)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := seal.SignEncKeySet(&seal.EncKeySet{Type: seal.EncKeySetType, AID: c.AID(), Seq: 1,
		Keys: []seal.EncKey{kp.Public}, IssuedAt: now}, c.Sign)
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

// -test-no-fed-key-lookup is the switch ANet scripts/scenario.sh uses for
// its C32 mutation (A2A-DESIGN §17): with it, a hub stops asking its peers
// for the keys of agents registered there, and nothing else changes. The
// scenario's claim — the lookup is what makes a peer's hub-local agent
// reachable — holds only if the switch removes exactly that path: here the
// same request is 200 without it and 404 with it, while the switched hub
// still answers its peer's lookups for its own agents.
func TestTheTestSwitchTurnsOffOnlyTheFederatedKeyLookup(t *testing.T) {
	fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
	if f := defineFlags(fs); *f.testNoFedKeyLookup {
		t.Fatal("-test-no-fed-key-lookup is on by default")
	}

	keysAt := func(h *fedHub, aid string) int {
		t.Helper()
		resp, err := http.Get(h.url + "/agents/" + aid + "/keys")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("without the switch", func(t *testing.T) {
		a, b := newFedHubs(t, nil)
		if code := keysAt(a, registerWithKeys(t, b)); code != http.StatusOK {
			t.Fatalf("keys of the peer's hub-local agent: %d, want 200", code)
		}
	})

	t.Run("with the switch", func(t *testing.T) {
		a, b := newFedHubs(t, []string{"-test-no-fed-key-lookup"})
		if code := keysAt(a, registerWithKeys(t, b)); code != http.StatusNotFound {
			t.Fatalf("keys of the peer's hub-local agent with the lookup off: %d, want 404", code)
		}
		// Only the lookup went: the switched hub's own agents are still
		// served to its peer, and to anyone asking it directly.
		own := registerWithKeys(t, a)
		if code := keysAt(b, own); code != http.StatusOK {
			t.Fatalf("the switched hub's own agent, asked at its peer: %d, want 200", code)
		}
		if code := keysAt(a, own); code != http.StatusOK {
			t.Fatalf("the switched hub's own agent, asked there: %d, want 200", code)
		}
	})
}
