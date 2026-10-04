package main

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// GET /hub/identity of the hub as anet-hub serves it (newRoot) states
// dir_max_bits (sealed-sender SSR-W18, core §2.12.2): the bucket width the
// hub's /directory:bucket answers, so that a daemon learns it before its
// first query.
func TestHubIdentityStatesDirMaxBits(t *testing.T) {
	served := func(agents int) (map[string]any, *aghub.Store) {
		t.Helper()
		dir := t.TempDir()
		store, err := aghub.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		id, err := hubid.LoadOrIncept(dir)
		if err != nil {
			t.Fatal(err)
		}
		store.SetHubKey(id.Ctrl)
		srv0 := aghub.NewServer(store)
		srv0.SetHubAID(id.AID)
		srv := httptest.NewServer(hubHandler(newRoot(id, srv0)))
		t.Cleanup(srv.Close)
		for i := 0; i < agents; i++ {
			agentWithKeys(t, store)
		}
		resp, err := http.Get(srv.URL + "/hub/identity")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var out map[string]any
		if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &out) != nil {
			t.Fatalf("GET /hub/identity: %d %s", resp.StatusCode, b)
		}
		return out, store
	}
	empty, _ := served(0)
	if got, ok := empty["dir_max_bits"]; !ok || got != float64(0) {
		t.Fatalf("an empty directory: dir_max_bits %v (present %v), want 0", got, ok)
	}
	// 256 entries: each half of the directory holds at least 32 of them
	// (failing that is a binomial tail far below 2^-60), so the hub answers
	// buckets of at least one bit.
	out, store := served(256)
	want, err := store.DirMaxBits()
	if err != nil {
		t.Fatal(err)
	}
	if want < 1 {
		t.Fatalf("256 entries: dir_max_bits %d, want at least 1", want)
	}
	if got := out["dir_max_bits"]; got != float64(want) {
		t.Fatalf("/hub/identity states dir_max_bits %v, the store computes %d", got, want)
	}
}

// agentWithKeys registers a fresh agent at store with a published key set,
// as /register leaves it, and returns its AID.
func agentWithKeys(t *testing.T, store *aghub.Store) string {
	t.Helper()
	c, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(c.AID(), "agent", nil, kel); err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().UnixMilli())
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
	if err != nil {
		t.Fatal(err)
	}
	mbox, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := seal.SignEncKeySet(&seal.EncKeySet{Type: seal.EncKeySetType, AID: c.AID(), Seq: 1,
		Keys: []seal.EncKey{kp.Public}, IssuedAt: now, Mbox: seal.Mbox{Epoch: 1, Pub: mbox}}, c.Sign)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishKeys(c.AID(), raw, c.KEL(), time.Now()); err != nil {
		t.Fatal(err)
	}
	return c.AID()
}
