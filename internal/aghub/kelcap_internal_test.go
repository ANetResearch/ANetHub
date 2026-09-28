package aghub

import (
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/identity"
)

// [redteam:F36] GET /agents/{aid}/jwks.json needs no authentication and
// deriving a JWKS replays the KEL. The hub derives it once per stored KEL:
// repeated requests, with or without If-None-Match, are answered from the
// cache keyed by the hash of the KEL bytes, and a KEL that grew is a new
// key, so the answer follows it at once.
func TestTheJWKSIsDerivedOncePerStoredKEL(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := NewServer(store)
	var derived atomic.Int32
	s.jwks.derive = func(kel []identity.SignedEvent) ([]byte, error) {
		derived.Add(1)
		return a2acard.JWKS(kel)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	put := func() {
		kel, _ := identity.MarshalKEL(c.KEL())
		if err := store.PutAgent(c.AID(), "n", nil, kel); err != nil {
			t.Fatal(err)
		}
	}
	get := func() string {
		resp, err := http.Get(srv.URL + "/agents/" + c.AID() + "/jwks.json")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("jwks: %d %s", resp.StatusCode, b)
		}
		return string(b)
	}
	put()
	first := get()
	for i := 0; i < 20; i++ {
		if got := get(); got != first {
			t.Fatalf("request %d: JWKS changed without a KEL change", i)
		}
	}
	if n := derived.Load(); n != 1 {
		t.Fatalf("21 requests for one KEL derived the JWKS %d times, want 1", n)
	}
	// The KEL grows (a drt adds a key state): the next request derives the
	// new JWKS, once.
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := c.Delegate(pub, 1); err != nil {
		t.Fatal(err)
	}
	put()
	second := get()
	get()
	if second == first {
		t.Fatalf("the JWKS did not follow the KEL")
	}
	if n := derived.Load(); n != 2 {
		t.Fatalf("after the KEL changed the JWKS was derived %d times in all, want 2", n)
	}
}

// The cache is bounded by the bytes it holds and forgets its oldest
// entries first.
func TestTheJWKSCacheIsBounded(t *testing.T) {
	var derived int
	c := newJWKSCache(3*(100+32), func([]identity.SignedEvent) ([]byte, error) {
		derived++
		return make([]byte, 100), nil
	})
	kels := make([][]byte, 4)
	for i := range kels {
		ctrl, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		kels[i], _ = identity.MarshalKEL(ctrl.KEL())
		if _, err := c.get(kels[i]); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.byKEL) != 3 || c.bytes > c.max {
		t.Fatalf("cache holds %d entries, %d bytes (max %d)", len(c.byKEL), c.bytes, c.max)
	}
	if _, err := c.get(kels[0]); err != nil || derived != 5 {
		t.Fatalf("the oldest entry was not the one forgotten: derived %d times, want 5 (%v)", derived, err)
	}
	if _, err := c.get(kels[3]); err != nil || derived != 5 {
		t.Fatalf("the newest entry was forgotten: derived %d times, want 5 (%v)", derived, err)
	}
}
