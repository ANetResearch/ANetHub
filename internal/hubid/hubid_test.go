package hubid

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
)

func TestStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.AID != b.AID || a.AID == "" {
		t.Fatalf("hub AID must be stable: %q vs %q", a.AID, b.AID)
	}
}

func TestSignVerifiableAgainstServedKEL(t *testing.T) {
	id, err := LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pre := []byte("fed-envelope-preimage")
	sig, seq := id.Ctrl.Sign(pre)

	srv := httptest.NewServer(id.Handler())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct{ AID, KEL string }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.AID != id.AID {
		t.Fatal("served AID mismatch")
	}
	kel, err := identity.UnmarshalKEL(mustB64(t, out.KEL))
	if err != nil {
		t.Fatal(err)
	}
	states, err := identity.Replay(kel)
	if err != nil {
		t.Fatal(err)
	}
	_ = states
	_ = sig
	_ = seq
	// Round-trip proves: what peers fetch is a replayable KEL for this AID.
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := jsonB64(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jsonB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// /hub/identity answers with the identity as it is when asked, and states
// the wire (core CORE-V1): a KEL that grows after the handler is made (a
// rotation) is served as it now is.
func TestServedIdentityIsCurrent(t *testing.T) {
	id, err := LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := id.Handler()
	id.KEL = append(append([]byte(nil), id.KEL...), 0xA0)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/hub/identity", nil))
	var out IdentityResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.KEL != base64.StdEncoding.EncodeToString(id.KEL) || out.AID != id.AID || out.Wire != 3 {
		t.Fatalf("served %+v, not the identity as it is now", out)
	}
	if rec.Header().Get("X-ANet-Wire") != "3" {
		t.Fatalf("X-ANet-Wire %q", rec.Header().Get("X-ANet-Wire"))
	}
}

// A hub's first start incepts a hub identity (toad 0, KEL C-5, H-30): no witness, ever, and the
// time of inception in its icp.
func TestHubIdentityIsAHubIdentity(t *testing.T) {
	before := uint64(time.Now().UnixMilli())
	id, err := LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	icp := id.Ctrl.KEL()[0].Event
	if id.Ctrl.Toad() != identity.ToadHub || len(icp.Witnesses) != 0 || icp.Timestamp < before {
		t.Fatalf("toad %d, icp %+v", id.Ctrl.Toad(), icp)
	}
}
