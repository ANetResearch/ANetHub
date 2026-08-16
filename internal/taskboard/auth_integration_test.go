package taskboard_test

// Real-KEL auth integration: the stub-auth unit tests prove the FSM; this
// file proves the actual security wiring — real incepted identities,
// registered in a real aghub store, signing real relayauth challenges over
// HTTP. The negatives pin the properties that make the scheme safe:
// action binding (no cross-endpoint replay), the replay window, and
// registration as a precondition.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/protocol/relayauth"
	"github.com/ANetResearch/ANetHub/internal/taskboard"
)

type agent struct {
	ctrl *identity.Controller
	aid  string
}

func newAgent(t *testing.T, store *aghub.Store, name string) agent {
	t.Helper()
	ctrl, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(ctrl.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(ctrl.AID(), name, nil, 0, kel); err != nil {
		t.Fatal(err)
	}
	return agent{ctrl: ctrl, aid: ctrl.AID()}
}

// signed builds the auth fields for one action, optionally at a shifted time.
func signed(a agent, action string, skew time.Duration) map[string]any {
	ts := uint64(time.Now().Add(skew).UnixMilli())
	sig, seq := a.ctrl.Sign(relayauth.Preimage(action, a.aid, ts))
	return map[string]any{
		"aid": a.aid, "ts": ts, "key_state_seq": seq,
		"sig": base64.StdEncoding.EncodeToString(sig),
	}
}

func TestRealKELChallengeFlow(t *testing.T) {
	dir := t.TempDir()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tb, err := taskboard.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer tb.Close()
	srv := httptest.NewServer(taskboard.NewServer(tb, store).Handler())
	defer srv.Close()

	post := func(path string, body map[string]any) (int, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(body)
		resp, err := srv.Client().Post(srv.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	alice := newAgent(t, store, "Alice")
	bob := newAgent(t, store, "Bob")

	// happy path: real signatures all the way through the FSM
	req := signed(alice, "task.create", 0)
	req["title"], req["taskdoc_cid"] = "real auth card", "bafyReal"
	code, out := post("/tasks/create", req)
	if code != 200 {
		t.Fatalf("create with real KEL sig: %d %v", code, out)
	}
	cardID := out["card"].(map[string]any)["id"].(string)

	req = signed(bob, "task.claim", 0)
	req["card_id"] = cardID
	if code, out := post("/tasks/claim", req); code != 200 {
		t.Fatalf("claim: %d %v", code, out)
	}

	// action binding: a valid task.claim signature must NOT authorize accept
	req = signed(alice, "task.claim", 0) // wrong action for this endpoint
	req["card_id"] = cardID
	if code, _ := post("/tasks/accept", req); code != 401 {
		t.Fatalf("cross-action replay must 401, got %d", code)
	}

	// replay window: stale challenge rejected
	req = signed(alice, "task.accept", -10*time.Minute)
	req["card_id"] = cardID
	if code, _ := post("/tasks/accept", req); code != 401 {
		t.Fatalf("stale challenge must 401, got %d", code)
	}

	// unregistered identity rejected even with a valid self-signature
	stranger, _ := identity.Incept()
	ts := uint64(time.Now().UnixMilli())
	sig, seq := stranger.Sign(relayauth.Preimage("task.claim", stranger.AID(), ts))
	if code, _ := post("/tasks/claim", map[string]any{
		"aid": stranger.AID(), "ts": ts, "key_state_seq": seq,
		"sig": base64.StdEncoding.EncodeToString(sig), "card_id": cardID,
	}); code != 401 {
		t.Fatalf("unregistered agent must 401, got %d", code)
	}

	// tampered signature rejected
	req = signed(bob, "task.submit", 0)
	req["card_id"] = cardID
	req["sig"] = base64.StdEncoding.EncodeToString([]byte("forged-bytes-forged-bytes-forged-bytes-forged-bytes-forged-forg"))
	if code, _ := post("/tasks/submit", req); code != 401 {
		t.Fatalf("tampered sig must 401, got %d", code)
	}

	// and the legitimate flow still completes after all that hostility
	req = signed(bob, "task.submit", 0)
	req["card_id"] = cardID
	if code, _ := post("/tasks/submit", req); code != 200 {
		t.Fatal("legit submit failed")
	}
	req = signed(alice, "task.accept", 0)
	req["card_id"] = cardID
	if code, _ := post("/tasks/accept", req); code != 200 {
		t.Fatal("legit accept failed")
	}
}
