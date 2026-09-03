package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// registerWithInvite is registerWithCard plus an admission token. The
// gate lives in the HTTP handler, so the HTTP layer is where it has to be
// tested — a store that refuses a bad invite proves nothing about a hub
// that never asked the store.
func registerWithInvite(t *testing.T, srv *httptest.Server, c *identity.Controller,
	name, invite string) (int, []byte) {
	t.Helper()
	kelB, _ := identity.MarshalKEL(c.KEL())
	ts := uint64(time.Now().UnixMilli())
	sig, seq := c.Sign(relayauth.Preimage(relayauth.ActionRegister, c.AID(), ts))
	body := map[string]any{
		"aid": c.AID(), "name": name, "caps": []string{},
		"kel": base64.StdEncoding.EncodeToString(kelB),
		"ts":  ts, "key_state_seq": seq, "sig": base64.StdEncoding.EncodeToString(sig),
	}
	if invite != "" {
		body["invite"] = invite
	}
	return post(t, srv.URL+"/register", body)
}

// The default is open registration, and it stays open. Every hub that
// upgrades to this build must behave exactly as it did before, or the
// upgrade locks out everybody.
func TestRegistrationStaysOpenByDefault(t *testing.T) {
	srv, _ := newHubWithStore(t)
	a, _ := twoAgents(t)
	if code, b := registerWithInvite(t, srv, a, "Newcomer", ""); code != 200 {
		t.Fatalf("a hub that was never configured must admit: %d %s", code, b)
	}
}

func TestWithAdmissionOnAnUninvitedAgentIsRefused(t *testing.T) {
	srv, store := newHubWithStore(t)
	if err := store.SetInviteRequired(true); err != nil {
		t.Fatal(err)
	}
	a, _ := twoAgents(t)

	code, b := registerWithInvite(t, srv, a, "Uninvited", "")
	if code != 403 {
		t.Fatalf("an uninvited agent must be refused, got %d %s", code, b)
	}
	// The refusal has to say what to do next. "403" alone sends an
	// operator to read hub source.
	if !strings.Contains(string(b), "invite") {
		t.Fatalf("the refusal must name the reason: %s", b)
	}
	// And it must not be in the registry.
	if store.KnowsAgent(a.AID()) {
		t.Fatal("a refused agent was registered anyway")
	}
}

func TestAValidInviteAdmitsAndIsRecorded(t *testing.T) {
	srv, store := newHubWithStore(t)
	if err := store.SetInviteRequired(true); err != nil {
		t.Fatal(err)
	}
	token, iv, err := store.NewInvite("a bench board", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := twoAgents(t)

	if code, b := registerWithInvite(t, srv, a, "Invited", token); code != 200 {
		t.Fatalf("a valid invite was refused: %d %s", code, b)
	}
	if !store.KnowsAgent(a.AID()) {
		t.Fatal("the admitted agent is not in the registry")
	}
	// Who came in on which invite is the question that matters when one
	// leaks, and a counter alone cannot answer it.
	list, err := store.Invites()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != iv.ID || list[0].Uses != 1 {
		t.Fatalf("the use was not recorded: %+v", list)
	}
	if len(list[0].Redeemers) != 1 || list[0].Redeemers[0].AID != a.AID() {
		t.Fatalf("the redeemer was not recorded: %+v", list[0].Redeemers)
	}
}

func TestAWrongInviteIsRefused(t *testing.T) {
	srv, store := newHubWithStore(t)
	if err := store.SetInviteRequired(true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.NewInvite("real one", 1, 0); err != nil {
		t.Fatal(err)
	}
	a, _ := twoAgents(t)
	if code, b := registerWithInvite(t, srv, a, "Guesser", "anetinv_madeitup"); code != 403 {
		t.Fatalf("a made-up invite must be refused, got %d %s", code, b)
	}
	if store.KnowsAgent(a.AID()) {
		t.Fatal("an agent got in with an invite that does not exist")
	}
}

// Turning admission on must not lock out the nodes already registered.
// They re-register on every restart and whenever their capability list
// changes; if that needed a token, an operator flipping the switch would
// take their own network down.
func TestAnAlreadyKnownAgentReRegistersWithoutAnInvite(t *testing.T) {
	srv, store := newHubWithStore(t)
	a, _ := twoAgents(t)
	if code, b := registerWithInvite(t, srv, a, "Early", ""); code != 200 {
		t.Fatalf("setup: %d %s", code, b)
	}

	if err := store.SetInviteRequired(true); err != nil {
		t.Fatal(err)
	}
	if code, b := registerWithInvite(t, srv, a, "Early", ""); code != 200 {
		t.Fatalf("turning admission on locked out an existing agent: %d %s", code, b)
	}
}

// A single-use invite admits one agent, not one per asker.
func TestASingleUseInviteAdmitsOneAgent(t *testing.T) {
	srv, store := newHubWithStore(t)
	if err := store.SetInviteRequired(true); err != nil {
		t.Fatal(err)
	}
	token, _, _ := store.NewInvite("one board", 1, 0)
	a, b2 := twoAgents(t)

	if code, b := registerWithInvite(t, srv, a, "First", token); code != 200 {
		t.Fatalf("first: %d %s", code, b)
	}
	code, body := registerWithInvite(t, srv, b2, "Second", token)
	if code != 403 {
		t.Fatalf("a second agent got in on a single-use invite: %d %s", code, body)
	}
	if store.KnowsAgent(b2.AID()) {
		t.Fatal("the second agent was registered anyway")
	}
}

// Revoking closes the gate against anybody who has not already used it.
func TestRevokingAnInviteStopsTheNextArrival(t *testing.T) {
	srv, store := newHubWithStore(t)
	if err := store.SetInviteRequired(true); err != nil {
		t.Fatal(err)
	}
	token, iv, _ := store.NewInvite("leaked", 0, 0)
	a, b2 := twoAgents(t)
	if code, b := registerWithInvite(t, srv, a, "Before", token); code != 200 {
		t.Fatalf("setup: %d %s", code, b)
	}
	if err := store.RevokeInvite(iv.ID); err != nil {
		t.Fatal(err)
	}
	if code, b := registerWithInvite(t, srv, b2, "After", token); code != 403 {
		t.Fatalf("a revoked invite still admitted: %d %s", code, b)
	}
	// The one who already came in stays. Revoking is a gate, not an
	// eviction, and conflating the two would make an operator think they
	// had removed somebody they had not.
	if !store.KnowsAgent(a.AID()) {
		t.Fatal("revoking the invite removed an agent already admitted")
	}
}

// The invite is checked AFTER the signature. Otherwise somebody who
// cannot prove they hold the key could burn a use, and an operator's
// invites could be exhausted by an attacker who never registers.
//
// The forgery has to be one that reaches the signature check: a request
// whose KEL does not derive the claimed AID is rejected earlier, by a
// different check, and a test built on that one would pass whatever the
// admission gate did. So this sends a correct AID and a correct KEL with
// a signature over the wrong thing.
func TestAnInviteIsNotSpentByACallerWhoCannotSign(t *testing.T) {
	srv, store := newHubWithStore(t)
	if err := store.SetInviteRequired(true); err != nil {
		t.Fatal(err)
	}
	token, _, _ := store.NewInvite("one board", 1, 0)
	a, _ := twoAgents(t)

	kelB, _ := identity.MarshalKEL(a.KEL())
	ts := uint64(time.Now().UnixMilli())
	// Signed over a different action, so the challenge cannot verify
	// while everything the earlier checks look at is correct.
	sig, seq := a.Sign(relayauth.Preimage(relayauth.ActionProfile, a.AID(), ts))
	code, body := post(t, srv.URL+"/register", map[string]any{
		"aid": a.AID(), "name": "Forger", "caps": []string{},
		"kel": base64.StdEncoding.EncodeToString(kelB),
		"ts":  ts, "key_state_seq": seq, "sig": base64.StdEncoding.EncodeToString(sig),
		"invite": token,
	})
	if code != 401 {
		t.Fatalf("an unverifiable challenge must be refused as unauthorized, got %d %s", code, body)
	}
	list, _ := store.Invites()
	if list[0].Uses != 0 {
		t.Fatalf("a caller who could not sign burned a use: %+v", list[0])
	}
	// And the invite still works for its intended holder.
	if code, b := registerWithInvite(t, srv, a, "Rightful", token); code != 200 {
		t.Fatalf("the invite was spoiled: %d %s", code, b)
	}
}

// The wire field has to survive as JSON under the exact name the daemon
// sends, which is the seam a struct rename breaks silently.
func TestTheInviteFieldIsNamedInviteOnTheWire(t *testing.T) {
	var req aghub.RegisterRequest
	if err := json.Unmarshal([]byte(`{"aid":"a","invite":"anetinv_x"}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.Invite != "anetinv_x" {
		t.Fatalf(`the hub does not read "invite" off the wire: %+v`, req)
	}
}
