package aghub

import (
	"errors"
	"testing"
	"time"
)

func inviteStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// A hub that was never configured admits openly, exactly as it did before
// this feature existed. Every deployment that upgrades keeps working, and
// every node already registered keeps registering.
func TestAdmissionIsOffUntilTurnedOn(t *testing.T) {
	s := inviteStore(t)
	if s.InviteRequired() {
		t.Fatal("a fresh hub must admit openly")
	}
	if err := s.SetInviteRequired(true); err != nil {
		t.Fatal(err)
	}
	if !s.InviteRequired() {
		t.Fatal("the setting did not persist")
	}
	if err := s.SetInviteRequired(false); err != nil {
		t.Fatal(err)
	}
	if s.InviteRequired() {
		t.Fatal("admission could be turned on but not off")
	}
}

// The token exists in plaintext once. A copy of hub.db must not be a bag
// of working invitations, so what is stored is a digest.
func TestTheTokenItselfIsNotStored(t *testing.T) {
	s := inviteStore(t)
	token, v, err := s.NewInvite("bench board", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 20 {
		t.Fatalf("token looks too short to be unguessable: %q", token)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM invite WHERE token_sha256=?`, token).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("the token is stored verbatim")
	}
	list, err := s.Invites()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != v.ID {
		t.Fatalf("mint did not show up in the list: %+v", list)
	}
	// Nothing an operator reads back may contain the token.
	for _, iv := range list {
		if iv.ID == token || iv.Label == token {
			t.Fatal("the token leaked into the listing")
		}
	}
}

func TestRedeemAcceptsAValidInviteOnce(t *testing.T) {
	s := inviteStore(t)
	token, _, err := s.NewInvite("one board", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(token, "aid-a"); err != nil {
		t.Fatalf("a valid invite was refused: %v", err)
	}
	// max_uses 1 means one agent, not one per asker.
	if err := s.RedeemInvite(token, "aid-b"); err != ErrInviteUsedUp {
		t.Fatalf("a second agent got in on a single-use invite: %v", err)
	}
}

// A retry that lost its response, or a node an operator deleted and who
// registers again, must not burn a second use.
func TestTheSameAgentRedeemingTwiceIsOneUse(t *testing.T) {
	s := inviteStore(t)
	token, _, err := s.NewInvite("one board", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(token, "aid-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(token, "aid-a"); err != nil {
		t.Fatalf("the same agent was refused its own invite: %v", err)
	}
	list, _ := s.Invites()
	if list[0].Uses != 1 {
		t.Fatalf("uses should still be 1, got %d", list[0].Uses)
	}
	if len(list[0].Redeemers) != 1 || list[0].Redeemers[0].AID != "aid-a" {
		t.Fatalf("the redeemer list is wrong: %+v", list[0].Redeemers)
	}
}

func TestRedeemRefusesWhatItShould(t *testing.T) {
	s := inviteStore(t)

	if err := s.RedeemInvite("", "aid"); err != ErrInviteRequired {
		t.Errorf("an empty token must say an invite is required, got %v", err)
	}
	if err := s.RedeemInvite("anetinv_nosuchthing", "aid"); err != ErrInviteUnknown {
		t.Errorf("an unknown token must be refused, got %v", err)
	}

	revoked, rv, _ := s.NewInvite("leaked", 0, 0)
	if err := s.RevokeInvite(rv.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(revoked, "aid"); err != ErrInviteRevoked {
		t.Errorf("a revoked invite must be refused, got %v", err)
	}

	expired, ev, _ := s.NewInvite("stale", 0, time.Hour)
	if _, err := s.db.Exec(`UPDATE invite SET expires_at=? WHERE id=?`,
		time.Now().Add(-time.Hour).Unix(), ev.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(expired, "aid"); err != ErrInviteExpired {
		t.Errorf("an expired invite must be refused, got %v", err)
	}

	// A negative ttl is refused rather than silently read as "no expiry",
	// which would turn one typo into a permanent invite.
	if _, _, err := s.NewInvite("typo", 0, -time.Hour); err == nil {
		t.Error("a negative ttl must be refused, not treated as no expiry")
	}
}

// An unlimited invite is allowed on purpose: a standing invite for a team
// is a thing operators want, and refusing it would only make them mint a
// fresh one every week.
func TestUnlimitedAndNeverExpiringIsAllowed(t *testing.T) {
	s := inviteStore(t)
	token, _, err := s.NewInvite("team standing invite", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, aid := range []string{"a", "b", "c", "d"} {
		if err := s.RedeemInvite(token, aid); err != nil {
			t.Fatalf("unlimited invite refused %s: %v", aid, err)
		}
	}
	list, _ := s.Invites()
	if list[0].Uses != 4 {
		t.Fatalf("uses should be 4, got %d", list[0].Uses)
	}
}

// Revoking closes the gate; it does not evict. An operator who wants
// somebody out deletes the agent, and the two actions are not the same.
func TestRevokingDoesNotRemoveWhoAlreadyCameIn(t *testing.T) {
	s := inviteStore(t)
	token, v, _ := s.NewInvite("leaked", 0, 0)
	if err := s.RedeemInvite(token, "aid-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeInvite(v.ID); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Invites()
	if len(list[0].Redeemers) != 1 {
		t.Fatal("revoking erased the record of who came in on it")
	}
	if list[0].RevokedAt == 0 {
		t.Fatal("the invite is not marked revoked")
	}
	if err := s.RevokeInvite("no-such-id"); err != ErrInviteUnknown {
		t.Fatalf("revoking an unknown id must say so, got %v", err)
	}
}

// Revoking twice and revoking a mistyped id are different situations and
// must not produce the same answer.
//
// Both used to return ErrInviteUnknown, so an operator who had been told
// an invite leaked and ran the command a second time could not tell
// whether the gate was already shut or whether they had just closed
// nothing at all — while -invite-list went on showing the code as
// revoked.
func TestRevokingTwiceSaysSoRatherThanClaimingTheIdIsUnknown(t *testing.T) {
	s := inviteStore(t)
	_, v, err := s.NewInvite("leaked", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeInvite(v.ID); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := s.RevokeInvite(v.ID); !errors.Is(err, ErrInviteAlreadyRevoked) {
		t.Fatalf("re-revoking a live id gave %v, want ErrInviteAlreadyRevoked", err)
	}
	// The distinction is only worth anything if the other case still
	// reports the other error.
	if err := s.RevokeInvite("no-such-id"); !errors.Is(err, ErrInviteUnknown) {
		t.Fatalf("revoking an unknown id gave %v, want ErrInviteUnknown", err)
	}
}

// The first revocation timestamp is the record of when the gate closed.
// A repeat of the command must not move it forward, or an invite revoked
// before a redemption would read as having been revoked after it.
func TestRevokingTwiceKeepsTheFirstTimestamp(t *testing.T) {
	s := inviteStore(t)
	_, v, err := s.NewInvite("leaked", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeInvite(v.ID); err != nil {
		t.Fatal(err)
	}
	// Backdated so the assertion can tell "unchanged" from "rewritten
	// within the same second" — revoked_at has one-second resolution, and
	// two revocations in the same second would otherwise look identical
	// whether or not the second one wrote.
	const closedAt = 1_700_000_000
	if _, err := s.db.Exec(`UPDATE invite SET revoked_at=? WHERE id=?`, closedAt, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeInvite(v.ID); !errors.Is(err, ErrInviteAlreadyRevoked) {
		t.Fatalf("re-revoke gave %v, want ErrInviteAlreadyRevoked", err)
	}
	list, err := s.Invites()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected one invite, got %d", len(list))
	}
	if list[0].RevokedAt != closedAt {
		t.Errorf("revoked_at moved from %d to %d — the record of when the gate closed was rewritten",
			closedAt, list[0].RevokedAt)
	}
}
