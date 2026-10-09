package aghub_test

// Spot checks of the x402 amount-overflow fixes after the round-5b merge
// (ANet an internal note): sums past what the ledger holds, reached by
// settlements racing each other, and by a redemption into the hub's own
// row. Each asserts that nothing moves.

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// Two payers settle 100 each, at once, to a payee 150 short of what a
// balance can hold. Each settlement alone fits; together they do not. The
// guard is inside each settlement's transaction, so exactly one settles and
// the other moves nothing: its payer keeps its credit, no receipt is
// signed, and the payee's balance still reads as an integer.
func TestSpotConcurrentSettlementsCannotTogetherPassWhatALedgerHolds(t *testing.T) {
	w := newOverflowWorld(t)
	third, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	register(t, w.srv, third, "Third", nil)
	// Written outside the supply, which bounds every balance by what was
	// issued in all; the row guard is what is tested.
	if err := w.store.MoveBalanceWithoutEntryForTest(w.victim.AID(),
		math.MaxInt64-150-balanceOf(t, w.srv, w.victim.AID())); err != nil {
		t.Fatal(err)
	}
	own := payment.CreditNetwork(w.hubAID)
	payers := []*identity.Controller{w.attacker, third}
	payloads := make([]*payment.PaymentPayload, len(payers))
	for i, p := range payers {
		payloads[i] = creditPayload(t, signedAuth(t, p, w.victim.AID(), 100, w.hubAID,
			fmt.Sprintf("spot-concurrent-%d", i)), w.victim.AID(), own)
	}
	results := make([]payment.SettlementResponse, len(payers))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range payers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, results[i] = settleCall(t, w.srv, payloads[i], requirementsFor(w.victim.AID(), 100, own))
		}(i)
	}
	close(start)
	wg.Wait()
	settled := 0
	for i, r := range results {
		switch {
		case r.Success:
			settled++
		case r.ErrorReason != payment.ReasonInvalidAmount:
			t.Errorf("payer %d refused as %q, want %s", i, r.ErrorReason, payment.ReasonInvalidAmount)
		default:
			if _, ok := r.Extensions[payment.ExtReceipt]; ok {
				t.Errorf("payer %d: a refused settlement carried a signed receipt", i)
			}
			if got := balanceOf(t, w.srv, payers[i].AID()); got != testRegistrationFunds {
				t.Errorf("refused payer %d balance = %d, want %d", i, got, testRegistrationFunds)
			}
		}
	}
	if settled != 1 {
		t.Fatalf("%d of the two settlements went through, want exactly one: %+v", settled, results)
	}
	if got := balanceOf(t, w.srv, w.victim.AID()); got != math.MaxInt64-50 {
		t.Errorf("payee balance = %d, want %d", got, int64(math.MaxInt64-50))
	}
	w.readable(t, w.victim.AID(), "")
}

// The hub's own row takes every redemption (a redemption is a payment to
// the hub). With the row standing above zero, a redemption of 2^63-1 — in
// range, from an account that holds it — would take the row past what it
// can hold. It is refused and nothing moves: the redeemer keeps its
// balance, no redemption is recorded and the supply totals do not move.
// Under the supply invariant the hub's row is never above zero and no
// account holds 2^63-1 beside others; both are written here outside it (an
// old hub, a hand edit), because the row guard has to hold there too.
func TestSpotARedemptionThatWouldOverflowTheHubsOwnRowMovesNothing(t *testing.T) {
	w := newOverflowWorld(t)
	own := payment.CreditNetwork(w.hubAID)
	redeem := func(c *identity.Controller, amt uint64, ref string) (int, []byte) {
		opt := payment.PaymentOption{Scheme: payment.SchemeCredit, Network: own, Amount: payment.Amount(amt),
			Asset: payment.AssetCredit, PayTo: w.hubAID}
		return post(t, w.srv.URL+"/x402/redeem", map[string]any{
			"x402Version": payment.Version, "paymentPayload": json.RawMessage(mustPayload(t, c, opt, ref)),
			"reference": ref})
	}
	if code, b := redeem(w.victim, 5000, "spot-first"); code != 200 {
		t.Fatalf("an ordinary redemption: %d %s", code, b)
	}
	if err := w.store.MoveBalanceWithoutEntryForTest(w.hubAID, 5000); err != nil {
		t.Fatal(err)
	}
	if err := w.store.MoveBalanceWithoutEntryForTest(w.attacker.AID(),
		math.MaxInt64-balanceOf(t, w.srv, w.attacker.AID())); err != nil {
		t.Fatal(err)
	}
	before := moneyState(t, w.dir)
	code, b := redeem(w.attacker, math.MaxInt64, "spot-all")
	if code == 200 {
		t.Fatalf("a redemption past what the hub's row holds went through: %s", b)
	}
	var out struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &out)
	if !refusedAsAmount(out.Error) {
		t.Errorf("error = %q, want %s", out.Error, payment.ReasonInvalidAmount)
	}
	if after := moneyState(t, w.dir); after != before {
		t.Errorf("the money tables changed.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if got := balanceOf(t, w.srv, w.attacker.AID()); got != math.MaxInt64 {
		t.Errorf("redeemer balance = %d, want %d", got, int64(math.MaxInt64))
	}
	w.readable(t, w.attacker.AID(), "")
	w.readable(t, w.hubAID, "")
}
