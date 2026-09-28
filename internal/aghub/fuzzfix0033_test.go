package aghub_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

// Regressions for what the hub fuzz targets found (ANet
// docs/notes/0033-验证-模糊测试-hub.md). Each was first a failing fuzz
// input, kept under testdata/fuzz/; these state the same thing as a plain
// test.

// A payment whose payee is this hub is a redemption, and only
// /x402/redeem books it as one: it writes the redemption record and puts
// the retirement on the issuance chain. /x402/settle used to accept the
// same authorization and move the credit to the hub's row with neither,
// so the published supply fell while the signed chain did not, and
// chain_agrees stayed false from then on (FuzzHubX402Facilitator,
// eae7515b52aa1a9e). /x402/verify and /x402/settle now refuse it with
// payee_mismatch, before moving anything, and the redemption path still
// takes the same authorization.
func TestAPaymentToTheHubIsOnlyARedemption(t *testing.T) {
	srv, _ := newHubWithStore(t)
	payer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, payer, "Payer", nil)
	hubAID := hubAIDOf(t, srv)
	own := payment.CreditNetwork(hubAID)
	now := time.Now().UnixMilli()
	a := authFor(t, payer, hubAID, 10, own, "", "to-the-hub", now-1000, now+60_000)
	p := creditPayload(t, a, hubAID, own)
	req := requirementsFor(hubAID, 10, own)
	before := balanceOf(t, srv, payer.AID())

	if _, v := verifyCall(t, srv, p, req); v.IsValid || v.InvalidReason != payment.ReasonPayeeMismatch {
		t.Errorf("verify of a payment to the hub: %+v, want invalid payee_mismatch", v)
	}
	if _, s := settleCall(t, srv, p, req); s.Success || s.ErrorReason != payment.ReasonPayeeMismatch {
		t.Errorf("settle of a payment to the hub: %+v, want payee_mismatch", s)
	}
	if got := balanceOf(t, srv, payer.AID()); got != before {
		t.Errorf("a refused settlement moved the payer %d -> %d", before, got)
	}
	if sup := supplyFull(t, srv); !sup.ChainAgrees || sup.Outstanding != sup.Balances {
		t.Errorf("supply after the refused settlement: %+v", sup)
	}

	// The same authorization is still a redemption.
	code, b := post(t, srv.URL+"/x402/redeem", map[string]any{
		"x402Version": payment.Version, "paymentPayload": p, "reference": "after the refusal"})
	if code != http.StatusOK {
		t.Fatalf("redeem: %d %s", code, b)
	}
	if got := balanceOf(t, srv, payer.AID()); got != before-10 {
		t.Errorf("redeeming 10 moved the payer %d -> %d", before, got)
	}
	if sup := supplyFull(t, srv); !sup.ChainAgrees || sup.Redeemed != 10 {
		t.Errorf("supply after the redemption: %+v", sup)
	}
}

// An entry hub does not forward to a peer's ledger a payment whose
// required payee is the entry hub itself: the peer's receipt would name
// this hub as payee, and clearing it would credit the hub's own row.
func TestAPaymentToTheHubIsNotForwardedToAPeer(t *testing.T) {
	srv, store := newHubWithStore(t)
	payer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	var forwarded int
	store.SetPeerSettler(func(network string, p *payment.PaymentPayload, req *payment.PaymentRequirements,
		auth *payment.Authorization) (payment.SettlementResponse, bool) {
		forwarded++
		return payment.SettlementResponse{Success: true}, true
	})
	hubAID := hubAIDOf(t, srv)
	theirs := payment.CreditNetwork(peer.AID())
	now := time.Now().UnixMilli()
	a := authFor(t, payer, hubAID, 10, theirs, "", "to-the-entry-hub", now-1000, now+60_000)
	out := store.SettleWithRequirements(hubAID, creditPayload(t, a, hubAID, theirs), requirementsFor(hubAID, 10, theirs))
	if out.Success || out.ErrorReason != payment.ReasonPayeeMismatch || forwarded != 0 {
		t.Errorf("a payment to the entry hub on a peer's ledger: %+v, forwarded %d times", out, forwarded)
	}
}

// A peer's settlement receipt that names this hub as payee is not
// cleared: ClearFromPeer would credit and debit the hub's own row, record
// the peer as owing the amount, and put an issuance on the chain that no
// account holds, so chain_agrees went false (FuzzHubClearFromPeer).
func TestAPeerReceiptPayingThisHubIsNotCleared(t *testing.T) {
	srv, store := newHubWithStore(t)
	hubAID := hubAIDOf(t, srv)
	peer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	payer, _ := identity.Incept()
	rec := &payment.Receipt{AuthID: "peer-auth-to-hub", Payer: payer.AID(), PayTo: hubAID, Amount: 10,
		Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli()}
	if err := rec.Sign(peer); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearFromPeer(peer.AID(), peer.KEL(), rec); err == nil {
		t.Error("a peer receipt paying this hub was cleared")
	}
	if owed, _ := store.Owed(peer.AID()); owed != 0 {
		t.Errorf("the peer is recorded as owing %d", owed)
	}
	if sup := supplyFull(t, srv); !sup.ChainAgrees || sup.Outstanding != sup.Balances {
		t.Errorf("supply after the refused receipt: %+v", sup)
	}
}
