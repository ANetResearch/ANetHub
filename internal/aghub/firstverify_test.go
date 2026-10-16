package aghub_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"
)

// A payment is judged by the payer's key as of this hub's first verification
// of it (KEL H-40 to H-42): verified while its key was the current one, it
// settles after the payer rotates, planned or emergency; never verified while
// its key was current, it needs the key current at settlement.

// payTerms is a payment of amount from payer to payee on the test hub's
// ledger, signed now, valid for a minute: the payload, and the
// requirements a merchant would ask the facilitator to enforce.
func payTerms(t *testing.T, srv *httptest.Server, payer *identity.Controller, payee string, amount uint64,
	ix string) (*payment.Authorization, *payment.PaymentPayload, *payment.PaymentRequirements) {
	t.Helper()
	network := payment.CreditNetwork(hubAIDOf(t, srv))
	a := signedAuth(t, payer, payee, amount, hubAIDOf(t, srv), ix)
	return a, creditPayload(t, a, payee, network), requirementsFor(payee, amount, network)
}

// rotateAtHub rotates c, planned or emergency, and has the hub take the
// rotation as the payer's node does (POST /agents/kel:push).
func rotateAtHub(t *testing.T, srv *httptest.Server, c *identity.Controller, emergency bool) {
	t.Helper()
	rot := identitytest.Rotate
	if emergency {
		rot = identitytest.RotateEmergency
	}
	if err := rot(c, tsAfter(c)); err != nil {
		t.Fatal(err)
	}
	if code, b := pushKEL(t, srv, c.AID(), kelURL(t, c)); code != http.StatusOK {
		t.Fatalf("push the rotation: %d %s", code, b)
	}
}

// TestFirstVerifyAtTipSurvivesRotation (H-40, H-41, H-42, M20): the merchant
// verifies a payment while the payer's key is the current one; the payer
// rotates, planned or emergency; the settlement of that payment succeeds and
// moves the credit once. A payment the old key signs after the rotation is
// another authorization, never verified at the tip, and is refused.
func TestFirstVerifyAtTipSurvivesRotation(t *testing.T) {
	for _, emergency := range []bool{false, true} {
		name := "planned"
		if emergency {
			name = "emergency"
		}
		t.Run(name, func(t *testing.T) {
			srv := newWitnessHubForPayments(t)
			payer, payee := twoAgents(t)
			register(t, srv, payer, "payer", nil)
			register(t, srv, payee, "payee", nil)
			_, p, req := payTerms(t, srv, payer, payee.AID(), 7, "ix-first-verify")
			if code, v := verifyCall(t, srv, p, req); code != http.StatusOK || !v.IsValid {
				t.Fatalf("verify at the tip: %d %+v", code, v)
			}
			old := snapshotOf(t, payer)
			rotateAtHub(t, srv, payer, emergency)
			before := balances(t, srv, payer.AID(), payee.AID())
			code, out := settleCall(t, srv, p, req)
			if code != http.StatusOK || !out.Success {
				t.Fatalf("settle after the payer rotated: %d %+v", code, out)
			}
			after := balances(t, srv, payer.AID(), payee.AID())
			if after[0] != before[0]-7 || after[1] != before[1]+7 {
				t.Errorf("balances %v -> %v, want 7 moved once", before, after)
			}
			// The old key's next authorization: never verified at the tip.
			_, p2, req2 := payTerms(t, srv, old, payee.AID(), 5, "ix-after-rotation")
			if _, v := verifyCall(t, srv, p2, req2); v.IsValid || v.InvalidReason != payment.ReasonInvalidSignature {
				t.Errorf("verify of the old key's new payment: %+v, want invalid_signature", v)
			}
			if _, out := settleCall(t, srv, p2, req2); out.Success || out.ErrorReason != payment.ReasonInvalidSignature {
				t.Errorf("settle of the old key's new payment: %+v, want invalid_signature", out)
			}
		})
	}
}

// TestRetiredKeyAuthWithoutFirstVerifyRefused (H-41): a payment signed while
// the payer's key was current but first shown to this hub after the payer
// rotated has no first verification at the tip: verify and settle refuse
// it (invalid_signature) and nothing moves. Having been verified once with
// the key already retired does not make it acceptable later.
func TestRetiredKeyAuthWithoutFirstVerifyRefused(t *testing.T) {
	srv := newWitnessHubForPayments(t)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "payer", nil)
	register(t, srv, payee, "payee", nil)
	_, p, req := payTerms(t, srv, payer, payee.AID(), 7, "ix-late")
	rotateAtHub(t, srv, payer, false)
	before := balances(t, srv, payer.AID(), payee.AID())
	if _, v := verifyCall(t, srv, p, req); v.IsValid || v.InvalidReason != payment.ReasonInvalidSignature {
		t.Errorf("verify after the rotation: %+v, want invalid_signature", v)
	}
	for i := 0; i < 2; i++ {
		if _, out := settleCall(t, srv, p, req); out.Success || out.ErrorReason != payment.ReasonInvalidSignature {
			t.Errorf("settle %d after the rotation: %+v, want invalid_signature", i, out)
		}
	}
	if after := balances(t, srv, payer.AID(), payee.AID()); !sameBalances(before, after) {
		t.Errorf("balances moved: %v -> %v", before, after)
	}
}

// H-40: the first whole verification is recorded by whichever call makes it,
// a settlement too: one refused for want of credit leaves the record, and
// once the payer has credit the same payment settles after a rotation.
func TestAFailedSettlementKeepsItsFirstVerification(t *testing.T) {
	srv := newWitnessHubForPayments(t)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "payer", nil)
	register(t, srv, payee, "payee", nil)
	_, p, req := payTerms(t, srv, payer, payee.AID(), testRegistrationFunds+1, "ix-short")
	if _, out := settleCall(t, srv, p, req); out.Success || out.ErrorReason != payment.ReasonInsufficientFunds {
		t.Fatalf("settle without the credit: %+v, want insufficient_funds", out)
	}
	rotateAtHub(t, srv, payer, true)
	fundAgent(t, srv, payer.AID(), 1)
	if _, out := settleCall(t, srv, p, req); !out.Success {
		t.Fatalf("settle once funded, after an emergency rotation: %+v", out)
	}
}

// newWitnessHubForPayments is a test hub whose /agents/kel:push limit does
// not get in the way.
func newWitnessHubForPayments(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := newWitnessHub(t)
	return srv
}

// The record is not a standing exemption: it holds for the authorization it
// was made for, until it is deleted with the settlement (7 days after
// NotAfter, firstverify_internal_test.go). The window still applies: a
// payment verified at the tip is refused once its NotAfter is past.
func TestAFirstVerificationDoesNotExtendTheWindow(t *testing.T) {
	srv, store := newWitnessHub(t)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "payer", nil)
	register(t, srv, payee, "payee", nil)
	_, p, req := payTerms(t, srv, payer, payee.AID(), 3, "ix-window")
	if _, v := verifyCall(t, srv, p, req); !v.IsValid {
		t.Fatalf("verify: %+v", v)
	}
	rotateAtHub(t, srv, payer, false)
	store.SetClockForTest(func() time.Time { return time.Now().Add(10 * time.Minute) })
	if _, out := settleCall(t, srv, p, req); out.Success || out.ErrorReason != payment.ReasonExpiredPayment {
		t.Errorf("settle past NotAfter: %+v, want expired_payment", out)
	}
}
