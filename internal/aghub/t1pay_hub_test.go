package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// An unauthenticated caller with a funded-or-not account cannot make the hub
// keep a first-verification record for every valid signature it presents.
func TestVerifyKeepsFewRecordsForAnAccountWithNoFunds(t *testing.T) {
	srv, store := newHubWithStore(t)
	payer, _ := aghub.NewAgentForTest()
	payee, _ := aghub.NewAgentForTest()
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	hubAID := hubAIDOf(t, srv)
	opt := payment.PaymentOption{Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: "1000000", Asset: payment.AssetCredit, PayTo: payee.AID()}
	const N = 200
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := 0; i < N; i++ {
		body, _ := json.Marshal(map[string]any{"x402Version": payment.Version,
			"paymentPayload":      json.RawMessage(mustPayload(t, payer, opt, fmt.Sprintf("n%06d", i))),
			"paymentRequirements": opt})
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			post(t, srv.URL+"/x402/verify", json.RawMessage(body))
		}()
	}
	wg.Wait()
	if n := countRows(t, store, `SELECT COUNT(*) FROM x402_first_verify`); n > 20 {
		t.Errorf("%d first-verification records for an account with no funds, want at most 20", n)
	}
}

// The address bucket ends a flood of verify calls with 429 and Retry-After.
func TestTheFacilitatorRoutesAreRateLimitedPerAddress(t *testing.T) {
	srv := newHub(t)
	limited := 0
	for i := 0; i < aghub.PayBurst+50; i++ {
		if code, _ := post(t, srv.URL+"/x402/verify", map[string]any{}); code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Errorf("no 429 after %d calls from one address", aghub.PayBurst+50)
	}
}

// A witness the hub cannot verify is not stored, and does not move the health.
func TestAForgedWitnessAttestationIsNotStored(t *testing.T) {
	srv, store := newHubWithStore(t)
	witness, _ := identitytest.Hub()
	a := &ael.HeadAttestation{ChainDID: hubAIDOf(t, srv), Seq: 777, HeadID: "bafy-forged", ObservedAt: time.Now().UnixMilli()}
	if err := a.Sign(witness); err != nil {
		t.Fatal(err)
	}
	a.Envelope.Sig[0] ^= 0xff
	raw, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	code, b := post(t, srv.URL+"/x402/witness", map[string]any{"attestation": base64.RawURLEncoding.EncodeToString(raw)})
	if code == http.StatusOK {
		t.Errorf("a forged attestation was accepted: %s", b)
	}
	if n := countRows(t, store, `SELECT COUNT(*) FROM head_attestation`); n != 0 {
		t.Errorf("%d attestation rows after a forged one", n)
	}
}

// A registered witness's genuine attestation is still stored.
func TestARegisteredWitnessAttestationIsStored(t *testing.T) {
	srv, store := newHubWithStore(t)
	witness, _ := aghub.NewAgentForTest()
	register(t, srv, witness, "Witness", nil)
	a := &ael.HeadAttestation{ChainDID: hubAIDOf(t, srv), Seq: 3, HeadID: "bafy-head", ObservedAt: time.Now().UnixMilli()}
	if err := a.Sign(witness); err != nil {
		t.Fatal(err)
	}
	raw, _ := a.Marshal()
	code, b := post(t, srv.URL+"/x402/witness", map[string]any{"attestation": base64.RawURLEncoding.EncodeToString(raw)})
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, b)
	}
	if n := countRows(t, store, `SELECT COUNT(*) FROM head_attestation`); n != 1 {
		t.Errorf("%d rows", n)
	}
}

func redeemOnce(t *testing.T, srvURL string, agent *identity.Controller, hubAID, amount, bind, ref string) (int, string) {
	t.Helper()
	opt := payment.PaymentOption{Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: amount, Asset: payment.AssetCredit, PayTo: hubAID}
	c, b := post(t, srvURL+"/x402/redeem", map[string]any{"x402Version": payment.Version,
		"paymentPayload": json.RawMessage(mustPayload(t, agent, opt, bind)), "reference": ref})
	return c, string(b)
}

// One reference may be redeemed against again; the reference is the one signed.
func TestAReferenceCanBeRedeemedAgainstTwice(t *testing.T) {
	srv := newHub(t)
	agent, _ := aghub.NewAgentForTest()
	register(t, srv, agent, "Agent", nil)
	fundAgent(t, srv, agent.AID(), 400)
	hubAID := hubAIDOf(t, srv)
	start := balanceOf(t, srv, agent.AID())
	if c, b := redeemOnce(t, srv.URL, agent, hubAID, "10", "redeem:payout", "payout"); c != 200 {
		t.Fatalf("first: %d %s", c, b)
	}
	if c, b := redeemOnce(t, srv.URL, agent, hubAID, "11", "redeem:payout", "payout"); c != 200 {
		t.Errorf("a second redemption against the same reference: %d %s", c, b)
	}
	if got := balanceOf(t, srv, agent.AID()); got != start-10-11 {
		t.Errorf("balance %d, want %d", got, start-10-11)
	}
}

func TestARedemptionReferenceMustBeTheSignedOne(t *testing.T) {
	srv := newHub(t)
	agent, _ := aghub.NewAgentForTest()
	register(t, srv, agent, "Agent", nil)
	fundAgent(t, srv, agent.AID(), 400)
	hubAID := hubAIDOf(t, srv)
	start := balanceOf(t, srv, agent.AID())
	if c, b := redeemOnce(t, srv.URL, agent, hubAID, "12", "redeem:signedref", "other-ref"); c == 200 {
		t.Errorf("accepted a reference that was not signed: %s", b)
	}
	long := strings.Repeat("r", 300)
	if c, b := redeemOnce(t, srv.URL, agent, hubAID, "12", "redeem:"+long, long); c == 200 {
		t.Errorf("accepted a 300-byte reference: %s", b)
	}
	if got := balanceOf(t, srv, agent.AID()); got != start {
		t.Errorf("balance %d after refused redemptions", got)
	}
}

// A settle refusal does not tell the payee the payer's balance.
func TestSettleDoesNotTellThePayeeTheBalance(t *testing.T) {
	srv := newHub(t)
	payer, _ := aghub.NewAgentForTest()
	payee, _ := aghub.NewAgentForTest()
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	fundAgent(t, srv, payer.AID(), 337)
	hubAID := hubAIDOf(t, srv)
	opt := payment.PaymentOption{Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: "9000000", Asset: payment.AssetCredit, PayTo: payee.AID()}
	_, b := post(t, srv.URL+"/x402/settle", map[string]any{"x402Version": payment.Version,
		"paymentPayload": json.RawMessage(mustPayload(t, payer, opt, "leak1")), "paymentRequirements": opt})
	if !strings.Contains(string(b), "insufficient_funds") || strings.Contains(string(b), "337") {
		t.Errorf("answer: %s", b)
	}
}
