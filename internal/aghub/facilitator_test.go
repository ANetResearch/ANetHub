package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// Tests for the facilitator's requirements check, idempotency, binding
// constraint, error reasons and ledger read authentication (A2A-DESIGN
// §8.5, §3.7).

// ownerGet is a relayauth v2 signed GET by c, the way the daemon reads its
// own balance, ledger and redemptions.
func ownerGet(t *testing.T, srv *httptest.Server, c *identity.Controller, action, path string) (int, []byte) {
	t.Helper()
	return signedDo(t, srv, c, action, http.MethodGet, path, nil)
}

// requirementsFor is what a merchant asks the facilitator to enforce.
func requirementsFor(payTo string, amount uint64, network string) *payment.PaymentRequirements {
	return &payment.PaymentRequirements{
		Scheme: payment.SchemeCredit, Network: network, Amount: payment.Amount(amount),
		Asset: payment.AssetCredit, PayTo: payTo,
	}
}

// authFor signs an authorization with explicit terms.
func authFor(t *testing.T, payer *identity.Controller, payTo string, amount uint64,
	network, ix, nonce string, issuedAt, notAfter int64) *payment.Authorization {
	t.Helper()
	a := &payment.Authorization{PayTo: payTo, Amount: amount, Network: network, Nonce: nonce,
		IssuedAt: issuedAt, NotAfter: notAfter, InteractionID: ix}
	if err := a.Sign(payer); err != nil {
		t.Fatal(err)
	}
	return a
}

// facilitatorCall posts a /verify or /settle body and returns the status
// and the raw answer.
func facilitatorCall(t *testing.T, srv *httptest.Server, path string, p *payment.PaymentPayload,
	req *payment.PaymentRequirements) (int, []byte) {
	t.Helper()
	body := map[string]any{"x402Version": payment.Version, "paymentPayload": p}
	if req != nil {
		body["paymentRequirements"] = req
	}
	return post(t, srv.URL+path, body)
}

func settleCall(t *testing.T, srv *httptest.Server, p *payment.PaymentPayload,
	req *payment.PaymentRequirements) (int, payment.SettlementResponse) {
	t.Helper()
	code, b := facilitatorCall(t, srv, "/x402/settle", p, req)
	var out payment.SettlementResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("settle answer %d is not a SettlementResponse: %s", code, b)
	}
	return code, out
}

func verifyCall(t *testing.T, srv *httptest.Server, p *payment.PaymentPayload,
	req *payment.PaymentRequirements) (int, payment.VerifyResponse) {
	t.Helper()
	code, b := facilitatorCall(t, srv, "/x402/verify", p, req)
	var out payment.VerifyResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("verify answer %d is not a VerifyResponse: %s", code, b)
	}
	return code, out
}

// balances reads several accounts at once, for "nothing moved" checks.
func balances(t *testing.T, srv *httptest.Server, aids ...string) []int64 {
	t.Helper()
	out := make([]int64, len(aids))
	for i, aid := range aids {
		out[i] = balanceOf(t, srv, aid)
	}
	return out
}

func sameBalances(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A settle or verify request without paymentRequirements is refused with
// 400 and moves nothing. Without the requirements the hub would settle
// whatever the payer signed.
func TestSettleAndVerifyRequirePaymentRequirements(t *testing.T) {
	srv := newHub(t)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	own := payment.CreditNetwork(hubAIDOf(t, srv))
	p := creditPayload(t, signedAuth(t, payer, payee.AID(), 30, hubAIDOf(t, srv), "req-missing"), payee.AID(), own)
	before := balances(t, srv, payer.AID(), payee.AID())

	code, sr := settleCall(t, srv, p, nil)
	if code != http.StatusBadRequest || sr.Success || sr.ErrorReason != payment.ReasonInvalidRequirements {
		t.Errorf("settle without requirements = %d %+v, want 400 %s", code, sr, payment.ReasonInvalidRequirements)
	}
	vcode, vr := verifyCall(t, srv, p, nil)
	if vcode != http.StatusBadRequest || vr.IsValid || vr.InvalidReason != payment.ReasonInvalidRequirements {
		t.Errorf("verify without requirements = %d %+v, want 400 %s", vcode, vr, payment.ReasonInvalidRequirements)
	}
	if after := balances(t, srv, payer.AID(), payee.AID()); !sameBalances(before, after) {
		t.Errorf("a request without requirements moved credit: %v -> %v", before, after)
	}
	// The same payment with its requirements settles, so the refusal above
	// was about the missing field and nothing else.
	if _, sr := settleCall(t, srv, p, requirementsFor(payee.AID(), 30, own)); !sr.Success {
		t.Fatalf("the same payment with requirements: %+v", sr)
	}
}

// The facilitator settles only a payment that meets the requirements, and
// compares the signed authorization, not only the payer's unsigned
// statement of what it accepted (A2A-DESIGN SI-9, R06 D2).
func TestSettleRefusesPaymentsThatDoNotMeetTheRequirements(t *testing.T) {
	srv := newHub(t)
	payer, payee := twoAgents(t)
	third, _ := identity.Incept()
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	register(t, srv, third, "Third", nil)
	fundAgent(t, srv, payer.AID(), 500)
	hubAID := hubAIDOf(t, srv)
	own := payment.CreditNetwork(hubAID)
	now := time.Now().UnixMilli()

	type tc struct {
		name   string
		auth   func(nonce string) *payment.Authorization
		accept func(a *payment.Authorization) payment.PaymentOption
		req    *payment.PaymentRequirements
		reason string
	}
	honest := func(a *payment.Authorization) payment.PaymentOption {
		return payment.PaymentOption{Scheme: payment.SchemeCredit, Network: a.Network,
			Amount: payment.Amount(a.Amount), Asset: payment.AssetCredit, PayTo: a.PayTo}
	}
	pays := func(to string, amount uint64) func(string) *payment.Authorization {
		return func(nonce string) *payment.Authorization {
			return authFor(t, payer, to, amount, own, "", nonce, now-1000, now+60_000)
		}
	}
	for _, c := range []tc{
		{"underpayment", pays(payee.AID(), 50), honest,
			requirementsFor(payee.AID(), 120, own), payment.ReasonInvalidAmount},
		{"one unit short", pays(payee.AID(), 119), honest,
			requirementsFor(payee.AID(), 120, own), payment.ReasonInvalidAmount},
		{"another payee", pays(third.AID(), 120), honest,
			requirementsFor(payee.AID(), 120, own), payment.ReasonPayeeMismatch},
		{"stated payee differs from the signed one", pays(third.AID(), 120),
			func(a *payment.Authorization) payment.PaymentOption {
				o := honest(a)
				o.PayTo = payee.AID()
				return o
			},
			requirementsFor(payee.AID(), 120, own), payment.ReasonPayeeMismatch},
		{"stated amount differs from the signed one", pays(payee.AID(), 1),
			func(a *payment.Authorization) payment.PaymentOption {
				o := honest(a)
				o.Amount = "120"
				return o
			},
			requirementsFor(payee.AID(), 120, own), payment.ReasonInvalidAmount},
		{"stated payee is not the signed one", pays(payee.AID(), 120),
			func(a *payment.Authorization) payment.PaymentOption {
				o := honest(a)
				o.PayTo = third.AID()
				return o
			},
			requirementsFor(payee.AID(), 120, own), payment.ReasonPayeeMismatch},
		{"stated amount is not the signed one", pays(payee.AID(), 120),
			func(a *payment.Authorization) payment.PaymentOption {
				o := honest(a)
				o.Amount = "999"
				return o
			},
			requirementsFor(payee.AID(), 120, own), payment.ReasonInvalidAmount},
		{"requirements on another network", pays(payee.AID(), 120), honest,
			requirementsFor(payee.AID(), 120, payment.CreditNetwork("did:anet:other-hub")),
			payment.ReasonNetworkMismatch},
		{"requirements on another scheme", pays(payee.AID(), 120), honest,
			func() *payment.PaymentRequirements {
				r := requirementsFor(payee.AID(), 120, own)
				r.Scheme = "exact"
				return r
			}(), payment.ReasonUnsupportedScheme},
		{"payload on another scheme", pays(payee.AID(), 120),
			func(a *payment.Authorization) payment.PaymentOption {
				o := honest(a)
				o.Scheme = "exact"
				return o
			},
			requirementsFor(payee.AID(), 120, own), payment.ReasonUnsupportedScheme},
		{"requirements without an amount", pays(payee.AID(), 120), honest,
			func() *payment.PaymentRequirements {
				r := requirementsFor(payee.AID(), 120, own)
				r.Amount = ""
				return r
			}(), payment.ReasonInvalidRequirements},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := c.auth("n-" + c.name)
			raw, err := a.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			p := &payment.PaymentPayload{X402Version: payment.Version, Accepted: c.accept(a),
				Payload: map[string]any{"authorization": base64.StdEncoding.EncodeToString(raw)}}
			before := balances(t, srv, payer.AID(), payee.AID(), third.AID())

			_, vr := verifyCall(t, srv, p, c.req)
			if vr.IsValid || vr.InvalidReason != c.reason {
				t.Errorf("verify = %+v, want invalid %s", vr, c.reason)
			}
			_, sr := settleCall(t, srv, p, c.req)
			if sr.Success || sr.ErrorReason != c.reason {
				t.Errorf("settle = %+v, want refused %s", sr, c.reason)
			}
			if d, _ := sr.Extensions[payment.ExtErrorDetail].(string); d == "" {
				t.Error("the refusal carries no detail for a person to read")
			}
			if after := balances(t, srv, payer.AID(), payee.AID(), third.AID()); !sameBalances(before, after) {
				t.Errorf("a refused payment moved credit: %v -> %v", before, after)
			}
		})
	}

	// Paying more than required is allowed, and what settles is what was
	// signed.
	before := balanceOf(t, srv, payee.AID())
	a := authFor(t, payer, payee.AID(), 130, own, "", "n-over", now-1000, now+60_000)
	_, sr := settleCall(t, srv, creditPayload(t, a, payee.AID(), own), requirementsFor(payee.AID(), 120, own))
	if !sr.Success || sr.Amount != "130" {
		t.Fatalf("an overpayment: %+v, want success for 130", sr)
	}
	if got := balanceOf(t, srv, payee.AID()); got != before+130 {
		t.Errorf("payee balance %d, want %d", got, before+130)
	}
}

// Resending a settled authorization is answered with the original
// receipt, byte for byte, and charges nothing. The after-the-window case
// is in facilitator_internal_test.go.
func TestARepeatedSettlementIsAnsweredWithTheOriginalReceipt(t *testing.T) {
	srv := newHub(t)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	own := payment.CreditNetwork(hubAIDOf(t, srv))
	p := creditPayload(t, signedAuth(t, payer, payee.AID(), 40, hubAIDOf(t, srv), "repeat-1"), payee.AID(), own)
	req := requirementsFor(payee.AID(), 40, own)

	_, first := settleCall(t, srv, p, req)
	if !first.Success {
		t.Fatalf("first settle: %+v", first)
	}
	afterFirst := balances(t, srv, payer.AID(), payee.AID())
	time.Sleep(5 * time.Millisecond) // a re-signed receipt would carry a later SettleAt
	_, again := settleCall(t, srv, p, req)
	if !again.Success || again.Extensions[payment.ExtReplayed] != true {
		t.Fatalf("repeat: %+v, want success flagged %s", again, payment.ExtReplayed)
	}
	if again.Transaction != first.Transaction {
		t.Errorf("repeat transaction %s, first %s", again.Transaction, first.Transaction)
	}
	r1, _ := first.Extensions[payment.ExtReceipt].(string)
	r2, _ := again.Extensions[payment.ExtReceipt].(string)
	if r1 == "" || r1 != r2 {
		t.Errorf("the repeat's receipt differs from the original:\n first %q\n again %q", r1, r2)
	}
	if after := balances(t, srv, payer.AID(), payee.AID()); !sameBalances(afterFirst, after) {
		t.Errorf("a repeat moved credit: %v -> %v", afterFirst, after)
	}
	// /verify answers the question "would this settle" for a settled
	// authorization with duplicate_nonce: it would not move anything again.
	if _, vr := verifyCall(t, srv, p, req); vr.IsValid || vr.InvalidReason != payment.ReasonDuplicateNonce {
		t.Errorf("verify of a settled authorization = %+v, want %s", vr, payment.ReasonDuplicateNonce)
	}
}

// One binding, one charge: a second authorization from the same payer
// with the same interaction id is refused with duplicate_binding, moves
// nothing, and names the settlement that holds the binding (A2A-DESIGN
// §8.5, C13).
func TestASecondAuthorizationForOneBindingMovesNothing(t *testing.T) {
	srv := newHub(t)
	payer, payee := twoAgents(t)
	other, _ := identity.Incept()
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	register(t, srv, other, "Other", nil)
	fundAgent(t, srv, payer.AID(), 500)
	own := payment.CreditNetwork(hubAIDOf(t, srv))
	now := time.Now().UnixMilli()
	req := requirementsFor(payee.AID(), 100, own)
	const bind = "pay-bind-0001"

	first := authFor(t, payer, payee.AID(), 100, own, bind, "nonce-1", now-1000, now+60_000)
	_, s1 := settleCall(t, srv, creditPayload(t, first, payee.AID(), own), req)
	if !s1.Success {
		t.Fatalf("first: %+v", s1)
	}
	before := balances(t, srv, payer.AID(), payee.AID())

	second := authFor(t, payer, payee.AID(), 100, own, bind, "nonce-2", now-1000, now+60_000)
	p2 := creditPayload(t, second, payee.AID(), own)
	_, vr := verifyCall(t, srv, p2, req)
	if vr.IsValid || vr.InvalidReason != payment.ReasonDuplicateBinding {
		t.Errorf("verify of the second = %+v, want %s", vr, payment.ReasonDuplicateBinding)
	}
	_, s2 := settleCall(t, srv, p2, req)
	if s2.Success || s2.ErrorReason != payment.ReasonDuplicateBinding {
		t.Fatalf("second = %+v, want refused %s", s2, payment.ReasonDuplicateBinding)
	}
	if got := s2.Extensions[payment.ExtOriginalTransaction]; got != s1.Transaction {
		t.Errorf("%s = %v, want the first settlement %s", payment.ExtOriginalTransaction, got, s1.Transaction)
	}
	if after := balances(t, srv, payer.AID(), payee.AID()); !sameBalances(before, after) {
		t.Errorf("the second authorization moved credit: %v -> %v", before, after)
	}

	// The first one resent is a repeat, not a second authorization.
	_, again := settleCall(t, srv, creditPayload(t, first, payee.AID(), own), req)
	if !again.Success || again.Transaction != s1.Transaction {
		t.Errorf("resending the first: %+v", again)
	}

	// The binding is per payer: another payer may use the same value.
	fundAgent(t, srv, other.AID(), 500)
	o := authFor(t, other, payee.AID(), 100, own, bind, "nonce-o", now-1000, now+60_000)
	if _, so := settleCall(t, srv, creditPayload(t, o, payee.AID(), own), req); !so.Success {
		t.Errorf("another payer with the same binding value: %+v", so)
	}
	// And an empty interaction id binds nothing.
	for _, n := range []string{"free-1", "free-2"} {
		a := authFor(t, payer, payee.AID(), 100, own, "", n, now-1000, now+60_000)
		if _, s := settleCall(t, srv, creditPayload(t, a, payee.AID(), own), req); !s.Success {
			t.Errorf("unbound authorization %s: %+v", n, s)
		}
	}
}

// A settlement that fails rolls back its row, so the binding stays free
// and a retry after the failure is not taken for a duplicate.
func TestAFailedSettlementLeavesTheBindingFree(t *testing.T) {
	srv := newHub(t)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	own := payment.CreditNetwork(hubAIDOf(t, srv))
	now := time.Now().UnixMilli()
	amount := uint64(aghub.RegistrationGrant + 50)
	req := requirementsFor(payee.AID(), amount, own)
	const bind = "pay-bind-rollback"

	first := authFor(t, payer, payee.AID(), amount, own, bind, "r-1", now-1000, now+60_000)
	if _, s := settleCall(t, srv, creditPayload(t, first, payee.AID(), own), req); s.Success ||
		s.ErrorReason != payment.ReasonInsufficientFunds {
		t.Fatalf("unfunded: %+v, want %s", s, payment.ReasonInsufficientFunds)
	}
	fundAgent(t, srv, payer.AID(), 100)
	second := authFor(t, payer, payee.AID(), amount, own, bind, "r-2", now-1000, now+60_000)
	s2 := func() payment.SettlementResponse {
		_, s := settleCall(t, srv, creditPayload(t, second, payee.AID(), own), req)
		return s
	}()
	if !s2.Success {
		t.Fatalf("the retry after a failed settlement: %+v", s2)
	}
	// Now the binding is held, and the first authorization is the
	// duplicate.
	if _, s := settleCall(t, srv, creditPayload(t, first, payee.AID(), own), req); s.Success ||
		s.ErrorReason != payment.ReasonDuplicateBinding {
		t.Errorf("the first authorization after the second settled: %+v", s)
	}
}

// Every refusal reports exactly one of the x402-layer constants, with no
// prose appended; the prose is in the extensions.
func TestEveryRefusalCarriesAReasonConstant(t *testing.T) {
	srv := newHub(t)
	payer, payee := twoAgents(t)
	stranger, _ := identity.Incept()
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	hubAID := hubAIDOf(t, srv)
	own := payment.CreditNetwork(hubAID)
	now := time.Now().UnixMilli()
	req := func(amount uint64) *payment.PaymentRequirements { return requirementsFor(payee.AID(), amount, own) }

	tampered := authFor(t, payer, payee.AID(), 90, own, "", "t-1", now-1000, now+60_000)
	tampered.Amount = 5 // the signature covers 90

	malformed := creditPayload(t, signedAuth(t, payer, payee.AID(), 5, hubAID, "m-1"), payee.AID(), own)
	malformed.Payload["authorization"] = "not base64 !"

	for _, c := range []struct {
		name   string
		p      *payment.PaymentPayload
		req    *payment.PaymentRequirements
		reason string
	}{
		{"unregistered payer", creditPayload(t, signedAuth(t, stranger, payee.AID(), 5, hubAID, "u-1"), payee.AID(), own),
			req(5), payment.ReasonUnknownPayer},
		{"signature over other terms", creditPayload(t, tampered, payee.AID(), own), req(5), payment.ReasonInvalidSignature},
		{"expired", creditPayload(t, authFor(t, payer, payee.AID(), 5, own, "", "e-1", now-20*60_000, now-10*60_000),
			payee.AID(), own), req(5), payment.ReasonExpiredPayment},
		{"empty window", creditPayload(t, authFor(t, payer, payee.AID(), 5, own, "", "w-1", now, now),
			payee.AID(), own), req(5), payment.ReasonExpiredPayment},
		{"unreadable authorization", malformed, req(5), payment.ReasonMalformed},
		{"another hub's ledger", creditPayload(t, authFor(t, payer, payee.AID(), 5, payment.CreditNetwork("did:anet:x"), "", "f-1", now-1000, now+60_000),
			payee.AID(), payment.CreditNetwork("did:anet:x")), requirementsFor(payee.AID(), 5, payment.CreditNetwork("did:anet:x")),
			payment.ReasonNetworkMismatch},
		{"insufficient funds", creditPayload(t, signedAuth(t, payer, payee.AID(), aghub.RegistrationGrant+1, hubAID, "i-1"), payee.AID(), own),
			req(aghub.RegistrationGrant + 1), payment.ReasonInsufficientFunds},
	} {
		_, sr := settleCall(t, srv, c.p, c.req)
		if sr.Success || sr.ErrorReason != c.reason {
			t.Errorf("%s: settle = %+v, want exactly %q", c.name, sr, c.reason)
		}
		_, vr := verifyCall(t, srv, c.p, c.req)
		if vr.IsValid || vr.InvalidReason != c.reason {
			t.Errorf("%s: verify = %+v, want exactly %q", c.name, vr, c.reason)
		}
	}
}

// The entry hub checks the requirements before it forwards anything, and
// /x402/verify never forwards: it answers network_mismatch for a peer's
// ledger.
func TestAForeignLedgerPaymentIsCheckedBeforeItIsForwarded(t *testing.T) {
	srv, store := newHubWithStore(t)
	payer, payee := twoAgents(t)
	register(t, srv, payee, "Payee", nil)
	peer := payment.CreditNetwork("did:anet:peer-hub")
	now := time.Now().UnixMilli()
	forwarded := 0
	store.SetPeerSettler(func(network string, p *payment.PaymentPayload, req *payment.PaymentRequirements,
		auth *payment.Authorization) (payment.SettlementResponse, bool) {
		forwarded++
		return payment.SettlementResponse{Success: true, Network: network}, true
	})

	under := authFor(t, payer, payee.AID(), 10, peer, "", "fw-1", now-1000, now+60_000)
	_, sr := settleCall(t, srv, creditPayload(t, under, payee.AID(), peer), requirementsFor(payee.AID(), 120, peer))
	if sr.Success || sr.ErrorReason != payment.ReasonInvalidAmount {
		t.Errorf("an underpayment on a peer's ledger: %+v, want %s", sr, payment.ReasonInvalidAmount)
	}
	elsewhere := authFor(t, payer, "did:anet:someone-else", 120, peer, "", "fw-2", now-1000, now+60_000)
	_, sr = settleCall(t, srv, creditPayload(t, elsewhere, "did:anet:someone-else", peer), requirementsFor(payee.AID(), 120, peer))
	if sr.Success || sr.ErrorReason != payment.ReasonPayeeMismatch {
		t.Errorf("a payment to someone else on a peer's ledger: %+v, want %s", sr, payment.ReasonPayeeMismatch)
	}
	// Offered on the peer's ledger while the authorization and the
	// requirements name this hub's: the offer is not what was required.
	hubNet := payment.CreditNetwork(hubAIDOf(t, srv))
	crossed := creditPayload(t, authFor(t, payer, payee.AID(), 120, hubNet, "", "fw-4", now-1000, now+60_000),
		payee.AID(), peer)
	_, sr = settleCall(t, srv, crossed, requirementsFor(payee.AID(), 120, hubNet))
	if sr.Success || sr.ErrorReason != payment.ReasonNetworkMismatch {
		t.Errorf("an offer on another network than required: %+v, want %s", sr, payment.ReasonNetworkMismatch)
	}
	// A scheme this facilitator does not settle, even when payload and
	// requirements agree on it.
	exact := creditPayload(t, authFor(t, payer, payee.AID(), 120, peer, "", "fw-5", now-1000, now+60_000),
		payee.AID(), peer)
	exact.Accepted.Scheme = "exact"
	exactReq := requirementsFor(payee.AID(), 120, peer)
	exactReq.Scheme = "exact"
	_, sr = settleCall(t, srv, exact, exactReq)
	if sr.Success || sr.ErrorReason != payment.ReasonUnsupportedScheme {
		t.Errorf("scheme exact on a peer's ledger: %+v, want %s", sr, payment.ReasonUnsupportedScheme)
	}
	// Offered and required on the peer's ledger while the authorization
	// was signed for another one: the signed network decides where it can
	// settle, and it is not the ledger the requirements name.
	signedElsewhere := creditPayload(t, authFor(t, payer, payee.AID(), 120,
		payment.CreditNetwork("did:anet:third-hub"), "", "fw-6", now-1000, now+60_000), payee.AID(), peer)
	_, sr = settleCall(t, srv, signedElsewhere, requirementsFor(payee.AID(), 120, peer))
	if sr.Success || sr.ErrorReason != payment.ReasonNetworkMismatch {
		t.Errorf("an authorization signed for another ledger than required: %+v, want %s",
			sr, payment.ReasonNetworkMismatch)
	}
	if forwarded != 0 {
		t.Fatalf("%d refused payment(s) were forwarded to the ledger hub", forwarded)
	}

	good := authFor(t, payer, payee.AID(), 120, peer, "", "fw-3", now-1000, now+60_000)
	gp := creditPayload(t, good, payee.AID(), peer)
	gr := requirementsFor(payee.AID(), 120, peer)
	_, vr := verifyCall(t, srv, gp, gr)
	if vr.IsValid || vr.InvalidReason != payment.ReasonNetworkMismatch {
		t.Errorf("verify on a peer's ledger = %+v, want %s", vr, payment.ReasonNetworkMismatch)
	}
	if forwarded != 0 {
		t.Error("verify forwarded a payment")
	}
	if _, sr := settleCall(t, srv, gp, gr); !sr.Success || forwarded != 1 {
		t.Errorf("a payment that meets the requirements was not forwarded: %+v (forwarded %d)", sr, forwarded)
	}
}

// /x402/supported names the extension every settlement carries and who
// signs on each network, with where to fetch the signer's KEL.
func TestSupportedNamesTheExtensionsAndSigners(t *testing.T) {
	srv := newHub(t)
	hubAID := hubAIDOf(t, srv)
	code, b := getJSON(t, srv.URL+"/x402/supported")
	if code != http.StatusOK {
		t.Fatalf("supported: %d %s", code, b)
	}
	var sup payment.Supported
	if err := json.Unmarshal(b, &sup); err != nil {
		t.Fatal(err)
	}
	if len(sup.Extensions) != 1 || sup.Extensions[0] != payment.ExtReceipt {
		t.Errorf("extensions = %v, want [%s]", sup.Extensions, payment.ExtReceipt)
	}
	own := payment.CreditNetwork(hubAID)
	if got := sup.Signers[own]; len(got) != 1 || got[0] != hubAID {
		t.Errorf("signers[%s] = %v, want [%s]", own, got, hubAID)
	}
	if got := sup.SignerKEL[hubAID]; got != srv.URL+"/hub/identity" {
		t.Errorf("signer KEL URL = %q, want %s/hub/identity", got, srv.URL)
	}
}

// Balance, ledger and redemptions answer only the account holder's own
// signed GET; the signature binds the action, the path and the query.
func TestLedgerReadsAreForTheAccountHolderOnly(t *testing.T) {
	srv := newHub(t)
	owner, other := twoAgents(t)
	register(t, srv, owner, "Owner", nil)
	register(t, srv, other, "Other", nil)
	base := "/agents/" + owner.AID()

	for _, c := range []struct {
		action, path, field string
	}{
		{relayauth.ActionBalance, base + "/balance", `"credits"`},
		{relayauth.ActionLedger, base + "/ledger", `"entries"`},
		{relayauth.ActionRedemptions, base + "/redemptions", `"redemptions"`},
	} {
		// Unsigned: 401 naming the headers, and no data.
		code, body := getJSON(t, srv.URL+c.path)
		if code != http.StatusUnauthorized || !strings.Contains(string(body), relayauth.HeaderSig) ||
			strings.Contains(string(body), c.field) {
			t.Errorf("unsigned GET %s = %d %s, want 401 without data", c.path, code, body)
		}
		// Signed by somebody else.
		if code, body := ownerGet(t, srv, other, c.action, c.path); code != http.StatusUnauthorized {
			t.Errorf("GET %s signed by another agent = %d %s, want 401", c.path, code, body)
		}
		// Signed by the owner for another action.
		wrong := relayauth.ActionBalance
		if c.action == relayauth.ActionBalance {
			wrong = relayauth.ActionLedger
		}
		if code, body := ownerGet(t, srv, owner, wrong, c.path); code != http.StatusUnauthorized {
			t.Errorf("GET %s signed for action %q = %d %s, want 401", c.path, wrong, code, body)
		}
		// Signed for one query, sent with another.
		req := signedRequest(t, srv, owner, c.action, http.MethodGet, c.path+"?limit=1", nil)
		req.URL.RawQuery = "limit=500"
		if code, body, _ := send(t, req); code != http.StatusUnauthorized {
			t.Errorf("GET %s with a query other than the signed one = %d %s, want 401", c.path, code, body)
		}
		// The owner's own signed read.
		req = signedRequest(t, srv, owner, c.action, http.MethodGet, c.path+"?limit=5", nil)
		code, body, _ = send(t, req)
		if code != http.StatusOK || !strings.Contains(string(body), c.field) {
			t.Errorf("the owner's signed GET %s = %d %s, want 200 with %s", c.path, code, body, c.field)
		}
		// And that signature is spent.
		again := signedRequest(t, srv, owner, c.action, http.MethodGet, c.path+"?limit=5", nil)
		again.Header = req.Header.Clone()
		if code, _, _ := send(t, again); code != http.StatusUnauthorized {
			t.Errorf("a replayed signed GET %s = %d, want 401", c.path, code)
		}
	}
	// The balance an owner reads is its own.
	code, body := ownerGet(t, srv, owner, relayauth.ActionBalance, base+"/balance")
	var bal aghub.Balance
	if code != http.StatusOK || json.Unmarshal(body, &bal) != nil || bal.AID != owner.AID() ||
		bal.Credits != aghub.RegistrationGrant {
		t.Errorf("owner balance = %d %s", code, body)
	}
}

// mismatchedPayment is a PAYMENT-SIGNATURE whose accepted option states
// one set of terms while the signed authorization carries another.
func mismatchedPayment(t *testing.T, payer *identity.Controller, stated payment.PaymentOption,
	payTo string, amount uint64, ix string) string {
	t.Helper()
	now := time.Now()
	a := authFor(t, payer, payTo, amount, stated.Network, ix, ix, now.UnixMilli(), now.Add(5*time.Minute).UnixMilli())
	raw, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(payment.PaymentPayload{X402Version: payment.Version, Accepted: stated,
		Payload: map[string]any{"authorization": base64.StdEncoding.EncodeToString(raw)}})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// The gateway settles the signed authorization, so it compares that with
// the quote: a buyer who states the price to the seller while signing a
// smaller amount, or a payment to somebody else, gets no voucher and
// moves nothing (R06 D2).
func TestTheGatewayComparesTheSignedTermsWithTheQuote(t *testing.T) {
	srv, store := newHubWithStore(t)
	seller, buyer := twoAgents(t)
	accomplice, _ := identity.Incept()
	if code, b := registerWithCard(t, srv, seller, "Worker", []string{"work.do"},
		sellableCard(t, seller, "Worker", []string{"work.do"},
			map[string]any{"work.do": 120}, "https://worker.example/x402/redeem")); code != 200 {
		t.Fatalf("register: %d %s", code, b)
	}
	register(t, srv, buyer, "Buyer", nil)
	register(t, srv, accomplice, "Accomplice", nil)
	fundAgent(t, srv, buyer.AID(), 500)
	stated := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAIDOf(t, srv)),
		Amount: "120", Asset: payment.AssetCredit, PayTo: seller.AID(),
	}
	url := srv.URL + "/x402/resource/" + seller.AID() + "/work.do"
	for _, c := range []struct {
		name   string
		payTo  string
		amount uint64
		reason string
	}{
		{"signed to somebody else", accomplice.AID(), 120, payment.ReasonPayeeMismatch},
		{"signed for less", seller.AID(), 1, payment.ReasonInvalidAmount},
	} {
		before := balances(t, srv, buyer.AID(), seller.AID(), accomplice.AID())
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(payment.HeaderPaymentSignature,
			mismatchedPayment(t, buyer, stated, c.payTo, c.amount, "gw-"+c.name))
		code, body, _ := send(t, req)
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		if code != http.StatusPaymentRequired || out["voucher"] != nil || out["error"] != c.reason {
			t.Errorf("%s: %d %s, want 402 %s and no voucher", c.name, code, body, c.reason)
		}
		if after := balances(t, srv, buyer.AID(), seller.AID(), accomplice.AID()); !sameBalances(before, after) {
			t.Errorf("%s: credit moved: %v -> %v", c.name, before, after)
		}
	}

	// A payment on a peer's ledger is refused, not forwarded: the voucher
	// is this hub's statement that it holds the payment.
	forwarded := 0
	store.SetPeerSettler(func(network string, p *payment.PaymentPayload, req *payment.PaymentRequirements,
		auth *payment.Authorization) (payment.SettlementResponse, bool) {
		forwarded++
		return payment.SettlementResponse{Success: true, Network: network, Amount: "120"}, true
	})
	onPeer := stated
	onPeer.Network = payment.CreditNetwork("did:anet:peer-hub")
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set(payment.HeaderPaymentSignature, signedPayment(t, buyer, onPeer, "gw-peer"))
	code, body, _ := send(t, req)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if code != http.StatusPaymentRequired || out["voucher"] != nil || out["error"] != payment.ReasonNetworkMismatch ||
		forwarded != 0 {
		t.Errorf("paying on a peer's ledger: %d %s (forwarded %d), want 402 %s and nothing forwarded",
			code, body, forwarded, payment.ReasonNetworkMismatch)
	}
}

// A redemption is a payment to this hub. An authorization paying anybody
// else is refused and moves nothing.
func TestARedemptionMustPayTheHub(t *testing.T) {
	srv := newHub(t)
	agent, other := twoAgents(t)
	register(t, srv, agent, "Agent", nil)
	register(t, srv, other, "Other", nil)
	opt := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAIDOf(t, srv)),
		Amount: "30", Asset: payment.AssetCredit, PayTo: other.AID(),
	}
	before := balances(t, srv, agent.AID(), other.AID())
	code, body := post(t, srv.URL+"/x402/redeem", map[string]any{
		"x402Version":    payment.Version,
		"paymentPayload": json.RawMessage(mustPayload(t, agent, opt, "redeem:elsewhere")),
		"reference":      "elsewhere",
	})
	if code != http.StatusBadRequest || !strings.Contains(string(body), payment.ReasonPayeeMismatch) {
		t.Errorf("a redemption paying another agent: %d %s, want 400 %s", code, body, payment.ReasonPayeeMismatch)
	}
	if after := balances(t, srv, agent.AID(), other.AID()); !sameBalances(before, after) {
		t.Errorf("a refused redemption moved credit: %v -> %v", before, after)
	}
}

// The voucher states the amount that settled. A buyer who paid more than
// the price holds a voucher for what it paid.
func TestAGatewayVoucherStatesTheSettledAmount(t *testing.T) {
	srv := newHub(t)
	seller, buyer := twoAgents(t)
	if code, b := registerWithCard(t, srv, seller, "Worker", []string{"work.do"},
		sellableCard(t, seller, "Worker", []string{"work.do"},
			map[string]any{"work.do": 120}, "https://worker.example/x402/redeem")); code != 200 {
		t.Fatalf("register: %d %s", code, b)
	}
	register(t, srv, buyer, "Buyer", nil)
	fundAgent(t, srv, buyer.AID(), 500)
	opt := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAIDOf(t, srv)),
		Amount: "150", Asset: payment.AssetCredit, PayTo: seller.AID(),
	}
	sellerBefore := balanceOf(t, srv, seller.AID())
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x402/resource/"+seller.AID()+"/work.do", nil)
	req.Header.Set(payment.HeaderPaymentSignature, signedPayment(t, buyer, opt, "gw-over"))
	code, body, _ := send(t, req)
	if code != http.StatusOK {
		t.Fatalf("paying 150 for a price of 120: %d %s", code, body)
	}
	var out struct {
		Voucher string `json:"voucher"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(out.Voucher)
	if err != nil {
		t.Fatal(err)
	}
	v, err := payment.UnmarshalVoucher(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.Amount != 150 {
		t.Errorf("voucher amount %d, want the settled 150", v.Amount)
	}
	if got := balanceOf(t, srv, seller.AID()); got != sellerBefore+150 {
		t.Errorf("seller balance %d, want %d", got, sellerBefore+150)
	}
}

// The entry hub credits its payee only against a ledger hub receipt for
// the forwarded authorization and the required terms. A receipt naming
// another payee, a smaller amount or another authorization is refused and
// credits nothing; the refusal keeps the receipt as evidence. A matching
// receipt whose signer's key history cannot be read is pending.
func TestTheEntryHubClearsOnlyAReceiptForTheRequiredTerms(t *testing.T) {
	_, store := newHubWithStore(t)
	ledgerHub, _ := identity.Incept()
	payer, payee := twoAgents(t)
	other, _ := identity.Incept()
	network := payment.CreditNetwork(ledgerHub.AID())
	now := time.Now().UnixMilli()
	auth := authFor(t, payer, payee.AID(), 60, network, "", "clear-1", now-1000, now+60_000)
	id, err := auth.ID()
	if err != nil {
		t.Fatal(err)
	}
	req := requirementsFor(payee.AID(), 60, network)
	kel := func(string) ([]identity.SignedEvent, error) { return ledgerHub.KEL(), nil }
	answer := func(authID, payTo string, amount uint64) payment.SettlementResponse {
		rec := &payment.Receipt{AuthID: authID, Payer: payer.AID(), PayTo: payTo, Amount: amount,
			Network: network, SettleAt: now}
		if err := rec.Sign(ledgerHub); err != nil {
			t.Fatal(err)
		}
		raw, err := rec.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return payment.SettlementResponse{Success: true, Payer: payer.AID(), Transaction: authID,
			Network: network, Amount: payment.Amount(amount),
			Extensions: map[string]any{payment.ExtReceipt: base64.StdEncoding.EncodeToString(raw)}}
	}
	credited := func() int64 {
		n, err := store.Balance(payee.AID())
		if err != nil {
			t.Fatal(err)
		}
		m, _ := store.Balance(other.AID())
		return n + m
	}

	for _, c := range []struct {
		name   string
		out    payment.SettlementResponse
		reason string
	}{
		{"receipt for another payee", answer(id, other.AID(), 60), payment.ReasonPayeeMismatch},
		{"receipt for less", answer(id, payee.AID(), 59), payment.ReasonInvalidAmount},
		{"receipt for another authorization", answer("bafyother", payee.AID(), 60), payment.ReasonSettlementFailed},
		{"no receipt", payment.SettlementResponse{Success: true, Network: network}, payment.ReasonSettlementFailed},
	} {
		got := store.ClearPeerSettlement(ledgerHub.AID(), kel, c.out, auth, req)
		if got.Success || got.ErrorReason != c.reason {
			t.Errorf("%s: %+v, want %s", c.name, got, c.reason)
		}
		if rec, ok := c.out.Extensions[payment.ExtReceipt]; ok && got.Extensions[payment.ExtReceipt] != rec {
			t.Errorf("%s: the refusal does not keep the ledger hub's receipt", c.name)
		}
		if n := credited(); n != 0 {
			t.Fatalf("%s: credited %d", c.name, n)
		}
	}

	good := answer(id, payee.AID(), 60)
	// The receipt does not verify against the key history this hub holds
	// for the ledger hub (a key rotation this hub has not seen, say).
	stale, _ := identity.Incept()
	staleKEL := func(string) ([]identity.SignedEvent, error) { return stale.KEL(), nil }
	if got := store.ClearPeerSettlement(ledgerHub.AID(), staleKEL, good, auth, req); got.Success ||
		got.ErrorReason != payment.ReasonSettlementPending || got.Extensions[payment.ExtReceipt] == nil {
		t.Errorf("receipt not verifiable against the held key history: %+v, want %s with the receipt",
			got, payment.ReasonSettlementPending)
	}
	unreadable := func(string) ([]identity.SignedEvent, error) { return nil, io.ErrUnexpectedEOF }
	if got := store.ClearPeerSettlement(ledgerHub.AID(), unreadable, good, auth, req); got.Success ||
		got.ErrorReason != payment.ReasonSettlementPending {
		t.Errorf("key history unreadable: %+v, want %s", got, payment.ReasonSettlementPending)
	}
	if n := credited(); n != 0 {
		t.Fatalf("credited %d while pending", n)
	}
	for i := 0; i < 2; i++ {
		if got := store.ClearPeerSettlement(ledgerHub.AID(), kel, good, auth, req); !got.Success {
			t.Fatalf("clearing a matching receipt (round %d): %+v", i, got)
		}
	}
	if n := credited(); n != 60 {
		t.Errorf("credited %d after clearing twice, want 60 once", n)
	}
}

// A repeat is answered with the original receipt only for a payload that
// carries the payer's valid signature. The authorization id is computed
// from the terms and not from the signature, so a lookup made before the
// signature check would answer anyone who copied the terms of a settled
// authorization.
func TestARepeatWithABrokenSignatureIsNotAnsweredWithTheReceipt(t *testing.T) {
	srv := newHub(t)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	own := payment.CreditNetwork(hubAIDOf(t, srv))
	now := time.Now().UnixMilli()
	req := requirementsFor(payee.AID(), 20, own)
	a := authFor(t, payer, payee.AID(), 20, own, "", "sig-1", now-1000, now+60_000)
	if _, s := settleCall(t, srv, creditPayload(t, a, payee.AID(), own), req); !s.Success {
		t.Fatalf("settle: %+v", s)
	}
	before := balances(t, srv, payer.AID(), payee.AID())

	forged := *a
	env := *a.Envelope
	env.Sig = append([]byte(nil), a.Envelope.Sig...)
	env.Sig[0] ^= 0xff
	forged.Envelope = &env
	_, s := settleCall(t, srv, creditPayload(t, &forged, payee.AID(), own), req)
	if s.Success || s.ErrorReason != payment.ReasonInvalidSignature {
		t.Errorf("a settled authorization with a broken signature: %+v, want %s", s, payment.ReasonInvalidSignature)
	}
	if rec := s.Extensions[payment.ExtReceipt]; rec != nil {
		t.Errorf("the refusal carries the settlement receipt: %v", rec)
	}
	if after := balances(t, srv, payer.AID(), payee.AID()); !sameBalances(before, after) {
		t.Errorf("credit moved: %v -> %v", before, after)
	}
}

// gatewayBuy sends one PAYMENT-SIGNATURE to the gateway and returns the
// status and the voucher, if any.
func gatewayBuy(t *testing.T, srv *httptest.Server, seller, capID, header string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x402/resource/"+seller+"/"+capID, nil)
	req.Header.Set(payment.HeaderPaymentSignature, header)
	code, body, _ := send(t, req)
	var out struct {
		Voucher string `json:"voucher"`
	}
	_ = json.Unmarshal(body, &out)
	return code, out.Voucher
}

// One payment buys one voucher. The facilitator answers a settled
// authorization with its original success at any time, so a buyer can
// send the same PAYMENT-SIGNATURE again; it gets the voucher it was
// issued, byte for byte, and never a second one. A second voucher would
// have a new nonce and so a new id, and the provider's one-use check would
// accept it: the work done again for no payment.
func TestOnePaymentBuysOneVoucher(t *testing.T) {
	srv := newHub(t)
	seller, buyer := twoAgents(t)
	caps := []string{"work.do", "work.other"}
	if code, b := registerWithCard(t, srv, seller, "Worker", caps,
		sellableCard(t, seller, "Worker", caps,
			map[string]any{"work.do": 120, "work.other": 100}, "https://worker.example/x402/redeem")); code != 200 {
		t.Fatalf("register: %d %s", code, b)
	}
	register(t, srv, buyer, "Buyer", nil)
	fundAgent(t, srv, buyer.AID(), 500)
	own := payment.CreditNetwork(hubAIDOf(t, srv))
	opt := payment.PaymentOption{Scheme: payment.SchemeCredit, Network: own,
		Amount: "120", Asset: payment.AssetCredit, PayTo: seller.AID()}
	header := signedPayment(t, buyer, opt, "gw-once")

	code, first := gatewayBuy(t, srv, seller.AID(), "work.do", header)
	if code != http.StatusOK || first == "" {
		t.Fatalf("the purchase: %d", code)
	}
	paid := balances(t, srv, buyer.AID(), seller.AID())

	// The same header again: the same voucher.
	code, again := gatewayBuy(t, srv, seller.AID(), "work.do", header)
	if code != http.StatusOK || again != first {
		t.Errorf("the repeated purchase: %d, voucher identical to the first: %v", code, again == first)
	}
	// The same header for another capability of the same provider: no
	// voucher at all.
	if code, v := gatewayBuy(t, srv, seller.AID(), "work.other", header); code != http.StatusConflict || v != "" {
		t.Errorf("the same payment for another capability: %d voucher=%v, want 409 and none", code, v != "")
	}
	if after := balances(t, srv, buyer.AID(), seller.AID()); !sameBalances(paid, after) {
		t.Errorf("a repeat moved credit: %v -> %v", paid, after)
	}

	// A payment the seller already settled on the relay path buys no
	// voucher here: the work it paid for is being done on that path.
	a := authFor(t, buyer, seller.AID(), 120, own, "", "relay-paid", time.Now().UnixMilli()-1000,
		time.Now().UnixMilli()+60_000)
	p := creditPayload(t, a, seller.AID(), own)
	if _, s := settleCall(t, srv, p, requirementsFor(seller.AID(), 120, own)); !s.Success {
		t.Fatalf("relay settlement: %+v", s)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if code, v := gatewayBuy(t, srv, seller.AID(), "work.do", base64.StdEncoding.EncodeToString(raw)); code != http.StatusConflict || v != "" {
		t.Errorf("a payment settled on the relay path, offered to the gateway: %d voucher=%v, want 409 and none",
			code, v != "")
	}
}

// Resending a redemption authorization is answered with the redemption
// already recorded and its receipt; the credit is taken once.
func TestARepeatedRedemptionReturnsTheRecordedRedemption(t *testing.T) {
	srv := newHub(t)
	agent, _ := identity.Incept()
	register(t, srv, agent, "Agent", nil)
	hubAID := hubAIDOf(t, srv)
	opt := payment.PaymentOption{Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: "30", Asset: payment.AssetCredit, PayTo: hubAID}
	body := map[string]any{
		"x402Version":    payment.Version,
		"paymentPayload": json.RawMessage(mustPayload(t, agent, opt, "redeem:once")),
		"reference":      "once",
	}
	code, b1 := post(t, srv.URL+"/x402/redeem", body)
	if code != http.StatusOK {
		t.Fatalf("redeem: %d %s", code, b1)
	}
	var first aghub.Redemption
	if err := json.Unmarshal(b1, &first); err != nil {
		t.Fatal(err)
	}
	after := balanceOf(t, srv, agent.AID())

	code, b2 := post(t, srv.URL+"/x402/redeem", body)
	var again aghub.Redemption
	if code != http.StatusOK || json.Unmarshal(b2, &again) != nil {
		t.Fatalf("the repeat: %d %s", code, b2)
	}
	if again.AuthID != first.AuthID || again.Amount != 30 || again.Reference != "once" ||
		again.Receipt == "" || again.Receipt != first.Receipt {
		t.Errorf("the repeat answered %+v, want the first redemption %+v", again, first)
	}
	if got := balanceOf(t, srv, agent.AID()); got != after {
		t.Errorf("the repeat took credit again: %d -> %d", after, got)
	}
	if sup := supplyOf(t, srv); sup.Redeemed != 30 || sup.Outstanding != sup.Balances {
		t.Errorf("supply after the repeat = %+v, want 30 redeemed once and a balanced ledger", sup)
	}
}
