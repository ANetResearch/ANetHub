package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// sellableCard is what a provider publishes to be buyable through the
// gateway: a price list and a public address, both inside its signature.
func sellableCard(t *testing.T, c *identity.Controller, name string, caps []string,
	prices map[string]any, redeemAt string) json.RawMessage {
	t.Helper()
	now := time.Now()
	card := &adp.AgentCard{
		SubjectDID: c.AID(), CardSchema: adp.CardSchema{Major: 1},
		Seq: uint64(now.UnixNano()), IssuedAt: now.Unix(),
		NotBefore:    now.Add(-time.Minute).Unix(),
		Capabilities: caps, CriticalExtensions: []string{}, Name: name,
	}
	if len(prices) > 0 {
		card.Extensions = map[string]any{aghub.ExtPricing: prices}
	}
	if redeemAt != "" {
		card.Endpoints = []adp.EndpointDesc{{
			Protocol: aghub.EndpointRedeem, URI: redeemAt, Methods: []string{"POST"}}}
	}
	if err := card.Sign(c); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The gateway: 402, then a voucher. Never a result.
func TestTheGatewaySellsAccessAndNotTheWork(t *testing.T) {
	srv := newHub(t)
	seller, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	buyer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	card := sellableCard(t, seller, "Worker", []string{"work.do"},
		map[string]any{"work.do": 120}, "https://worker.example/x402/redeem")
	if code, b := registerWithCard(t, srv, seller, "Worker", []string{"work.do"}, card); code != 200 {
		t.Fatalf("register seller: %d %s", code, b)
	}
	register(t, srv, buyer, "Buyer", nil)
	fundAgent(t, srv, buyer.AID(), 500)

	url := srv.URL + "/x402/resource/" + seller.AID() + "/work.do"

	// 1. The quote. A 402 that says what it costs and where the work will
	// happen — the buyer needs the second fact before paying, because the
	// hub is not going to do the work for them.
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	var quote struct {
		Accepts  []payment.PaymentOption `json:"accepts"`
		RedeemAt string                  `json:"redeem_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&quote); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("quote = %d, want 402", resp.StatusCode)
	}
	if h := resp.Header.Get(payment.HeaderPaymentRequired); h == "" {
		t.Error("a 402 must carry the terms in the PAYMENT-REQUIRED header")
	}
	if len(quote.Accepts) == 0 || quote.Accepts[0].Amount != "120" {
		t.Fatalf("quote = %+v", quote.Accepts)
	}
	if quote.Accepts[0].PayTo != seller.AID() {
		t.Errorf("the hub quoted itself as payee: %s", quote.Accepts[0].PayTo)
	}
	if quote.RedeemAt != "https://worker.example/x402/redeem" {
		t.Errorf("redeem_at = %q — the buyer cannot find the work", quote.RedeemAt)
	}

	// 2. Pay, and be handed permission rather than a result.
	sig := signedPayment(t, buyer, quote.Accepts[0], "gw-1")
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set(payment.HeaderPaymentSignature, sig)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Voucher     string `json:"voucher"`
		RedeemAt    string `json:"redeem_at"`
		Transaction string `json:"transaction"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("paid request = %d (%+v)", resp.StatusCode, out)
	}
	if resp.Header.Get(payment.HeaderPaymentResponse) == "" {
		t.Error("a settled request must carry PAYMENT-RESPONSE")
	}
	if out.Voucher == "" {
		t.Fatal("paid and got no voucher")
	}

	// 3. The voucher says what the seller will need to check, and is
	// signed by this hub so the seller can check it.
	raw, err := base64.StdEncoding.DecodeString(out.Voucher)
	if err != nil {
		t.Fatal(err)
	}
	v, err := payment.UnmarshalVoucher(raw)
	if err != nil {
		t.Fatal(err)
	}
	hubAID := hubAIDOf(t, srv)
	if err := v.Verify(hubKELOf(t, srv.URL), hubAID, seller.AID(), "work.do",
		payment.CreditNetwork(hubAID), time.Now().UnixMilli()); err != nil {
		t.Errorf("the seller cannot verify what it was sold: %v", err)
	}
	if v.Payer != buyer.AID() || v.Amount != 120 {
		t.Errorf("voucher = %+v", v)
	}

	// 4. The credit moved, and to the seller — not to the hub. Both
	// started with the registration grant on top of what they were
	// funded, which is why the numbers are not 500 and 0.
	wantBuyer := int64(500 + aghub.RegistrationGrant - 120)
	wantSeller := int64(aghub.RegistrationGrant + 120)
	if got := balanceOf(t, srv, buyer.AID()); got != wantBuyer {
		t.Errorf("buyer balance = %d, want %d", got, wantBuyer)
	}
	if got := balanceOf(t, srv, seller.AID()); got != wantSeller {
		t.Errorf("seller balance = %d, want %d", got, wantSeller)
	}
}

// What the gateway must refuse to sell.
func TestTheGatewayRefusesToSellWhatItCannot(t *testing.T) {
	srv := newHub(t)
	unreachable, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	free, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	// Priced, but nowhere to go and collect. Selling this would take money
	// for a voucher that can never be spent.
	if code, b := registerWithCard(t, srv, unreachable, "NAT'd", []string{"work.do"},
		sellableCard(t, unreachable, "NAT'd", []string{"work.do"},
			map[string]any{"work.do": 120}, "")); code != 200 {
		t.Fatalf("register: %d %s", code, b)
	}
	// Reachable, but publishes no price. Absent is not free.
	if code, b := registerWithCard(t, srv, free, "Free", []string{"work.do"},
		sellableCard(t, free, "Free", []string{"work.do"}, nil,
			"https://free.example/x402/redeem")); code != 200 {
		t.Fatalf("register: %d %s", code, b)
	}

	for _, tc := range []struct {
		name, path string
		code       int
		mentions   string
	}{
		{"an agent this hub does not host",
			"/x402/resource/did:anet:nobody/work.do", http.StatusNotFound, "does not host"},
		{"a capability the agent does not price",
			"/x402/resource/" + free.AID() + "/work.do", http.StatusNotFound, "no prices"},
		{"a priced agent with no public address",
			"/x402/resource/" + unreachable.AID() + "/work.do", http.StatusConflict, "no public address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var body map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&body)
			if resp.StatusCode != tc.code {
				t.Errorf("code = %d, want %d (%v)", resp.StatusCode, tc.code, body)
			}
			if msg, _ := body["error"].(string); !strings.Contains(msg, tc.mentions) {
				t.Errorf("error = %q, want mention of %q", msg, tc.mentions)
			}
		})
	}
}

// The price is the seller's, not the hub's. A buyer who signs for less
// than the published price must not walk away with a full voucher.
func TestTheGatewayWillNotSellBelowThePublishedPrice(t *testing.T) {
	srv := newHub(t)
	seller, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	buyer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	if code, b := registerWithCard(t, srv, seller, "Worker", []string{"work.do"},
		sellableCard(t, seller, "Worker", []string{"work.do"},
			map[string]any{"work.do": 120}, "https://worker.example/x402/redeem")); code != 200 {
		t.Fatalf("register: %d %s", code, b)
	}
	register(t, srv, buyer, "Buyer", nil)
	fundAgent(t, srv, buyer.AID(), 500)

	cheap := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAIDOf(t, srv)),
		Amount: "1", Asset: payment.AssetCredit, PayTo: seller.AID(),
	}
	req, _ := http.NewRequest(http.MethodGet,
		srv.URL+"/x402/resource/"+seller.AID()+"/work.do", nil)
	req.Header.Set(payment.HeaderPaymentSignature, signedPayment(t, buyer, cheap, "gw-cheap"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("underpaying = %d, want 402", resp.StatusCode)
	}
	untouched := int64(500 + aghub.RegistrationGrant)
	if got := balanceOf(t, srv, buyer.AID()); got != untouched {
		t.Errorf("an underpayment moved credit: balance = %d, want %d", got, untouched)
	}

	// Paying the right amount to the wrong payee is the same class of
	// attempt: a voucher naming the seller, bought by paying somebody else.
	misaddressed := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAIDOf(t, srv)),
		Amount: "120", Asset: payment.AssetCredit, PayTo: buyer.AID(),
	}
	req, _ = http.NewRequest(http.MethodGet,
		srv.URL+"/x402/resource/"+seller.AID()+"/work.do", nil)
	req.Header.Set(payment.HeaderPaymentSignature, signedPayment(t, buyer, misaddressed, "gw-mis"))
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("paying the wrong payee = %d, want 400", resp2.StatusCode)
	}
}

// signedPayment builds the PAYMENT-SIGNATURE header value.
func signedPayment(t *testing.T, payer *identity.Controller, opt payment.PaymentOption,
	interactionID string) string {
	t.Helper()
	amount, err := payment.ParseAmount(opt.Amount)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a := &payment.Authorization{
		PayTo: opt.PayTo, Amount: amount, Network: opt.Network, Nonce: interactionID,
		IssuedAt: now.UnixMilli(), NotAfter: now.Add(5 * time.Minute).UnixMilli(),
		InteractionID: interactionID,
	}
	if err := a.Sign(payer); err != nil {
		t.Fatal(err)
	}
	raw, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	pp := payment.PaymentPayload{
		X402Version: payment.Version, Accepted: opt,
		Payload: map[string]any{"authorization": base64.StdEncoding.EncodeToString(raw)},
	}
	b, err := json.Marshal(pp)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
