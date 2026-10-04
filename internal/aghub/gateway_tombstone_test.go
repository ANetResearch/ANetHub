package aghub_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// The hub's x402 resource gateway is gone in 0.3.0:
// GET /x402/resource/{aid}/{capability} is a 410 tombstone. It
// answers gateway_removed whatever agent, capability or payment it is
// asked about, a payment sent there moves no credit and buys nothing, and
// the one sentence it answers with tells a plain HTTP x402 client where to
// go instead (anet's local A2A interface, where anet signs the payment).
func TestTheGatewayIsATombstone(t *testing.T) {
	srv, store := newHubWithStore(t)
	seller, buyer := twoAgents(t)
	register(t, srv, seller, "Worker", []string{"work.do"})
	register(t, srv, buyer, "Buyer", nil)
	hub := hubAIDOf(t, srv)
	before := balances(t, srv, seller.AID(), buyer.AID(), hub)

	// What a buyer sent the gateway: a signed authorization for the
	// seller, in the PAYMENT-SIGNATURE header.
	now := time.Now().UnixMilli()
	auth := authFor(t, buyer, seller.AID(), 10, payment.CreditNetwork(hub), "", "tombstone-1",
		now, now+int64(5*time.Minute/time.Millisecond))
	raw, err := json.Marshal(creditPayload(t, auth, seller.AID(), payment.CreditNetwork(hub)))
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(raw)

	want, err := wire3.Body(wire3.Refusal{Reason: wire3.ReasonGatewayRemoved})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, path, payment string
		wire                bool
	}{
		{"a capability of an agent registered here", "/x402/resource/" + seller.AID() + "/work.do", "", true},
		{"the same with a payment", "/x402/resource/" + seller.AID() + "/work.do", signature, true},
		{"a plain HTTP x402 client, which sends no wire header", "/x402/resource/" + seller.AID() + "/work.do", signature, false},
		{"an agent this hub does not host", "/x402/resource/did:anet:nobody/work.do", "", true},
		{"a capability id with more segments", "/x402/resource/" + seller.AID() + "/work/do", "", true},
		{"no capability", "/x402/resource/" + seller.AID(), "", true},
	} {
		req, err := http.NewRequest(http.MethodGet, srv.URL+c.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.wire {
			req.Header.Set(wire3.Header, wireHeader)
		}
		if c.payment != "" {
			req.Header.Set(payment.HeaderPaymentSignature, c.payment)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusGone || !bytes.Equal(body, want) {
			t.Errorf("%s: %d %s\nwant 410 %s", c.name, resp.StatusCode, body, want)
		}
		if resp.Header.Get(wire3.Header) != wireHeader {
			t.Errorf("%s: %s = %q", c.name, wire3.Header, resp.Header.Get(wire3.Header))
		}
		// Neither half of x402's exchange: no quote, no settlement.
		for _, h := range []string{payment.HeaderPaymentRequired, payment.HeaderPaymentResponse} {
			if v := resp.Header.Get(h); v != "" {
				t.Errorf("%s: the tombstone answers with %s: %s", c.name, h, v)
			}
		}
	}

	if after := balances(t, srv, seller.AID(), buyer.AID(), hub); !sameBalances(before, after) {
		t.Errorf("a payment sent to the tombstone moved credit: %v -> %v", before, after)
	}
	db := store.DBForTest()
	var settled int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credit_settled`).Scan(&settled); err != nil {
		t.Fatal(err)
	}
	if settled != 0 {
		t.Errorf("the tombstone settled %d authorization(s)", settled)
	}
	// Nothing is kept for a gateway that no longer sells: no voucher table.
	var tables int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%voucher%'`).
		Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Errorf("hub.db still has %d voucher table(s)", tables)
	}
}
