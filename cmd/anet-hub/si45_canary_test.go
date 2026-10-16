//go:build !no_federation

package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// SI-45, the canary of hub-payment-privacy §7.4 (J-PAY-7 in unit form): a
// cross-hub payment of a characteristic amount, 7919, with a characteristic
// binding, and a redemption of the same amount against a characteristic
// reference. Afterwards nothing either hub serves without authentication —
// the published epochs and their records, the epoch chain and its head, the
// witnesses, the registry and the stats — carries the amount, the binding,
// the reference or the transaction id. What is public about the ledger is a
// total per epoch.
func TestSI45PublicSurfacesNameNoPayment(t *testing.T) {
	const amount = 7919
	const bind, ref = "canary-bind-3f61", "canary-ref-5b1e"
	r := newCrossHubRig(t)
	// Totals that are not the amount itself.
	if err := r.b.store.Credit(r.payer.AID(), 9000, "test grant"); err != nil {
		t.Fatal(err)
	}
	if err := r.a.Credit(r.other.AID(), 500, "test grant"); err != nil {
		t.Fatal(err)
	}
	out := settleAt(t, r.aURL, r.pay(t, r.payee.AID(), amount, bind, "n-canary"), r.requires(r.payee.AID(), amount))
	if !out.Success {
		t.Fatalf("the cross-hub payment: %+v", out)
	}
	// The payee redeems what it was paid, on its own hub.
	now := time.Now().UnixMilli()
	a := &payment.Authorization{PayTo: r.aID.AID, Amount: amount, Network: payment.CreditNetwork(r.aID.AID),
		Nonce: "n-redeem", IssuedAt: now - 1000, NotAfter: now + 60_000}
	if err := a.Sign(r.payee); err != nil {
		t.Fatal(err)
	}
	raw, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := &payment.PaymentPayload{X402Version: payment.Version,
		Accepted: payment.PaymentOption{Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(r.aID.AID),
			Amount: payment.Amount(amount), Asset: payment.AssetCredit, PayTo: r.aID.AID},
		Payload: map[string]any{"authorization": base64.StdEncoding.EncodeToString(raw)}}
	red, err := r.a.Redeem(r.aID.AID, p, ref)
	if err != nil {
		t.Fatalf("the redemption: %v", err)
	}
	// Both hubs publish the epoch that covers it.
	publishNow(t, r.aDir, r.a)
	publishNow(t, r.b.dir, r.b.store)
	secrets := []string{bind, ref, out.Transaction, red.AuthID}
	for _, base := range []string{r.aURL, r.b.url} {
		for _, path := range []string{"/x402/supply", "/x402/issuance?from=0", "/x402/issuance/head",
			"/x402/witnesses", "/agents", "/a2a/v1/agents", "/stats", "/graph", "/x402/supported",
			"/agents/" + r.payee.AID(), "/agents/" + r.payer.AID()} {
			resp, err := http.Get(base + path)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			for _, s := range secrets {
				if strings.Contains(string(body), s) {
					t.Errorf("GET %s shows %q", path, s)
				}
			}
			if hasNumber(body, amount) {
				t.Errorf("GET %s shows the amount %d: %s", path, amount, body)
			}
			// The records, decoded, state totals only.
			if strings.HasPrefix(path, "/x402/issuance?") {
				var iss aghub.IssuanceResponse
				if err := json.Unmarshal(body, &iss); err != nil {
					t.Fatal(err)
				}
				if len(iss.Entries) == 0 {
					t.Errorf("%s published no epoch", base)
				}
				for _, e := range iss.Entries {
					b, err := base64.RawURLEncoding.Strict().DecodeString(e.Record)
					if err != nil {
						t.Fatal(err)
					}
					rec, err := ael.UnmarshalEventRecord(b)
					if err != nil {
						t.Fatalf("an entry of %s is not an epoch record: %v", path, err)
					}
					ep, err := ael.ParseSupplyEpoch(rec)
					if err != nil {
						t.Errorf("an entry of %s: %v", path, err)
						continue
					}
					if ep.Outstanding == amount {
						t.Errorf("an epoch states the amount as its total")
					}
					for _, s := range append(secrets, r.payer.AID(), r.payee.AID()) {
						if strings.Contains(string(b), s) {
							t.Errorf("an epoch record carries %q", s)
						}
					}
				}
			}
		}
	}
}

// hasNumber reports whether the JSON in b has the number n, or a string
// that is n, anywhere.
func hasNumber(b []byte, n int) bool {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return strings.Contains(string(b), strconv.Itoa(n))
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case float64:
			return x == float64(n)
		case string:
			return x == strconv.Itoa(n)
		case []any:
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		case map[string]any:
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}
