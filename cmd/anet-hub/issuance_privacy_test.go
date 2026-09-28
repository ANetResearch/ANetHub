//go:build !no_federation

package main

// What the public issuance chain says about a cross-hub task payment
// (A2A-DESIGN §1 SI-1, §2 X4, §21 item 9) [redteam:F1].
//
// A cross-hub payment goes on both hubs' public issuance chains
// (GET /x402/issuance, unauthenticated): the ledger hub records the payer,
// the amount and "cross-hub settlement <id> to <payee>", the payee's hub
// records the payee and the amount. §21 item 9 states this, and states
// what the red team's PoC (lens si1) showed follows from it: where the
// payee publishes a different signed price per skill (anet-pricing/v1 on
// its card), payee and amount name the skill bought — the x402 resource
// SI-1 keeps off the hub — for anyone who reads the chains. It is a stated
// limitation, not a leak of the task: the daemon's
// payments.publish_prices=false keeps the prices off the cards (ANet
// module/x402/price_inference_test.go covers that side).
//
// So this test pins both halves: the inference works from public data
// alone, exactly as §21 item 9 says, and nothing of the task itself — the
// binding the authorization carries, the skill's id — is on either chain.
// If the chain stops showing amounts, item 9 and this test change together.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestThePublicIssuanceChainShowsAmountsAndAIDsAndNothingOfTheTask(t *testing.T) {
	r := newCrossHubRig(t)

	// The payee's published prices (module/x402/card.go puts these in the
	// signed anet-pricing/v1 extension of the card the hub registry serves).
	prices := map[string]string{"text.summarize": "3", "legal.contract.review": "11"}

	// Inside the sealed task (not visible to anyone but the two parties):
	// the payer buys legal.contract.review from the payee.
	const secretCap = "legal.contract.review"
	p := r.pay(t, r.payee.AID(), 11, "bind-opaque", "n-1")
	if out := settleAt(t, r.aURL, p, r.requires(r.payee.AID(), 11)); !out.Success {
		t.Fatalf("cross-hub settlement: %+v", out)
	}

	// ---- a stranger, with no credentials ----
	type entry struct {
		Kind   string `json:"kind"`
		AID    string `json:"aid"`
		Amount int64  `json:"amount"`
		Reason string `json:"reason"`
	}
	read := func(base string) []entry {
		t.Helper()
		resp, err := http.Get(base + "/x402/issuance?from=0")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s/x402/issuance: %s", base, resp.Status)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		// Nothing of the task: not the binding the authorization carries
		// (pay_bind in production, one-way), not the skill (SI-1).
		for _, secret := range []string{"bind-opaque", secretCap, "anet:capability/"} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("GET %s/x402/issuance shows %q", base, secret)
			}
		}
		var out struct {
			Entries []entry `json:"entries"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out.Entries
	}
	var payer, payee, amount string
	for _, e := range read(r.b.url) {
		if strings.HasPrefix(e.Reason, "cross-hub settlement ") && strings.Contains(e.Reason, " to "+r.payee.AID()) {
			payer, payee, amount = e.AID, r.payee.AID(), fmt.Sprint(e.Amount)
		}
	}
	if payer == "" {
		t.Fatalf("no cross-hub settlement on the ledger hub's public chain; §21 item 9 says there is one")
	}
	sawClearing := false
	for _, e := range read(r.aURL) {
		if e.AID == payee && fmt.Sprint(e.Amount) == amount && strings.HasPrefix(e.Reason, "cleared from ") {
			sawClearing = true
		}
	}
	var hits []string
	for skill, a := range prices {
		if a == amount {
			hits = append(hits, skill)
		}
	}
	// The inference §21 item 9 states: payer, payee and amount from the
	// chain, and the payee's published prices, name the skill.
	if payer != r.payer.AID() || len(hits) != 1 || hits[0] != secretCap {
		t.Fatalf("payer %s amount %s skills %v: the chain no longer shows what §21 item 9 says it shows",
			payer, amount, hits)
	}
	if !sawClearing {
		t.Errorf("the payee's hub's chain does not show the clearing of %s credits to %s", amount, payee)
	}
}
