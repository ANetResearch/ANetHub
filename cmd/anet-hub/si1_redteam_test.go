//go:build !no_federation

package main

// Red-team PoC (lens si1, A2A-DESIGN §1 SI-1, §2 X4, §21 item 9).
//
// A cross-hub task payment goes on both hubs' public issuance chains
// (GET /x402/issuance, unauthenticated): the ledger hub records the payer,
// the amount and "cross-hub settlement <id> to <payee>", the payee's hub
// records the payee and the amount. §21 item 9 admits amounts, times and
// AIDs are public. What it does not admit is that, together with the
// payee's signed per-skill prices (anet-pricing/v1 on its A2A card, also
// public), the amount names the capability that was bought — the x402
// `resource` ("anet:capability/<id>") SI-1 keeps off the hub and X4 strips
// from the settlement. Here that inference is open to anyone who can read
// the two chains, not only the hub.
//
// The test passes when the attack succeeds.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestRedteamSI1PublicIssuanceChainNamesTheCapabilityBought(t *testing.T) {
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
		var out struct {
			Entries []entry `json:"entries"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
		t.Fatalf("attack failed: no cross-hub settlement on the ledger hub's public chain")
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
	if payer != r.payer.AID() || len(hits) != 1 || hits[0] != secretCap {
		t.Fatalf("attack failed: payer %s amount %s skills %v", payer, amount, hits)
	}
	t.Logf("public chain: %s paid %s %s credits (payee's chain shows the clearing: %v) => resource anet:capability/%s",
		payer, payee, amount, sawClearing, hits[0])
}
