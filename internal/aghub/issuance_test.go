package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// Every change to the supply must be on the signed chain.
//
// Before this, /x402/supply computed issued and redeemed from rows the
// hub writes, which establishes internal consistency and nothing about
// whether those rows were edited afterwards. Transfers do not have that
// problem — a settlement leaves a hub-signed receipt with the payer and a
// record on both parties' chains — but issuance has no counterparty, so
// nothing outside the hub attested to it.
func TestEverySupplyChangeIsOnTheSignedChain(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil) // registration grant: one issue
	if err := store.GrantCredit(agent.AID(), 500, "operator"); err != nil {
		t.Fatal(err)
	}

	entries, err := store.IssuanceSince(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("chain has %d entries, want 2 (registration grant + operator grant)", len(entries))
	}
	// Sequence and links, which is what makes a rewrite detectable.
	// An AEL begins at seq 0. A chain served from seq 1 cannot be
	// replayed by anyone, because every verifier requires the genesis
	// record first.
	if entries[0].Seq != 0 || entries[1].Seq != 1 {
		t.Errorf("sequence = %d,%d, want 0,1", entries[0].Seq, entries[1].Seq)
	}
	if entries[1].PrevID != entries[0].ID {
		t.Errorf("entry 2 does not link to entry 1: prev=%s id=%s",
			entries[1].PrevID, entries[0].ID)
	}
	if entries[1].Amount != 500 || entries[1].Kind != aghub.EvCreditIssued {
		t.Errorf("entry 2 = %+v", entries[1])
	}

	// Each record verifies against the hub's key history, so a reader
	// needs nothing from the hub except the hub's published KEL.
	if err := store.VerifyIssuanceChain(hubKELOf(t, srv.URL)); err != nil {
		t.Fatalf("the published chain does not verify: %v", err)
	}

	// A redemption retires credit and must appear as such.
	hubAID := hubAIDOf(t, srv)
	opt := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: "100", Asset: payment.AssetCredit, PayTo: hubAID,
	}
	code, b := post(t, srv.URL+"/x402/redeem", map[string]any{
		"x402Version": 2, "paymentPayload": json.RawMessage(mustPayload(t, agent, opt, "r-1")),
		"reference": "inv-1",
	})
	if code != 200 {
		t.Fatalf("redeem: %d %s", code, b)
	}
	entries, _ = store.IssuanceSince(0, 0)
	last := entries[len(entries)-1]
	if last.Kind != aghub.EvCreditRetired || last.Amount != 100 {
		t.Errorf("redemption is not on the chain as retired: %+v", last)
	}
}

// The chain and the balance table are two derivations of the same facts,
// and publishing both is what makes the comparison possible.
func TestSupplyPublishesBothDerivationsAndWhetherTheyAgree(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	if err := store.GrantCredit(agent.AID(), 500, "operator"); err != nil {
		t.Fatal(err)
	}

	s := supplyFull(t, srv)
	if !s.ChainAgrees {
		t.Errorf("chain and table disagree: chain issued=%d retired=%d, table issued=%d redeemed=%d",
			s.ChainIssued, s.ChainRetired, s.Issued, s.Redeemed)
	}
	if s.ChainIssued != s.Issued {
		t.Errorf("chain issued %d, table issued %d", s.ChainIssued, s.Issued)
	}
	if s.ChainHead == "" || s.ChainHeadSeq == 0 {
		t.Error("no chain head published — a witness has nothing to pin")
	}
}

// A reader who has the chain can compute the supply without believing
// the hub's own arithmetic.
func TestAReaderCanRecomputeTheSupplyFromTheChain(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	if err := store.GrantCredit(agent.AID(), 700, "operator"); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(srv.URL + "/x402/issuance")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Entries []aghub.IssuanceEntry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	// Verify and total from the signed records, not the JSON columns.
	// The columns are rendered by the hub; the record is what it signed.
	kel := hubKELOf(t, srv.URL)
	ledger := ael.NewLedger()
	var issued int64
	for _, e := range out.Entries {
		raw, derr := base64.StdEncoding.DecodeString(e.Record)
		if derr != nil {
			t.Fatal(derr)
		}
		var rec ael.EventRecord
		if uerr := coredet.Unmarshal(raw, &rec); uerr != nil {
			t.Fatal(uerr)
		}
		if aerr := ledger.Append(&rec, kel); aerr != nil {
			t.Fatalf("seq %d does not verify: %v", e.Seq, aerr)
		}
		if rec.EventType != aghub.EvCreditIssued {
			continue
		}
		p, ok := rec.Payload.(map[any]any)
		if !ok {
			// coredet decodes generic maps; accept either shape.
			if pm, ok2 := rec.Payload.(map[string]any); ok2 {
				issued += toInt64(pm["amount"])
				continue
			}
			t.Fatalf("payload shape %T", rec.Payload)
		}
		issued += toInt64(p["amount"])
	}
	want := int64(700 + aghub.RegistrationGrant)
	if issued != want {
		t.Errorf("recomputed issued = %d, want %d", issued, want)
	}
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	case int:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}

func supplyFull(t *testing.T, srv *httptest.Server) aghub.Supply {
	t.Helper()
	resp, err := http.Get(srv.URL + "/x402/supply")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Supply aghub.Supply `json:"supply"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Supply
}

// A hub that has been running has credit outstanding from before the
// chain existed, and there is no honest way to make the chain account for
// it retroactively.
//
// Backfilling one record per historical grant would have the hub signing
// a reconstruction of its own unaudited table and presenting it as a
// contemporaneous record. Leaving the chain empty would make the
// comparison useless for ever. The opening record states what is true and
// is reported separately, so a reader can subtract it and see what is
// actually attested.
func TestAnUpgradedHubOpensItsChainAtTheOutstandingBalance(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)

	// Simulate a hub whose credit predates the chain: clear the chain,
	// leaving the balances.
	if err := store.ClearIssuanceForTest(); err != nil {
		t.Fatal(err)
	}
	before := supplyFull(t, srv)
	if before.ChainAgrees {
		t.Fatal("setup: the chain should not agree yet")
	}

	if err := store.OpenBalance(before.Outstanding); err != nil {
		t.Fatal(err)
	}
	after := supplyFull(t, srv)
	if after.ChainOutstanding != after.Outstanding {
		t.Errorf("chain outstanding %d, table outstanding %d",
			after.ChainOutstanding, after.Outstanding)
	}
	if after.ChainOpening != before.Outstanding {
		t.Errorf("opening = %d, want %d", after.ChainOpening, before.Outstanding)
	}
	if !after.ChainAgrees {
		t.Errorf("the chain still disagrees after opening: %+v", after)
	}
	// Reported separately, never folded into issued. Everything in
	// ChainIssued has a signed ordered record a witness can pin; the
	// opening is the hub's own statement about its own past.
	if after.ChainIssued != 0 {
		t.Errorf("the opening was counted as issued: %d", after.ChainIssued)
	}

	// Idempotent: a restart must not add a second opening.
	if err := store.OpenBalance(before.Outstanding); err != nil {
		t.Fatal(err)
	}
	again := supplyFull(t, srv)
	if again.ChainOpening != after.ChainOpening {
		t.Errorf("a second call added another opening: %d → %d",
			after.ChainOpening, again.ChainOpening)
	}

	// And issuance after the opening is recorded normally, linked onto it.
	if err := store.GrantCredit(agent.AID(), 300, "after opening"); err != nil {
		t.Fatal(err)
	}
	final := supplyFull(t, srv)
	if final.ChainIssued != 300 || !final.ChainAgrees {
		t.Errorf("post-opening issuance = %d, agrees = %v", final.ChainIssued, final.ChainAgrees)
	}
	entries, _ := store.IssuanceSince(0, 0)
	if len(entries) != 2 || entries[1].PrevID != entries[0].ID {
		t.Errorf("the grant did not link onto the opening: %+v", entries)
	}
}

// A hub that had processed a redemption before the chain existed must
// still reconcile.
//
// The first version compared the historical issued/redeemed split, which
// a chain opening partway through a hub's life cannot know — it knows
// only the net that was outstanding when it opened. Live deployment
// reported false disagreement on exactly this shape.
func TestOpeningReconcilesOnAHubThatHadAlreadyRedeemed(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	if err := store.GrantCredit(agent.AID(), 1000, "operator"); err != nil {
		t.Fatal(err)
	}
	hubAID := hubAIDOf(t, srv)
	opt := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: "30", Asset: payment.AssetCredit, PayTo: hubAID,
	}
	if code, b := post(t, srv.URL+"/x402/redeem", map[string]any{
		"x402Version": 2, "paymentPayload": json.RawMessage(mustPayload(t, agent, opt, "pre-chain")),
		"reference": "pre-chain",
	}); code != 200 {
		t.Fatalf("redeem: %d %s", code, b)
	}

	// Now the chain is discarded: this is a hub whose issued/redeemed
	// history predates it, with the split unknowable from the chain.
	if err := store.ClearIssuanceForTest(); err != nil {
		t.Fatal(err)
	}
	before := supplyFull(t, srv)
	if before.Redeemed == 0 {
		t.Fatal("setup: expected a redemption before the chain")
	}
	if err := store.OpenBalance(before.Outstanding); err != nil {
		t.Fatal(err)
	}
	after := supplyFull(t, srv)
	if !after.ChainAgrees {
		t.Errorf("a hub with a pre-chain redemption did not reconcile: "+
			"opening=%d issued=%d retired=%d chain_outstanding=%d table_outstanding=%d",
			after.ChainOpening, after.ChainIssued, after.ChainRetired,
			after.ChainOutstanding, after.Outstanding)
	}
}

// A one-record chain must be distinguishable from no chain.
//
// chain_head_seq carried omitempty, so a chain holding exactly the
// opening record reported no sequence at all — and every reader deciding
// whether there is a head to pin would read that as "nothing yet".
func TestAOneRecordChainReportsItsSequence(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	if err := store.ClearIssuanceForTest(); err != nil {
		t.Fatal(err)
	}
	if err := store.OpenBalance(100); err != nil {
		t.Fatal(err)
	}
	body := rawSupply(t, srv)
	if !strings.Contains(body, `"chain_head_seq"`) {
		t.Errorf("chain_head_seq is absent from a chain that has a head: %s", body)
	}
	if !strings.Contains(body, `"chain_head"`) {
		t.Errorf("chain_head is absent: %s", body)
	}
}

func rawSupply(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	resp, err := http.Get(srv.URL + "/x402/supply")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b := make([]byte, 0, 2048)
	buf := make([]byte, 1024)
	for {
		n, rerr := resp.Body.Read(buf)
		b = append(b, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	return string(b)
}
