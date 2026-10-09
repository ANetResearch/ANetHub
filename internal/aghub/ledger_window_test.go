package aghub_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// PAY-L6 (core §2.12.2): GET /agents/{aid}/ledger and
// /agents/{aid}/redemptions serve the ledger window only — the last 14
// days, whether or not the janitor has run yet — and say so: window_days is
// 14 and oldest_seq the seq of the earliest row in the window (0 when it is
// empty); total and sum cover the window, whatever the page.
func TestTheLedgerReadsServeTheWindow(t *testing.T) {
	srv, store := newHubWithStore(t)
	owner, _ := twoAgents(t)
	register(t, srv, owner, "Owner", nil)
	hubAID := hubAIDOf(t, srv)
	start := time.Now().Truncate(time.Millisecond)
	now := start
	store.SetClockForTest(func() time.Time { return now })
	base := "/agents/" + owner.AID()

	ledger := func() aghub.LedgerResponse {
		t.Helper()
		code, body := ownerGet(t, srv, owner, relayauth.ActionLedger, base+"/ledger?limit=2")
		var out aghub.LedgerResponse
		if code != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("ledger: %d %s", code, body)
		}
		return out
	}
	redemptions := func() aghub.RedemptionsResponse {
		t.Helper()
		code, body := ownerGet(t, srv, owner, relayauth.ActionRedemptions, base+"/redemptions?limit=1")
		var out aghub.RedemptionsResponse
		if code != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("redemptions: %d %s", code, body)
		}
		return out
	}
	// Day 0: a grant and a redemption. Day 10: a grant and a redemption.
	grant := func(n int64) {
		if err := store.GrantCredit(owner.AID(), n, "operator"); err != nil {
			t.Fatal(err)
		}
	}
	redeem := func(n uint64, ref string) {
		t.Helper()
		a := &payment.Authorization{PayTo: hubAID, Amount: n, Network: payment.CreditNetwork(hubAID), Nonce: ref,
			IssuedAt: now.Add(-time.Second).UnixMilli(), NotAfter: now.Add(5 * time.Minute).UnixMilli()}
		if err := a.Sign(owner); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Redeem(hubAID, creditPayload(t, a, hubAID, payment.CreditNetwork(hubAID)), ref); err != nil {
			t.Fatalf("redeem %d: %v", n, err)
		}
	}
	grant(100)
	redeem(7, "early")
	first := ledger()
	if first.WindowDays != 14 || first.OldestSeq == 0 || first.Total < 3 {
		t.Fatalf("day 0: %+v", first)
	}
	now = start.Add(10 * 24 * time.Hour)
	grant(50)
	redeem(3, "late")
	// Day 15: only day 10's rows are served, before the janitor runs.
	now = start.Add(15 * 24 * time.Hour)
	l := ledger()
	var sum int64
	for _, e := range l.Entries {
		sum += e.Delta
	}
	if l.Total != 2 || l.Sum != 47 || l.Returned != 2 || len(l.Entries) != 2 || sum != 47 ||
		l.OldestSeq <= first.OldestSeq || l.Entries[0].Seq != l.OldestSeq || l.Truncated {
		t.Errorf("day 15 ledger: %+v, want day 10's two entries summing to 47 (oldest_seq after %d)", l, first.OldestSeq)
	}
	for _, e := range l.Entries {
		if at, err := time.Parse(time.RFC3339Nano, e.At); err != nil || at.Before(start.Add(time.Hour)) {
			t.Errorf("an entry from before the window: %+v (%v)", e, err)
		}
	}
	r := redemptions()
	if r.WindowDays != 14 || r.Total != 1 || r.Sum != 3 || len(r.Redemptions) != 1 ||
		r.Redemptions[0].Reference != "late" || r.OldestSeq != r.Redemptions[0].Seq || r.OldestSeq == 0 {
		t.Errorf("day 15 redemptions: %+v", r)
	}
	// Day 25: the window is empty.
	now = start.Add(25 * 24 * time.Hour)
	if l := ledger(); l.Total != 0 || l.Sum != 0 || l.OldestSeq != 0 || len(l.Entries) != 0 || l.WindowDays != 14 {
		t.Errorf("day 25 ledger: %+v", l)
	}
	if r := redemptions(); r.Total != 0 || r.OldestSeq != 0 || len(r.Redemptions) != 0 {
		t.Errorf("day 25 redemptions: %+v", r)
	}
	// A page smaller than the window says so.
	for i := 0; i < 3; i++ {
		grant(1)
	}
	if l := ledger(); l.Total != 3 || l.Returned != 2 || !l.Truncated || l.Note == "" || l.Sum != 3 {
		t.Errorf("a page of the window: %+v", l)
	}
	if bal, _ := store.Balance(owner.AID()); bal != int64(testRegistrationFunds)+100-7+50-3+3 {
		t.Errorf("the balance is %d; the window changes what is listed, never the balance", bal)
	}
}
