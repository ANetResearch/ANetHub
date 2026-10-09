package aghub_test

import (
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// A correcting entry closes the gap once, is visible, and cannot move
// money.
//
// Accounts carrying settlements from before settlement wrote ledger
// entries have balances that moved and left nothing behind. `anet
// reconcile` then reports a discrepancy on every run — and a check that
// always says something is wrong is a check people stop reading.
func TestALedgerCorrectionIsDerivedAndVisible(t *testing.T) {
	srv, store := newHubWithStore(t)
	a, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, a, "Old account", []string{"work.do"})

	// A balance move with no entry behind it: the shape the old
	// settlement path left.
	if err := store.MoveBalanceWithoutEntryForTest(a.AID(), -30); err != nil {
		t.Fatal(err)
	}
	bal, _ := store.Balance(a.AID())
	_, sum, err := store.LedgerTotals(a.AID())
	if err != nil {
		t.Fatal(err)
	}
	if bal == sum {
		t.Fatal("the fixture did not create a gap")
	}

	delta, err := store.RepairLedger(a.AID())
	if err != nil {
		t.Fatal(err)
	}
	if delta != bal-sum {
		t.Errorf("wrote %d, want the gap %d", delta, bal-sum)
	}
	// The balance is untouched: this writes history, it does not move
	// money, so an operator can run it and cannot aim it.
	if got, _ := store.Balance(a.AID()); got != bal {
		t.Errorf("the balance changed from %d to %d", bal, got)
	}
	_, sum2, _ := store.LedgerTotals(a.AID())
	if sum2 != bal {
		t.Errorf("entries sum to %d, balance is %d — the gap is still there", sum2, bal)
	}
	// And running it again does nothing, because there is no gap left.
	again, err := store.RepairLedger(a.AID())
	if err != nil || again != 0 {
		t.Errorf("a second run wrote %d (err %v); it must be a no-op", again, err)
	}

	// The correction is in the ledger, named for what it is.
	code, body := ownerGet(t, srv, a, relayauth.ActionLedger, "/agents/"+a.AID()+"/ledger?limit=500")
	if code != 200 {
		t.Fatalf("ledger = %d", code)
	}
	if !strings.Contains(string(body), "ledger correction") {
		t.Error("the correction is not visible in the ledger")
	}
}
