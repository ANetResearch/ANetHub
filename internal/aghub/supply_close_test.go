package aghub_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// PAY-S3 step 3 (M-PAY-6): the close checks the tree it built against the
// ledger before anything is signed. When the balances do not add up to
// issued − redeemed, or the hub's row is not the negative of that, or a
// balance is negative, nothing is published — no record, no leaves, the
// totals and the count left as they were — and the hub logs an ERROR. Once
// the ledger adds up again the epoch closes.
func TestTheCloseRefusesALedgerThatDoesNotAddUp(t *testing.T) {
	for _, c := range []struct {
		name   string
		break_ func(t *testing.T, store *aghub.Store, hubAID, aid string)
	}{
		{"a balance raised outside the ledger", func(t *testing.T, store *aghub.Store, _, aid string) {
			if err := store.MoveBalanceWithoutEntryForTest(aid, 5); err != nil {
				t.Fatal(err)
			}
		}},
		{"a balance lowered outside the ledger", func(t *testing.T, store *aghub.Store, _, aid string) {
			if err := store.MoveBalanceWithoutEntryForTest(aid, -5); err != nil {
				t.Fatal(err)
			}
		}},
		{"the hub's row moved alone", func(t *testing.T, store *aghub.Store, hubAID, _ string) {
			if err := store.MoveBalanceWithoutEntryForTest(hubAID, -5); err != nil {
				t.Fatal(err)
			}
		}},
		{"the issued total edited", func(t *testing.T, store *aghub.Store, _, _ string) {
			if _, err := store.DBForTest().Exec(`UPDATE supply_totals SET issued = issued + 5`); err != nil {
				t.Fatal(err)
			}
		}},
		{"a negative balance", func(t *testing.T, store *aghub.Store, hubAID, aid string) {
			// Moved from one account to another outside the ledger: the sums
			// still agree, but an account cannot owe the hub.
			if err := store.MoveBalanceWithoutEntryForTest(aid, -(testRegistrationFunds + 1)); err != nil {
				t.Fatal(err)
			}
			if err := store.MoveBalanceWithoutEntryForTest("did:anet:somebody", testRegistrationFunds+1); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, store := newHubWithStore(t)
			hubAID := hubAIDOf(t, srv)
			a, b := twoAgents(t)
			register(t, srv, a, "A", nil)
			register(t, srv, b, "B", nil)
			c.break_(t, store, hubAID, a.AID())
			totals := func() string {
				var issued, redeemed, events, last int64
				if err := store.DBForTest().QueryRow(`SELECT issued, redeemed, events_since_publish, last_to_day
				    FROM supply_totals`).Scan(&issued, &redeemed, &events, &last); err != nil {
					t.Fatal(err)
				}
				return fmt.Sprintf("%d/%d/%d/%d", issued, redeemed, events, last)
			}
			before := totals()
			logs := captureLog(t)
			e, err := store.PublishDueAtForTest(time.Now().Add(8 * 24 * time.Hour))
			if !errors.Is(err, aghub.ErrSupplyMismatch) || e != nil {
				t.Fatalf("closing a ledger that does not add up: %+v, %v; want ErrSupplyMismatch", e, err)
			}
			for _, q := range []string{`SELECT COUNT(*) FROM supply_chain`, `SELECT COUNT(*) FROM liab_leaf`,
				`SELECT COUNT(*) FROM liab_meta`} {
				if n := countRows(t, store, q); n != 0 {
					t.Errorf("%s = %d after a refused close", q, n)
				}
			}
			if after := totals(); after != before {
				t.Errorf("the totals moved: %s -> %s", before, after)
			}
			if !strings.Contains(logs.String(), "ERROR") {
				t.Errorf("no ERROR was logged: %q", logs.String())
			}
		})
	}
	// The same hub, with the ledger adding up, closes.
	srv, store := newHubWithStore(t)
	a, _ := twoAgents(t)
	register(t, srv, a, "A", nil)
	if e := publishEpoch(t, store); e.Outstanding != testRegistrationFunds {
		t.Errorf("outstanding %d", e.Outstanding)
	}
}
