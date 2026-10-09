package aghub

// SI-5 (hub-payment-privacy §6.1, the hub's half): a new hub admits only the
// AIDs its operator admits, and registration pays nothing (SI-52, M-PAY-21).

import (
	"net/http"
	"testing"
)

func TestANewHubIsClosed(t *testing.T) {
	g := newGateHub(t)
	mode, err := g.store.AdmissionMode()
	if err != nil || mode != AdmissionClosed {
		t.Fatalf("a new hub's admission mode is %q (%v), want closed", mode, err)
	}
	// Nothing was written to make it so: closed is what an unset mode
	// means, so no upgrade or restore can open a hub by losing a row.
	var n int
	if err := g.store.db.QueryRow(`SELECT COUNT(*) FROM hub_meta WHERE key=?`, metaAdmissionMode).Scan(&n); err != nil || n != 0 {
		t.Errorf("a new hub wrote its mode (%d rows, %v)", n, err)
	}
	c, _ := NewAgentForTest()
	for _, extra := range []map[string]any{nil, {"check_only": true}, g.pow(c.AID(), "good")} {
		code, out := g.register(c, c, extra)
		if code != http.StatusForbidden || out["reason"] != "admission_required" || out["aid"] != c.AID() {
			t.Errorf("a stranger at a new hub (%v): %d %s, want 403 admission_required naming its AID", extra, code, out["_raw"])
		}
	}
	if g.store.KnowsAgent(c.AID()) {
		t.Fatal("a new hub registered a stranger")
	}
	// No window is open and the list is empty.
	a, err := g.store.ListAdmissions()
	if err != nil || a.Window != nil || len(a.Admitted) != 0 || a.Mode != AdmissionClosed {
		t.Errorf("a new hub's admissions: %+v %v", a, err)
	}
}

// Registration pays no credit, by any route (PAY-A5, SI-52): the list
// (without a grant), a window and open registration all leave a balance of
// 0 and no ledger entry.
func TestRegistrationPaysNothing(t *testing.T) {
	for _, route := range []string{"listed", "window_open", "open"} {
		t.Run(route, func(t *testing.T) {
			g := newGateHub(t)
			c, _ := NewAgentForTest()
			g.gateState(route, c)
			code, out := g.register(c, c, g.pow(c.AID(), "good"))
			if code != http.StatusOK {
				t.Fatalf("register: %d %s", code, out["_raw"])
			}
			bal, err := g.store.Balance(c.AID())
			if err != nil || bal != 0 {
				t.Errorf("registration through %s paid %d credits (%v)", route, bal, err)
			}
			var entries int
			if err := g.store.db.QueryRow(`SELECT COUNT(*) FROM credit_entry WHERE aid=?`, c.AID()).Scan(&entries); err != nil || entries != 0 {
				t.Errorf("registration through %s left %d ledger entries", route, entries)
			}
			// And registering again pays nothing either.
			if code, out := g.register(c, c, nil); code != http.StatusOK {
				t.Fatalf("re-register: %d %s", code, out["_raw"])
			}
			if bal, _ := g.store.Balance(c.AID()); bal != 0 {
				t.Errorf("re-registration paid %d credits", bal)
			}
		})
	}
}
