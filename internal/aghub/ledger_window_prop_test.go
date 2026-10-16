package aghub

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"
)

// P-PAY-7 (hub-payment-privacy §7.2; SI-47): under random settlements,
// forwarded settlements, redemptions, peer receipts and supply epochs, with
// time moving forward at random, every round of the janitor leaves no row
// of the ledger window past its time, the settlement guard holds hashes
// only, the largest ledger seq ever written stays where it was, and the
// supply invariant holds (P-PAY-3).
//
// The times are also checked against what the rig itself signed rather
// than what the hub stored: a settled row is kept exactly until 7 days past
// its authorization's NotAfter, and a peer's clearing exactly until 8 days
// past its receipt's SettleAt. And deleting them reopens nothing (PAY-L3):
// every authorization that ever settled is sent again after every round,
// through the door it settled by, and is answered with its original
// settlement or refused as expired, never settled a second time.

// windowRig is a hub on a clock the test moves, with a few accounts and a
// peer hub.
type windowRig struct {
	t      *testing.T
	s      *Store
	hubAID string
	now    time.Time
	agents []*identity.Controller
	peer   *identity.Controller
	n      int
	hw     int64 // the largest credit_entry seq seen
	// done counts what succeeded, by kind, so the property is known to
	// have been tested on rows of every table.
	done map[string]int
	// paid is every authorization that settled, to send again; cleared is
	// the SettleAt of every peer receipt cleared, by its authorization id.
	paid    []*windowPaid
	cleared map[string]int64
}

// windowPaid is an authorization that settled, and the door it settled by.
type windowPaid struct {
	kind     string // "settled", "forwarded" or "redeemed"
	p        *payment.PaymentPayload
	req      *payment.PaymentRequirements
	id       string
	notAfter int64
	// expired: a repeat was refused as expired, which time does not undo.
	expired bool
}

func newWindowRig(t *testing.T) *windowRig {
	t.Helper()
	s, hub, payer, payee := settlementStore(t)
	r := &windowRig{t: t, s: s, hubAID: hub.AID(), now: time.Now().Truncate(time.Millisecond), done: map[string]int{},
		cleared: map[string]int64{}}
	s.clock = func() time.Time { return r.now }
	r.agents = []*identity.Controller{payer, payee}
	for i := 0; i < 2; i++ {
		c, _ := identitytest.Hub()
		kel, _ := identity.MarshalKEL(c.KEL())
		if err := s.PutAgent(c.AID(), "agent", nil, kel); err != nil {
			t.Fatal(err)
		}
		r.agents = append(r.agents, c)
	}
	for _, c := range r.agents {
		if err := s.GrantCredit(c.AID(), 10_000, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	r.peer, _ = identitytest.Hub()
	return r
}

func (r *windowRig) next() string { r.n++; return strconv.Itoa(r.n) }

// pay settles amt from one agent to payTo: here, for the peer (forPeer), or
// as a redemption (payTo the hub), with or without a task binding, under an
// authorization valid for window.
func (r *windowRig) pay(rng *rand.Rand, payTo string, forPeer bool) {
	payer := r.agents[rng.IntN(len(r.agents))]
	bind := ""
	if rng.IntN(2) == 0 {
		bind = "bind-" + strconv.Itoa(rng.IntN(6)) // reused, so the guard refuses some
	}
	window := time.Duration(1+rng.Int64N(int64(payment.MaxAuthWindow/time.Minute))) * time.Minute
	a := authAt(r.t, payer, payTo, uint64(1+rng.IntN(30)), payment.CreditNetwork(r.hubAID), bind,
		"w-"+r.next(), r.now.Add(-time.Second), window)
	p, req := payloadFor(r.t, a), requirementsOf(a)
	var ok bool
	kind := "settled"
	switch {
	case payTo == r.hubAID:
		_, err := r.s.Redeem(r.hubAID, p, "ref-"+r.next())
		ok, kind = err == nil, "redeemed"
	case forPeer:
		out := r.s.SettleForPeer(r.hubAID, r.peer.AID(), p, req)
		ok, kind = out.Success, "forwarded"
	default:
		out := r.s.SettleWithRequirements(r.hubAID, p, req)
		ok = out.Success
		if out.ErrorReason == payment.ReasonDuplicateBinding {
			r.done["guarded"]++
		}
	}
	if ok {
		r.done[kind]++
		if bind != "" {
			r.done["bound"]++
		}
		id, err := a.ID()
		if err != nil {
			r.t.Fatal(err)
		}
		r.paid = append(r.paid, &windowPaid{kind: kind, p: p, req: req, id: id, notAfter: a.NotAfter})
	}
}

// replay sends every authorization that settled again, by the door it
// settled by: the answer is its original settlement (a repeat), or a
// refusal as expired once the settled row may be gone, and the ledger does
// not move either way.
func (r *windowRig) replay(step string) {
	t := r.t
	t.Helper()
	before := ledgerRows(t, r.s)
	for _, x := range r.paid {
		if x.expired {
			continue
		}
		var ok bool
		var reason string
		switch x.kind {
		case "redeemed":
			red, err := r.s.Redeem(r.hubAID, x.p, "ref-again")
			ok = err == nil && red.AuthID == x.id
			if rf, isRefusal := err.(*Refusal); isRefusal {
				reason = rf.Reason
			} else if err != nil {
				reason = err.Error()
			}
		case "forwarded":
			out := r.s.SettleForPeer(r.hubAID, r.peer.AID(), x.p, x.req)
			ok, reason = out.Success && out.Transaction == x.id && out.Extensions[payment.ExtReplayed] == true, out.ErrorReason
		default:
			out := r.s.SettleWithRequirements(r.hubAID, x.p, x.req)
			ok, reason = out.Success && out.Transaction == x.id && out.Extensions[payment.ExtReplayed] == true, out.ErrorReason
		}
		switch {
		case ok:
		case reason == payment.ReasonExpiredPayment:
			x.expired = true
		default:
			t.Fatalf("%s: %s %s sent again: neither its settlement nor expired (%q)", step, x.kind, x.id, reason)
		}
	}
	if after := ledgerRows(t, r.s); after != before {
		t.Fatalf("%s: sending settled authorizations again moved the ledger:\n%s\n%s", step, before, after)
	}
}

// clear credits an agent with the peer's receipt, settled up to 6 days ago.
func (r *windowRig) clear(rng *rand.Rand) {
	at := r.now.Add(-time.Duration(rng.Int64N(int64(6 * 24 * time.Hour))))
	rec := &payment.Receipt{AuthID: "peer-" + r.next(), Payer: "did:anet:their-user",
		PayTo: r.agents[rng.IntN(len(r.agents))].AID(), Amount: uint64(1 + rng.IntN(30)),
		Network: payment.CreditNetwork(r.peer.AID()), SettleAt: at.UnixMilli()}
	if err := rec.Sign(r.peer); err != nil {
		r.t.Fatal(err)
	}
	if err := r.s.ClearFromPeer(r.peer.AID(), r.peer.KEL(), rec); err != nil {
		r.t.Fatalf("clearing a receipt %v old: %v", r.now.Sub(at), err)
	}
	r.cleared[rec.AuthID] = rec.SettleAt
	r.done["cleared"]++
}

// check runs the janitor at the rig's time and checks what is left.
func (r *windowRig) check(step string) {
	t := r.t
	t.Helper()
	if _, err := r.s.PruneLedger(); err != nil {
		t.Fatalf("%s: %v", step, err)
	}
	now := r.now
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := r.s.db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %s: %v", step, q, err)
		}
		return n
	}
	for _, c := range []struct {
		what string
		q    string
		arg  any
	}{
		{"credit_entry older than 14 days", `SELECT COUNT(*) FROM credit_entry WHERE at < ?`, ledgerStamp(now.Add(-14 * 24 * time.Hour))},
		{"credit_redemption older than 14 days", `SELECT COUNT(*) FROM credit_redemption WHERE at < ?`, ledgerStamp(now.Add(-14 * 24 * time.Hour))},
		{"credit_settled 7 days past NotAfter", `SELECT COUNT(*) FROM credit_settled WHERE not_after <= ?`, now.Add(-7 * 24 * time.Hour).UnixMilli()},
		{"settle_guard past its until", `SELECT COUNT(*) FROM settle_guard WHERE until <= ?`, now.UnixMilli()},
		{"settle_guard longer than 30 days", `SELECT COUNT(*) FROM settle_guard WHERE until > ?`, now.Add(30 * 24 * time.Hour).UnixMilli()},
		{"credit_cleared 8 days past SettleAt", `SELECT COUNT(*) FROM credit_cleared WHERE settle_at <= ?`, now.Add(-8 * 24 * time.Hour).UnixMilli()},
		{"a guard that is not a hash", `SELECT COUNT(*) FROM settle_guard WHERE length(h) <> 32 OR typeof(h) <> 'blob' OR ? = 0`, 1},
	} {
		if n := count(c.q, c.arg); n != 0 {
			t.Fatalf("%s: %d rows of %s remain", step, n, c.what)
		}
	}
	// The leaves of every epoch published 14 days ago or more are gone.
	rows, err := r.s.db.Query(`SELECT c.record FROM liab_meta m JOIN supply_chain c ON c.to_day = m.to_day`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var raw []byte
		_ = rows.Scan(&raw)
		if pub, err := publishedAt(raw); err != nil || now.UnixMilli()-pub >= proofKeptFor {
			rows.Close()
			t.Fatalf("%s: the leaves of an epoch published %v ago remain (%v)", step, time.Duration(now.UnixMilli()-pub)*time.Millisecond, err)
		}
	}
	rows.Close()
	if n := count(`SELECT COUNT(*) FROM liab_leaf WHERE to_day NOT IN (SELECT to_day FROM liab_meta)`); n != 0 {
		t.Fatalf("%s: %d leaves of no kept epoch", step, n)
	}
	// No payer in the guard, whatever it holds.
	guards, err := r.s.db.Query(`SELECT h FROM settle_guard`)
	if err != nil {
		t.Fatal(err)
	}
	for guards.Next() {
		var h []byte
		_ = guards.Scan(&h)
		for _, c := range r.agents {
			if bytes.Contains(h, []byte(c.AID())) {
				guards.Close()
				t.Fatalf("%s: a guard holds the payer %s", step, c.AID())
			}
		}
	}
	guards.Close()
	// The high-water mark of the ledger does not fall with its rows.
	var hw int64
	if err := r.s.db.QueryRow(`SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'credit_entry'), 0)`).Scan(&hw); err != nil {
		t.Fatal(err)
	}
	if hw < r.hw {
		t.Fatalf("%s: the largest ledger seq fell from %d to %d", step, r.hw, hw)
	}
	r.hw = hw
	if sup, err := r.s.Supply(r.hubAID); err != nil || !sup.Consistent() {
		t.Fatalf("%s: the supply does not add up: %+v (%v)", step, sup, err)
	}
	// Each settled row and each clearing is there exactly while its time,
	// counted from what was signed, has not passed.
	for _, x := range r.paid {
		kept := x.notAfter > now.Add(-7*24*time.Hour).UnixMilli()
		if n := count(`SELECT COUNT(*) FROM credit_settled WHERE auth_id = ?`, x.id); (n == 1) != kept {
			t.Fatalf("%s: the settled row of %s (NotAfter %v before now) is there: %v, want %v",
				step, x.id, now.Sub(time.UnixMilli(x.notAfter)), n == 1, kept)
		}
	}
	for id, settleAt := range r.cleared {
		kept := settleAt > now.Add(-8*24*time.Hour).UnixMilli()
		if n := count(`SELECT COUNT(*) FROM credit_cleared WHERE auth_id = ?`, id); (n == 1) != kept {
			t.Fatalf("%s: the clearing of %s (settled %v before now) is there: %v, want %v",
				step, id, now.Sub(time.UnixMilli(settleAt)), n == 1, kept)
		}
	}
	r.replay(step)
}

func TestPropTheLedgerWindowKeepsNothingPastItsTime(t *testing.T) {
	seeds := []uint64{1, 2, 3}
	steps := 160
	if v := os.Getenv("ANET_PROP_SEEDS"); v != "" {
		n, _ := strconv.Atoi(v)
		seeds = seeds[:0]
		for i := 0; i < n; i++ {
			seeds = append(seeds, uint64(time.Now().UnixNano())+uint64(i))
		}
	}
	for _, seed := range seeds {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
			r := newWindowRig(t)
			for i := 0; i < steps; i++ {
				switch op := rng.IntN(10); {
				case op <= 2:
					r.pay(rng, r.agents[rng.IntN(len(r.agents))].AID(), false)
				case op == 3:
					r.pay(rng, "did:anet:elsewhere-"+r.next(), true)
				case op == 4:
					r.pay(rng, r.hubAID, false)
				case op == 5:
					r.clear(rng)
				case op == 6:
					e, err := r.s.publishDueAt(r.now)
					if err != nil {
						t.Fatalf("step %d: publishing: %v", i, err)
					}
					if e != nil {
						r.done["epoch"]++
					}
				default:
					// Time passes: minutes to days, now and then a long gap.
					d := time.Duration(rng.Int64N(int64(36 * time.Hour)))
					if rng.IntN(8) == 0 {
						d = time.Duration(rng.Int64N(int64(20 * 24 * time.Hour)))
					}
					r.now = r.now.Add(d)
					r.check(fmt.Sprintf("step %d (+%v)", i, d))
				}
			}
			r.check("the end")
			for _, kind := range []string{"settled", "bound", "guarded", "forwarded", "redeemed", "cleared", "epoch"} {
				if r.done[kind] == 0 {
					t.Errorf("no %s step succeeded; the property was not tested on its rows (%v)", kind, r.done)
				}
			}
			// And, long after, nothing of the window is left at all.
			r.now = r.now.Add(31 * 24 * time.Hour)
			r.check("31 days later")
			for _, table := range []string{"credit_entry", "credit_redemption", "credit_settled", "settle_guard",
				"credit_cleared", "liab_leaf", "liab_meta"} {
				var n int
				_ = r.s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n)
				if n != 0 {
					t.Errorf("31 days after the last movement %s still holds %d rows", table, n)
				}
			}
		})
	}
}
