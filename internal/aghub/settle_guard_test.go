package aghub

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/payment"
)

// The settlement guard (hub-payment-privacy PAY-L3, SI-9; core L33): one
// settlement per payer and task, for 30 days, kept as
// SHA-256("anet-settle-guard/v1" ‖ 0x00 ‖ payer ‖ 0x00 ‖ pay_bind) and
// nothing else, so the guard does not keep who paid for what.

// guardRows is every settle_guard row: its key and its until.
func guardRows(t *testing.T, s *Store) (hs [][]byte, until []int64) {
	t.Helper()
	rows, err := s.db.Query(`SELECT h, until FROM settle_guard ORDER BY h`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var h []byte
		var u int64
		if err := rows.Scan(&h, &u); err != nil {
			t.Fatal(err)
		}
		hs, until = append(hs, h), append(until, u)
	}
	return hs, until
}

// M-PAY-8 (the guard's half): a settlement bound to a task leaves one guard
// row, keyed by evidence.SettleGuard(payer, pay_bind), until 30 days after
// the settlement, and the table has no other column; neither the payer nor
// the task is anywhere in it. The settled row names its guard. Without a
// binding there is no guard.
func TestTheSettlementGuardKeepsOnlyTheHash(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	now := time.Now().Truncate(time.Millisecond)
	s.clock = func() time.Time { return now }
	own := payment.CreditNetwork(hub.AID())
	const bind = "9f2c0d3e4a5b6c7d8e9f0a1b2c3d4e5f"
	a := authAt(t, payer, payee.AID(), 12, own, bind, "g-1", now.Add(-time.Second), time.Minute)
	if out := s.SettleWithRequirements(hub.AID(), payloadFor(t, a), requirementsOf(a)); !out.Success {
		t.Fatal(out)
	}
	cols, err := s.db.Query(`SELECT name FROM pragma_table_info('settle_guard') ORDER BY cid`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for cols.Next() {
		var n string
		_ = cols.Scan(&n)
		names = append(names, n)
	}
	cols.Close()
	if strings.Join(names, ",") != "h,until" {
		t.Errorf("settle_guard has the columns %v, want h and until only", names)
	}
	want, _ := evidence.SettleGuard(payer.AID(), bind)
	hs, until := guardRows(t, s)
	if len(hs) != 1 || !bytes.Equal(hs[0], want) || until[0] != now.Add(30*24*time.Hour).UnixMilli() {
		t.Fatalf("guard rows %x until %v, want %x until settlement + 30 days", hs, until, want)
	}
	for _, h := range hs {
		if len(h) != 32 || bytes.Contains(h, []byte(payer.AID())) || bytes.Contains(h, []byte(bind)) {
			t.Errorf("a guard key that is not a bare hash: %x", h)
		}
	}
	var guardH []byte
	id, _ := a.ID()
	if err := s.db.QueryRow(`SELECT guard_h FROM credit_settled WHERE auth_id=?`, id).Scan(&guardH); err != nil ||
		!bytes.Equal(guardH, want) {
		t.Errorf("the settled row's guard: %x (%v)", guardH, err)
	}
	b := authAt(t, payer, payee.AID(), 3, own, "", "g-2", now.Add(-time.Second), time.Minute)
	if out := s.SettleWithRequirements(hub.AID(), payloadFor(t, b), requirementsOf(b)); !out.Success {
		t.Fatal(out)
	}
	if hs, _ := guardRows(t, s); len(hs) != 1 {
		t.Errorf("a settlement without a binding left a guard: %d rows", len(hs))
	}
}

// SI-9: a second authorization for a task its payer already settled is
// refused with duplicate_binding and moves nothing, for 30 days. While the
// first settlement's row is kept (7 days past its NotAfter) the refusal
// names it; after that only the code is given; after the 30 days a new
// authorization for the task settles. A different payer, or the same payer
// for another task, is not held by the guard. Verify says the same.
func TestASecondPaymentForATaskIsRefusedFor30Days(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	start := time.Now().Truncate(time.Millisecond)
	now := start
	s.clock = func() time.Time { return now }
	own := payment.CreditNetwork(hub.AID())
	const bind = "task-bind-1"
	n := 0
	pay := func(bind string) (payment.SettlementResponse, payment.VerifyResponse) {
		n++
		a := authAt(t, payer, payee.AID(), 5, own, bind, "s-"+string(rune('a'+n)), now.Add(-time.Second), 5*time.Minute)
		v := s.VerifyWithRequirements(hub.AID(), payloadFor(t, a), requirementsOf(a))
		return s.SettleWithRequirements(hub.AID(), payloadFor(t, a), requirementsOf(a)), v
	}
	first, v := pay(bind)
	if !first.Success || !v.IsValid {
		t.Fatalf("first: %+v %+v", first, v)
	}
	before := ledgerRows(t, s)
	second, v := pay(bind)
	if second.Success || second.ErrorReason != payment.ReasonDuplicateBinding ||
		second.Extensions[payment.ExtOriginalTransaction] != first.Transaction {
		t.Errorf("second within the row's time: %+v, want duplicate_binding naming %s", second, first.Transaction)
	}
	if v.IsValid || v.InvalidReason != payment.ReasonDuplicateBinding {
		t.Errorf("verify of the second: %+v", v)
	}
	if after := ledgerRows(t, s); after != before {
		t.Errorf("a duplicate binding moved credit")
	}
	if other, _ := pay("task-bind-2"); !other.Success {
		t.Errorf("another task: %+v", other)
	}
	// 8 days on the first settlement's row is deleted; the guard stays.
	now = start.Add(8 * 24 * time.Hour)
	if _, err := s.PruneLedger(); err != nil {
		t.Fatal(err)
	}
	third, v := pay(bind)
	if third.Success || third.ErrorReason != payment.ReasonDuplicateBinding {
		t.Errorf("third after the row was deleted: %+v", third)
	}
	if _, named := third.Extensions[payment.ExtOriginalTransaction]; named {
		t.Errorf("the refusal names a settlement whose row is gone: %+v", third)
	}
	if v.IsValid {
		t.Errorf("verify of the third: %+v", v)
	}
	// 30 days after the first, the binding is free again (the guard is
	// taken over before or after the janitor deletes it).
	now = start.Add(30*24*time.Hour + time.Millisecond)
	if fourth, v := pay(bind); !fourth.Success || !v.IsValid {
		t.Errorf("after 30 days: %+v %+v", fourth, v)
	}
	if _, err := s.PruneLedger(); err != nil {
		t.Fatal(err)
	}
	// The other task's guard is 30 days old too and gone; the new one stays.
	want, _ := evidence.SettleGuard(payer.AID(), bind)
	if hs, until := guardRows(t, s); len(hs) != 1 || !bytes.Equal(hs[0], want) || until[0] <= now.UnixMilli() {
		t.Errorf("after the janitor: guards %x, until %v (now %d)", hs, until, now.UnixMilli())
	}
}

// CORE-E9 at the settlement: a pay_bind holding U+0000 could move the
// boundary of the guard's hash input; such an authorization is refused as
// malformed and moves nothing, and verify agrees.
func TestASettlementGuardInputWithNULIsRefused(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	own := payment.CreditNetwork(hub.AID())
	before := ledgerRows(t, s)
	for _, bind := range []string{"a\x00b", "\x00", "task\x00"} {
		a := authAt(t, payer, payee.AID(), 5, own, bind, "nul-"+bind, s.now().Add(-time.Second), time.Minute)
		if out := s.SettleWithRequirements(hub.AID(), payloadFor(t, a), requirementsOf(a)); out.Success ||
			out.ErrorReason != payment.ReasonMalformed {
			t.Errorf("pay_bind %q: %+v", bind, out)
		}
		if v := s.VerifyWithRequirements(hub.AID(), payloadFor(t, a), requirementsOf(a)); v.IsValid ||
			v.InvalidReason != payment.ReasonMalformed {
			t.Errorf("verify, pay_bind %q: %+v", bind, v)
		}
	}
	if after := ledgerRows(t, s); after != before {
		t.Errorf("a refused settlement moved credit")
	}
}
