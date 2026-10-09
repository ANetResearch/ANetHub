package aghub

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"
)

// mustKEL is c's KEL, marshalled.
func mustKEL(t *testing.T, c *identity.Controller) []byte {
	t.Helper()
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return kel
}

// The janitor of the ledger window (hub-payment-privacy PAY-L2, janitor.go).

// M-PAY-8 (the janitor's half), M-PAY-35: the hub runs the janitor at start
// and on every tick; a round deletes the ledger window's rows past their
// time — the entries and the redemptions after 14 days among them — and
// keeps the rest.
func TestTheJanitorRunsAtStartAndOnEveryTick(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	start := time.Now().Truncate(time.Millisecond)
	now := start
	s.clock = func() time.Time { return now }
	own := payment.CreditNetwork(hub.AID())
	a := authAt(t, payer, payee.AID(), 5, own, "j-1", "j-1", now.Add(-time.Second), time.Minute)
	if out := s.SettleWithRequirements(hub.AID(), payloadFor(t, a), requirementsOf(a)); !out.Success {
		t.Fatal(out)
	}
	r := authAt(t, payer, hub.AID(), 4, own, "", "j-2", now.Add(-time.Second), time.Minute)
	if _, err := s.Redeem(hub.AID(), payloadFor(t, r), "j-ref"); err != nil {
		t.Fatal(err)
	}
	rows := func(table string) int {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	entries := rows("credit_entry")
	// 13 days on, the start round deletes the settled row (7 days past its
	// NotAfter) and nothing of the window.
	now = start.Add(13 * 24 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tick := make(chan time.Time)
	rounds := make(chan struct{}, 4)
	go s.runLedgerJanitor(ctx, tick, func() { rounds <- struct{}{} })
	<-rounds
	if rows("credit_settled") != 0 || rows("credit_entry") != entries || rows("credit_redemption") != 1 ||
		rows("settle_guard") != 1 {
		t.Errorf("after the start round at 13 days: settled %d, entries %d of %d, redemptions %d, guards %d",
			rows("credit_settled"), rows("credit_entry"), entries, rows("credit_redemption"), rows("settle_guard"))
	}
	// A tick at 15 days deletes the window's rows.
	now = start.Add(15 * 24 * time.Hour)
	tick <- now
	<-rounds
	if rows("credit_entry") != 0 || rows("credit_redemption") != 0 {
		t.Errorf("after a tick at 15 days: entries %d, redemptions %d", rows("credit_entry"), rows("credit_redemption"))
	}
	if rows("settle_guard") != 1 {
		t.Errorf("the guard went before its 30 days")
	}
	// The balances are what the window leaves.
	if n, _ := s.Balance(payee.AID()); n != 5 {
		t.Errorf("payee balance %d after the window, want 5", n)
	}
}

// The janitor deletes rows; it neither rebuilds credit_entry nor touches
// sqlite_sequence (PAY-3's ledger_hw is the largest seq ever written, which
// AUTOINCREMENT keeps there): the table's root page and its sequence are
// what they were, and the next entry is numbered after every one deleted.
func TestPruningNeitherRebuildsTheLedgerNorForgetsItsSeq(t *testing.T) {
	s, _, payer, _ := settlementStore(t)
	start := time.Now().Truncate(time.Millisecond)
	now := start
	s.clock = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if err := s.GrantCredit(payer.AID(), 1, "operator"); err != nil {
			t.Fatal(err)
		}
	}
	state := func() (root, seq, rows int64) {
		t.Helper()
		if err := s.db.QueryRow(`SELECT rootpage FROM sqlite_master WHERE type='table' AND name='credit_entry'`).Scan(&root); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name='credit_entry'`).Scan(&seq); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM credit_entry`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return
	}
	root0, seq0, rows0 := state()
	if rows0 == 0 || seq0 == 0 {
		t.Fatal("setup: no entries")
	}
	now = start.Add(15 * 24 * time.Hour)
	if n, err := s.PruneLedger(); err != nil || n["credit_entry"] != rows0 {
		t.Fatalf("pruned %v (%v), want %d entries", n, err, rows0)
	}
	root1, seq1, rows1 := state()
	if rows1 != 0 || root1 != root0 || seq1 != seq0 {
		t.Errorf("after pruning: root page %d (was %d), seq %d (was %d), rows %d", root1, root0, seq1, seq0, rows1)
	}
	if err := s.GrantCredit(payer.AID(), 1, "operator"); err != nil {
		t.Fatal(err)
	}
	var next int64
	_ = s.db.QueryRow(`SELECT MIN(seq) FROM credit_entry`).Scan(&next)
	if next <= seq0 {
		t.Errorf("the next entry is numbered %d, not after the %d already given out", next, seq0)
	}
}

// SI-47 at the unit level: what a pruned row held is not left in hub.db or
// its write-ahead log. The round deletes with secure_delete and then
// truncates the log, so a characteristic redemption reference and amount
// are found nowhere in the data directory afterwards, and the log is empty.
func TestAPrunedRowLeavesNoBytes(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, hub, payer, _ := settlementStore(t) // its identities only
	s.SetHubKey(hub)
	start := time.Now().Truncate(time.Millisecond)
	now := start
	s.clock = func() time.Time { return now }
	if err := s.PutAgent(payer.AID(), "agent", nil, mustKEL(t, payer)); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantCredit(payer.AID(), 9000, "fixture"); err != nil {
		t.Fatal(err)
	}
	const canary = "REFERENCE-CANARY-7919-a4f1"
	r := authAt(t, payer, hub.AID(), 7919, payment.CreditNetwork(hub.AID()), "", "canary", now.Add(-time.Second), time.Minute)
	if _, err := s.Redeem(hub.AID(), payloadFor(t, r), canary); err != nil {
		t.Fatal(err)
	}
	found := func() []string {
		var hits []string
		for _, name := range []string{"hub.db", "hub.db-wal"} {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			if bytes.Contains(b, []byte(canary)) {
				hits = append(hits, name)
			}
		}
		return hits
	}
	if len(found()) == 0 {
		t.Fatal("setup: the canary is nowhere before pruning")
	}
	now = start.Add(15 * 24 * time.Hour)
	if _, err := s.PruneLedger(); err != nil {
		t.Fatal(err)
	}
	if hits := found(); len(hits) != 0 {
		t.Errorf("a pruned redemption's reference is still in %v", hits)
	}
	if st, err := os.Stat(filepath.Join(dir, "hub.db-wal")); err == nil && st.Size() != 0 {
		t.Errorf("hub.db-wal holds %d bytes after the round's checkpoint", st.Size())
	}
}

// The janitor deletes nothing before its time (PAY-L2, PAY-L3, PAY-L5): 6
// days and 23 hours after an authorization's NotAfter its settled row is
// still there and a repeat is answered with the original receipt; 7 days
// and 23 hours after a peer's receipt was settled its clearing row is still
// there, so the same receipt again is answered as cleared rather than
// credited twice; 13 days on the window's entries are all still served.
func TestTheJanitorKeepsWhatIsStillNeeded(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	start := time.Now().Truncate(time.Millisecond)
	now := start
	s.clock = func() time.Time { return now }
	own := payment.CreditNetwork(hub.AID())
	a := authAt(t, payer, payee.AID(), 6, own, "keep-1", "keep-1", now.Add(-time.Second), time.Minute)
	first := s.SettleWithRequirements(hub.AID(), payloadFor(t, a), requirementsOf(a))
	if !first.Success {
		t.Fatal(first)
	}
	peer, _ := identitytest.Hub()
	rec := &payment.Receipt{AuthID: "keep-peer", Payer: "did:anet:their-user", PayTo: payee.AID(), Amount: 9,
		Network: payment.CreditNetwork(peer.AID()), SettleAt: start.UnixMilli()}
	if err := rec.Sign(peer); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearFromPeer(peer.AID(), peer.KEL(), rec); err != nil {
		t.Fatal(err)
	}
	entries := func() int {
		win, err := s.LedgerEntries(payee.AID(), 500)
		if err != nil {
			t.Fatal(err)
		}
		return win.Total
	}
	before := entries()
	now = start.Add(time.Minute + 7*24*time.Hour - time.Hour)
	if _, err := s.PruneLedger(); err != nil {
		t.Fatal(err)
	}
	again := s.SettleWithRequirements(hub.AID(), payloadFor(t, a), requirementsOf(a))
	if !again.Success || again.Extensions[payment.ExtReceipt] != first.Extensions[payment.ExtReceipt] {
		t.Errorf("a repeat within 7 days of NotAfter: %+v, want the original receipt", again)
	}
	now = start.Add(8*24*time.Hour - time.Hour)
	if _, err := s.PruneLedger(); err != nil {
		t.Fatal(err)
	}
	bal, _ := s.Balance(payee.AID())
	if err := s.ClearFromPeer(peer.AID(), peer.KEL(), rec); err != nil {
		t.Errorf("the cleared receipt again, within 8 days of its settlement: %v", err)
	}
	if n, _ := s.Balance(payee.AID()); n != bal {
		t.Errorf("the receipt was credited again: %d -> %d", bal, n)
	}
	now = start.Add(13 * 24 * time.Hour)
	if _, err := s.PruneLedger(); err != nil {
		t.Fatal(err)
	}
	if n := entries(); n != before {
		t.Errorf("13 days on the window lists %d entries, want the %d it had", n, before)
	}
}
