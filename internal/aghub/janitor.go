package aghub

import (
	"context"
	"fmt"
	"log"
	"time"
)

// The ledger window (hub-payment-privacy §0.4, PAY-L2).
//
// The ledger's detail is kept for a short, fixed time and then deleted: who
// paid whom, how much and when is on this hub for 14 days, in its backups for
// at most 14 more (deploy/hub-db-roll.sh), and gone after that. What stays is
// the balance of each account and what the hubs owe each other. A balance is
// therefore no longer the sum of the entries behind it, and nothing here
// pretends it is: an account reconciles the window it can see, and checks its
// balance against the published supply epochs (supply.go).
//
// What each table keeps:
//
//	credit_entry       14 days
//	credit_redemption  14 days (the operator handles a redemption within that
//	                   time, with anet-hub redemptions)
//	credit_settled     until 7 days after the authorization's NotAfter; a
//	                   repeat after that is expired anyway, and is refused as
//	                   one, so the deleted row cannot be settled twice
//	settle_guard       30 days after the settlement
//	credit_cleared     until 8 days after the receipt's SettleAt, a day longer
//	                   than ClearFromPeer accepts a receipt at all
//	x402_first_verify  until 7 days after the authorization's NotAfter, as
//	                   credit_settled
//	liab_leaf, liab_meta  14 days after the epoch was published (supply.go)
//
// The janitor runs hourly, so a row outlives its time by at most an hour. The
// database deletes with secure_delete on (Open), and every round ends with a
// checkpoint that truncates the write-ahead log, so a deleted row's bytes do
// not stay in either file.
const (
	// LedgerWindowDays is the window of /agents/{aid}/ledger and
	// /agents/{aid}/redemptions (window_days).
	LedgerWindowDays = 14
	// ledgerWindow is how long credit_entry and credit_redemption rows
	// are kept.
	ledgerWindow = LedgerWindowDays * 24 * time.Hour
	// settledKeptAfter is how long a credit_settled row is kept after its
	// authorization's NotAfter.
	settledKeptAfter = 7 * 24 * time.Hour
	// guardKept is how long a settle_guard row is kept after the
	// settlement.
	guardKept = 30 * 24 * time.Hour
	// peerReceiptMaxAge is how old a peer's receipt may be and still be
	// cleared here (receipt_too_old after that); clearedKeptAfter is how
	// long its credit_cleared row is kept after its SettleAt, longer than
	// that by a day.
	peerReceiptMaxAge = 7 * 24 * time.Hour
	clearedKeptAfter  = 8 * 24 * time.Hour
	// janitorEvery is how often RunLedgerJanitor prunes.
	janitorEvery = time.Hour
)

// ledgerStampLayout is how the ledger tables write a time: UTC with all nine
// fractional digits, so every stamp has the same length and comparing two as
// text compares them as times (the window's queries do; an index on at
// serves them). It is RFC 3339, and time.RFC3339Nano reads it.
const ledgerStampLayout = "2006-01-02T15:04:05.000000000Z"

// ledgerStamp is t as the ledger tables write it.
func ledgerStamp(t time.Time) string { return t.UTC().Format(ledgerStampLayout) }

// windowStart is the earliest time a row of the ledger window may have at now.
func windowStart(now time.Time) string { return ledgerStamp(now.Add(-ledgerWindow)) }

// retentionStep is one table's deletion: query, run with the value of arg at
// the time of the round.
type retentionStep struct {
	table string
	query string
	arg   func(now time.Time) any
}

// ledgerRetention is what the janitor deletes, table by table (PAY-L2). An
// area whose table is deleted on the same clock adds its step here, as KEL's
// x402_first_verify is.
//
// None of them rebuilds a table or touches sqlite_sequence: a supply epoch's
// ledger_hw is the largest credit_entry seq ever written, which AUTOINCREMENT
// keeps there after the rows are gone (supply.go).
var ledgerRetention = []retentionStep{
	{"credit_entry", `DELETE FROM credit_entry WHERE at < ?`,
		func(now time.Time) any { return windowStart(now) }},
	{"credit_redemption", `DELETE FROM credit_redemption WHERE at < ?`,
		func(now time.Time) any { return windowStart(now) }},
	{"credit_settled", `DELETE FROM credit_settled WHERE not_after <= ?`,
		func(now time.Time) any { return now.Add(-settledKeptAfter).UnixMilli() }},
	{"settle_guard", `DELETE FROM settle_guard WHERE until <= ?`,
		func(now time.Time) any { return now.UnixMilli() }},
	{"credit_cleared", `DELETE FROM credit_cleared WHERE settle_at <= ?`,
		func(now time.Time) any { return now.Add(-clearedKeptAfter).UnixMilli() }},
	// The first verification of an authorization (facilitator.go,
	// KEL H-40), kept as long as its settlement: delete_after is NotAfter
	// + 7 days.
	{"x402_first_verify", `DELETE FROM x402_first_verify WHERE delete_after <= ?`,
		func(now time.Time) any { return now.UnixMilli() }},
}

// PruneLedger deletes every row past its time (ledgerRetention) and the
// balance proofs of epochs published 14 days ago or more, then truncates the
// write-ahead log. It returns how many rows it deleted, by table.
func (s *Store) PruneLedger() (map[string]int64, error) { return s.pruneLedgerAt(s.now()) }

// pruneLedgerAt is PruneLedger with the clock reading now.
func (s *Store) pruneLedgerAt(now time.Time) (map[string]int64, error) {
	deleted := map[string]int64{}
	for _, st := range ledgerRetention {
		res, err := s.db.Exec(st.query, st.arg(now))
		if err != nil {
			return deleted, fmt.Errorf("hub: pruning %s: %w", st.table, err)
		}
		n, _ := res.RowsAffected()
		deleted[st.table] = n
	}
	// The leaves of each epoch, 14 days after it was published. The epoch
	// schedule drops them too (RunSupplyEpochs); both are idempotent.
	if err := s.pruneLiabilityProofsAt(now); err != nil {
		return deleted, fmt.Errorf("hub: pruning balance proofs: %w", err)
	}
	// Truncate the write-ahead log, so the page images of what was just
	// deleted do not stay in it. A reader holding a snapshot can keep the
	// log from being truncated this round (busy = 1); the next round does
	// it.
	var busy, logPages, done int64
	if err := s.db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logPages, &done); err != nil {
		return deleted, fmt.Errorf("hub: checkpoint after pruning: %w", err)
	}
	if busy != 0 {
		log.Printf("hub: ledger window: the write-ahead log was in use and is truncated at the next round")
	}
	return deleted, nil
}

// RunLedgerJanitor prunes the ledger window (PruneLedger) at start and then
// every janitorEvery until ctx ends. A round that failed is logged and the
// next one tries again.
func (s *Store) RunLedgerJanitor(ctx context.Context) {
	t := time.NewTicker(janitorEvery)
	defer t.Stop()
	s.runLedgerJanitor(ctx, t.C, func() {})
}

// runLedgerJanitor is RunLedgerJanitor on the ticks of tick; done is called
// after each round.
func (s *Store) runLedgerJanitor(ctx context.Context, tick <-chan time.Time, done func()) {
	round := func() {
		n, err := s.PruneLedger()
		if err != nil {
			log.Printf("%v; trying again in %v", err, janitorEvery)
		}
		var total int64
		for _, k := range n {
			total += k
		}
		if total > 0 {
			log.Printf("hub: ledger window: deleted %d rows past their time (%v)", total, n)
		}
		done()
	}
	round()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			round()
		}
	}
}
