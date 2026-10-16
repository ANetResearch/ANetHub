package aghub

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"
)

// RunSupplyEpochs, the only thing that publishes in a running hub (PAY-S2,
// PAY-S5): it checks once at start, so a hub that was down over a midnight
// catches up; then once after each UTC midnight and not in between, however
// many supply events arrive; a check that failed for a reason that can pass
// is made again at the next tick, the same day; and every tick drops the
// leaves of epochs published 14 days ago, not only the first tick of a day.
func TestTheSchedulePublishesAtStartAfterMidnightAndAfterAFailure(t *testing.T) {
	start := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	r := newSupplyRig(t, start, 2)
	agent := r.agents[0].AID()
	if err := r.store.GrantCredit(agent, 10, "first"); err != nil { // the first supply event
		t.Fatal(err)
	}
	// Eight days later the hub starts: the week since the first event is due.
	r.now = start.Add(8 * 24 * time.Hour)
	ticks := make(chan time.Time)
	handled := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		r.store.runSupplyEpochs(ctx, ticks, func() { handled <- struct{}{} })
		close(stopped)
	}()
	t.Cleanup(func() { cancel(); <-stopped })
	<-handled
	// tick moves the clock to at, gives the schedule one tick and waits for
	// it to be handled.
	tick := func(at time.Time) {
		t.Helper()
		r.now = at
		ticks <- at
		<-handled
	}
	epochs := func() int {
		t.Helper()
		var n int
		if err := r.store.db.QueryRow(`SELECT COUNT(*) FROM supply_chain`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	leavesOf := func(toDay uint64) int {
		t.Helper()
		var n int
		if err := r.store.db.QueryRow(`SELECT COUNT(*) FROM liab_leaf WHERE to_day = ?`, toDay).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	head := func() SupplyEpochEntry {
		t.Helper()
		e, ok, err := r.store.latestEpoch()
		if err != nil || !ok {
			t.Fatalf("no epoch: %v", err)
		}
		return e
	}

	if epochs() != 1 {
		t.Fatalf("at start: %d epochs, want the one that was due", epochs())
	}
	e0 := head()
	if e0.ToDay != uint64(utcDay(r.now)-1) {
		t.Errorf("the epoch published at start ends on day %d, want %d", e0.ToDay, utcDay(r.now)-1)
	}

	// 25 supply events the same day make the next epoch due, but the hub
	// looks only after midnight.
	for i := 0; i < 25; i++ {
		if err := r.store.GrantCredit(agent, 1, "event"); err != nil {
			t.Fatal(err)
		}
	}
	tick(r.now.Add(time.Minute))
	tick(r.now.Add(time.Hour))
	if epochs() != 1 {
		t.Fatalf("published before midnight: %d epochs", epochs())
	}
	nextDay := time.UnixMilli((utcDay(r.now) + 1) * dayMillis).UTC()
	tick(nextDay.Add(30 * time.Second))
	if epochs() != 2 {
		t.Fatalf("after midnight: %d epochs, want 2", epochs())
	}
	e1 := head()

	// The next midnight nothing is due (no event, one day); the events that
	// make it due arrive later that day, and the epoch waits for the next
	// midnight: a publication follows a midnight, never an event.
	tick(time.UnixMilli((utcDay(r.now) + 1) * dayMillis).UTC().Add(30 * time.Second))
	if epochs() != 2 {
		t.Fatalf("a quiet day closed an epoch: %d epochs", epochs())
	}
	for i := 0; i < 20; i++ {
		if err := r.store.GrantCredit(agent, 1, "event"); err != nil {
			t.Fatal(err)
		}
	}
	tick(r.now.Add(12 * time.Hour))
	if epochs() != 2 {
		t.Fatalf("an epoch was published in the middle of a day, after the event that made it due: %d epochs", epochs())
	}

	// A check that fails for a reason that can pass is made again a tick
	// later, the same day: here the leaves' bookkeeping row of the day the
	// next epoch closes is in the way, then gone.
	for i := 0; i < 20; i++ {
		if err := r.store.GrantCredit(agent, 1, "event"); err != nil {
			t.Fatal(err)
		}
	}
	after := time.UnixMilli((utcDay(r.now) + 1) * dayMillis).UTC().Add(30 * time.Second)
	if _, err := r.store.db.Exec(`INSERT INTO liab_meta(to_day, ledger_hw, leaves) VALUES(?, 0, 0)`,
		utcDay(after)-1); err != nil {
		t.Fatal(err)
	}
	tick(after)
	if epochs() != 2 {
		t.Fatalf("the blocked check published: %d epochs", epochs())
	}
	if _, err := r.store.db.Exec(`DELETE FROM liab_meta WHERE to_day = ?`, utcDay(after)-1); err != nil {
		t.Fatal(err)
	}
	tick(after.Add(time.Minute))
	if epochs() != 3 {
		t.Fatalf("the failed check was not made again the same day: %d epochs", epochs())
	}

	// 14 days after the first epoch was published its leaves go at the
	// first tick past that moment, though the day has not changed since the
	// last check; the second epoch's stay.
	if leavesOf(e0.ToDay) == 0 || leavesOf(e1.ToDay) == 0 {
		t.Fatal("setup: no leaves")
	}
	at, err := publishedAt(e0.raw)
	if err != nil {
		t.Fatal(err)
	}
	gone := time.UnixMilli(at + proofKeptFor)
	tick(gone.Add(-2 * time.Minute)) // a new day: the hub checks, the leaves are kept
	if leavesOf(e0.ToDay) == 0 {
		t.Fatal("leaves dropped before their 14 days")
	}
	if utcDay(gone) != utcDay(r.now) {
		t.Fatal("setup: the 14 days end on another day")
	}
	tick(gone.Add(time.Second))
	if n := leavesOf(e0.ToDay); n != 0 {
		t.Errorf("14 days after publication the first epoch still has %d leaves", n)
	}
	if leavesOf(e1.ToDay) == 0 {
		t.Error("the second epoch's leaves went too")
	}

	// A ledger that does not add up is logged once, as an ERROR, and not
	// checked again every tick: it waits for the operator, and for the next
	// midnight.
	for i := 0; i < 20; i++ {
		if err := r.store.GrantCredit(agent, 1, "event"); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.store.MoveBalanceWithoutEntryForTest(agent, 5); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	out, flags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(out); log.SetFlags(flags) })
	n := epochs()
	midnight := time.UnixMilli((utcDay(r.now) + 1) * dayMillis).UTC()
	tick(midnight.Add(30 * time.Second))
	tick(midnight.Add(90 * time.Second))
	tick(midnight.Add(150 * time.Second))
	if epochs() != n {
		t.Errorf("a ledger that does not add up was published: %d epochs, had %d", epochs(), n)
	}
	if c := strings.Count(logs.String(), "ERROR"); c != 1 {
		t.Errorf("a ledger that does not add up was logged %d times in three ticks of one day, want once:\n%s", c, logs.String())
	}
}
