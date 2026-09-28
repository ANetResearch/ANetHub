package federation

import (
	"strings"
	"testing"
	"time"
)

// Every accepted forward prunes fed_dedupe of entries older than the
// window (DedupeWindow, seven days). Without an index on ts that DELETE
// reads the whole table, and the table holds every payload CID of the last
// seven days: a hub forwarding a steady stream pays a full scan of a week's
// traffic per message. Seen in the lab soak (ANet docs/notes/0036): 2 000
// rows an hour on each hub at the soak's rate, a full scan per forward.
func TestDedupePruningUsesAnIndex(t *testing.T) {
	r := newRig(t)
	if ok, _, err := r.a.TryForward("aid:bob", fedEnv(t, "aid:bob", "one")); !ok || err != nil {
		t.Fatalf("forward: %v %v", ok, err)
	}
	rows, err := r.b.db.Query(`EXPLAIN QUERY PLAN DELETE FROM fed_dedupe WHERE ts < ?`,
		time.Now().Add(-DedupeWindow).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	p := strings.Join(plan, "; ")
	if !strings.Contains(p, "USING") {
		t.Fatalf("pruning fed_dedupe scans the table: %s", p)
	}
}
