package aghub_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

func i64(v int64) *int64 { return &v }

// The per-recipient quota (sealed-sender SSR-H5, SSR-H22): every AID has the
// defaults until the operator raises one of its values; only the values
// given change; nothing goes below a default; a value set back to its
// default is the default again, and a quota at every default keeps no row.
// The hub process, another process than the one that wrote, sees a change
// within a minute.
func TestQuotaOnlyRises(t *testing.T) {
	dir := t.TempDir()
	hub, err := aghub.Open(dir) // the hub process
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	now := time.Now()
	hub.SetClockForTest(func() time.Time { return now })
	op, err := aghub.Open(dir) // anet-hub quota beside it
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	_, aid := twoAgents(t)
	def := aghub.DefaultQuota()
	if def != (aghub.Quota{FirstContactsPerMin: 30, NonContactMsgs: 500, NonContactBytes: 64 << 20}) ||
		def.FirstContactsBurst() != 60 {
		t.Fatalf("the defaults are %+v (burst %d), want 30 a minute with bursts of 60, 500 messages, 64 MiB",
			def, def.FirstContactsBurst())
	}
	if q := hub.QuotaFor(aid.AID()); q != def {
		t.Fatalf("an AID nobody raised: %+v", q)
	}

	q, err := op.SetQuota(aid.AID(), aghub.QuotaChange{FirstContactsPerMin: i64(120)})
	want := def
	want.FirstContactsPerMin = 120
	if err != nil || q != want {
		t.Fatalf("raising the first contacts: %+v %v, want %+v", q, err, want)
	}
	q, err = op.SetQuota(aid.AID(), aghub.QuotaChange{NonContactMiB: i64(256)})
	want.NonContactBytes = 256 << 20
	if err != nil || q != want {
		t.Fatalf("raising the MiB: %+v %v, want %+v (only the value given changes)", q, err, want)
	}
	if got, err := op.QuotaOf(aid.AID()); err != nil || got != want {
		t.Fatalf("QuotaOf: %+v %v", got, err)
	}

	// Within a minute the hub process uses the raised values.
	if q := hub.QuotaFor(aid.AID()); q != def && q != want {
		t.Fatalf("the hub process sees %+v", q)
	}
	now = now.Add(time.Minute)
	if q := hub.QuotaFor(aid.AID()); q != want {
		t.Fatalf("a minute later the hub process sees %+v, want %+v", q, want)
	}

	// Below a default: refused, nothing written.
	for _, c := range []struct {
		ch    aghub.QuotaChange
		field string
		def   int64
	}{
		{aghub.QuotaChange{FirstContactsPerMin: i64(29)}, aghub.QuotaFirstContactsPerMin, 30},
		{aghub.QuotaChange{NonContactMsgs: i64(0)}, aghub.QuotaNonContactMsgs, 500},
		{aghub.QuotaChange{NonContactMiB: i64(-1)}, aghub.QuotaNonContactMiB, 64},
		{aghub.QuotaChange{NonContactMsgs: i64(1000), NonContactMiB: i64(63)}, aghub.QuotaNonContactMiB, 64},
	} {
		_, err := op.SetQuota(aid.AID(), c.ch)
		var below *aghub.QuotaBelowDefaultError
		if !errors.As(err, &below) || below.Field != c.field || below.Default != c.def {
			t.Errorf("%+v: %v, want below default %s %d", c.ch, err, c.field, c.def)
		}
	}
	if _, err := op.SetQuota(aid.AID(), aghub.QuotaChange{NonContactMsgs: i64(1 << 40)}); !errors.Is(err, aghub.ErrQuotaTooLarge) {
		t.Errorf("an absurd value: %v", err)
	}
	if got, _ := op.QuotaOf(aid.AID()); got != want {
		t.Fatalf("a refused change wrote: %+v", got)
	}

	// Back to the defaults: no row left.
	if q, err := op.SetQuota(aid.AID(), aghub.QuotaChange{FirstContactsPerMin: i64(30), NonContactMiB: i64(64)}); err != nil || q != def {
		t.Fatalf("back to the defaults: %+v %v", q, err)
	}
	var rows int
	if err := op.DBForTest().QueryRow(`SELECT COUNT(*) FROM quota_override`).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("a quota at every default keeps %d row(s) (%v)", rows, err)
	}
	now = now.Add(time.Minute)
	if q := hub.QuotaFor(aid.AID()); q != def {
		t.Errorf("after the reset the hub process sees %+v", q)
	}

	// A change made in the hub process itself is in force at once.
	if _, err := hub.SetQuota(aid.AID(), aghub.QuotaChange{NonContactMsgs: i64(800)}); err != nil {
		t.Fatal(err)
	}
	if q := hub.QuotaFor(aid.AID()); q.NonContactMsgs != 800 {
		t.Errorf("a change in the hub process is not in force at once: %+v", q)
	}

	// A row below the defaults, written by hand, lowers nothing.
	if _, err := op.DBForTest().Exec(`INSERT INTO quota_override VALUES(?, 1, 1, 1)`, "bafyhandwritten"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if q := hub.QuotaFor("bafyhandwritten"); q != def {
		t.Errorf("a hand-written row below the defaults gives %+v", q)
	}
}
