package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// ledgerStamp is how the ledger tables write a time (aghub janitor.go).
func ledgerStamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }

// redemptionRow is one credit_redemption row a test writes.
type redemptionRow struct {
	authID, aid string
	amount      int64
	reference   string
	at          time.Time
}

// writeRedemptions puts rows into credit_redemption of the hub in dir, as Redeem leaves them.
func writeRedemptions(t *testing.T, dir string, rows ...redemptionRow) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(15000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO credit_redemption(auth_id, aid, amount, reference, at) VALUES(?,?,?,?,?)`,
			r.authID, r.aid, r.amount, r.reference, ledgerStamp(r.at)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRedemptionsListsTheWindow (hub-payment-privacy PAY-U2): anet-hub redemptions lists every
// redemption of the 14-day window, of every account, oldest first, one tab-separated line each with
// the reference quoted; it leaves out what is older; its last line is redemptions.summary with the
// window's count and sum. --json says the same as data. Nothing is written.
func TestRedemptionsListsTheWindow(t *testing.T) {
	dir := hubDir(t)
	_, a := newAID(t)
	_, b := newAID(t)
	now := time.Now()
	writeRedemptions(t, dir,
		redemptionRow{"auth-new", a, 30, "INV-3", now.Add(-time.Hour)},
		redemptionRow{"auth-old", b, 1000, "too old", now.Add(-15 * 24 * time.Hour)},
		redemptionRow{"auth-mid", b, 12, "pay\tout\n\x1b[2Jnow", now.Add(-13 * 24 * time.Hour)},
		redemptionRow{"auth-first", a, 5, "", now.Add(-13*24*time.Hour - time.Minute)},
	)
	line := func(at time.Time, aid, amount, ref, auth string) string {
		return strings.Join([]string{ledgerStamp(at), aid, amount, strconv.Quote(ref), auth}, "\t") + "\n"
	}
	for _, lang := range []string{"en", "zh"} {
		want := line(now.Add(-13*24*time.Hour-time.Minute), a, "5", "", "auth-first") +
			line(now.Add(-13*24*time.Hour), b, "12", "pay\tout\n\x1b[2Jnow", "auth-mid") +
			line(now.Add(-time.Hour), a, "30", "INV-3", "auth-new") +
			sentenceOf(lang, "redemptions.summary", map[string]string{"n": "3", "m": "47"})
		r := cli(t, lang, "-data", dir, "redemptions")
		expectOut(t, r, want)
		if strings.Contains(r.stdout, "\x1b") || strings.Count(r.stdout, "\n") != 4 {
			t.Errorf("a reference reached the terminal as it is: %q", r.stdout)
		}
	}
	r := cli(t, "en", "redemptions", "--json", "--data", dir)
	var out redemptionsJSON
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || r.code != 0 {
		t.Fatalf("--json: %d %q %v", r.code, r.stdout, err)
	}
	if out.Count != 3 || out.Sum != 47 || out.WindowDays != aghub.LedgerWindowDays || len(out.Redemptions) != 3 ||
		out.Redemptions[0].AuthID != "auth-first" || out.Redemptions[2].Reference != "INV-3" ||
		out.Redemptions[1].Amount != 12 || out.Redemptions[1].AID != b {
		t.Errorf("--json: %+v", out)
	}
	if strings.Contains(r.stdout, "auth-old") {
		t.Error("--json lists a redemption older than the window")
	}

	// An empty window says so; the wrong directory is data.missing.
	expectOut(t, cli(t, "en", "-data", hubDir(t), "redemptions"),
		sentenceOf("en", "redemptions.summary", map[string]string{"n": "0", "m": "0"}))
	empty := t.TempDir()
	expectErr(t, cli(t, "en", "-data", empty, "redemptions"), 1,
		sentenceOf("en", "data.missing", map[string]string{"path": empty}))
	expectErr(t, cli(t, "en", "-data", dir, "redemptions", "x"), 2, "usage: anet-hub redemptions [--json]\n")
}

// The -relay-ttl help states the bound a start enforces (forward-secrecy §0, FS-T1): the bound, in a
// form the flag itself takes, is aghub.MaxUndeliveredTTL; it is accepted and one millisecond more is
// refused.
func TestRelayTTLHelpStatesTheBound(t *testing.T) {
	fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := defineFlags(fs)
	usage := fs.Lookup("relay-ttl").Usage
	bound := aghub.MaxUndeliveredTTL.String()
	if !strings.Contains(usage, "at most "+bound) || !strings.Contains(usage, "14 days 22 h 55 min") {
		t.Fatalf("the -relay-ttl help does not state the bound %s: %q", bound, usage)
	}
	if err := fs.Parse([]string{"-relay-ttl", bound}); err != nil || *f.undeliveredTTL != aghub.MaxUndeliveredTTL {
		t.Fatalf("the stated bound does not parse back: %v", err)
	}
	if err := f.limits().Validate(); err != nil {
		t.Errorf("the stated bound is refused: %v", err)
	}
	l := f.limits()
	l.UndeliveredTTL += time.Millisecond
	if l.Validate() == nil {
		t.Error("a TTL past the stated bound is accepted")
	}
}
