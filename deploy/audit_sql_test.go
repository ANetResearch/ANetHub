package deploy_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// audit-amount-overflow.sql was written against main's schema and is run
// by an operator with the sqlite3 CLI, which not every host has (see
// needSQLite3). Its statements are plain SQL, so this runs them through
// the driver the hub itself uses, on a database with this line's schema
// (aghub.Open), without the CLI: every statement must parse against the
// real tables, a clean hub must list nothing in sections 1–9, and each
// kind of row the overflow bug wrote must be listed where the script says.

// auditSections runs the script on db and returns each section's heading
// and the rows the statements under it printed, in order.
func auditSections(t *testing.T, conn *sql.Conn) (heads []string, rows map[string][]string) {
	t.Helper()
	raw, err := os.ReadFile("audit-amount-overflow.sql")
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		// Dot commands are the CLI's, comments are nobody's.
		if strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, "--") {
			continue
		}
		kept = append(kept, line)
	}
	rows = map[string][]string{}
	cur := ""
	ctx := context.Background()
	for _, stmt := range strings.Split(strings.Join(kept, "\n"), ";\n") {
		stmt = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(stmt), ";"))
		if stmt == "" {
			continue
		}
		if strings.HasPrefix(stmt, "PRAGMA") {
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
			continue
		}
		q, err := conn.QueryContext(ctx, stmt)
		if err != nil {
			t.Fatalf("the script does not run on this schema: %v\n%s", err, stmt)
		}
		cols, _ := q.Columns()
		for q.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := q.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			if len(cols) == 1 && cols[0] == "section" {
				cur = fmt.Sprint(vals[0])
				heads = append(heads, cur)
				continue
			}
			parts := make([]string, len(vals))
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					v = string(b)
				}
				parts[i] = fmt.Sprint(v)
			}
			rows[cur] = append(rows[cur], strings.Join(parts, " | "))
		}
		if err := q.Err(); err != nil {
			t.Fatal(err)
		}
		q.Close()
	}
	return heads, rows
}

// section is the heading that starts with "== n." among heads.
func section(t *testing.T, heads []string, n string) string {
	t.Helper()
	for _, h := range heads {
		if strings.HasPrefix(h, "== "+n+". ") {
			return h
		}
	}
	t.Fatalf("no section %s among %q", n, heads)
	return ""
}

func openHubDB(t *testing.T) (dir string, db *sql.DB) {
	t.Helper()
	dir = t.TempDir()
	store, err := aghub.Open(dir) // the schema this line's hub creates
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	db, err = sql.Open("sqlite", filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	// A connection the audit ran on stays query_only; not pooled, so the
	// fixture writes after it get a fresh one.
	db.SetMaxIdleConns(0)
	t.Cleanup(func() { db.Close() })
	return dir, db
}

func TestTheAmountAuditListsWhatTheOverflowWroteAndNothingOnACleanHub(t *testing.T) {
	_, db := openHubDB(t)
	const hub, attacker, victim, peer = "did:anet:hub", "did:anet:attacker", "did:anet:victim", "did:anet:peer"
	at := "2026-09-01T00:00:00Z"
	for _, q := range []string{
		// A clean hub: an issued grant and one ordinary settlement.
		`INSERT INTO credit_entry(aid, delta, reason, at) VALUES('` + hub + `', -5100, 'issued:grant', '` + at + `')`,
		`INSERT INTO credit_entry(aid, delta, reason, at) VALUES('` + victim + `', 5100, 'grant', '` + at + `')`,
		`INSERT INTO credit_balance(aid, credits) VALUES('` + hub + `', -5100)`,
		`INSERT INTO credit_balance(aid, credits) VALUES('` + victim + `', 5090)`,
		`INSERT INTO credit_balance(aid, credits) VALUES('` + attacker + `', 10)`,
		`INSERT INTO credit_settled(auth_id, payer, pay_to, amount, interaction_id, at) VALUES('ok-1', '` +
			victim + `', '` + attacker + `', 10, '', '` + at + `')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	heads, rows := auditSections(t, conn)
	conn.Close()
	if len(heads) != 13 { // 0, 1, 1b, 2 … 11
		t.Fatalf("%d sections, want 13: %q", len(heads), heads)
	}
	for _, n := range []string{"1", "1b", "2", "3", "4", "5", "6", "7", "8", "9"} {
		if got := rows[section(t, heads, n)]; len(got) != 0 {
			t.Errorf("clean hub: section %s lists %q", n, got)
		}
	}

	// What the bug wrote: a settlement of 2^64-1000 (stored -1000, the
	// attacker up and the victim down), a redemption of 2^64-1000 (the
	// redeemer credited), a peer receipt of 0, a negative discharge, a
	// negative debt, and the chain record of the redemption.
	for _, q := range []string{
		`INSERT INTO credit_settled(auth_id, payer, pay_to, amount, interaction_id, at) VALUES('ov-settle', '` +
			attacker + `', '` + victim + `', -1000, '', '` + at + `')`,
		`INSERT INTO credit_entry(aid, delta, reason, at) VALUES('` + attacker + `', 1000, 'ov-settle', '` + at + `')`,
		`INSERT INTO credit_entry(aid, delta, reason, at) VALUES('` + victim + `', -1000, 'ov-settle', '` + at + `')`,
		`INSERT INTO credit_redemption(auth_id, aid, amount, reference, at) VALUES('ov-redeem', '` +
			attacker + `', -1000, 'x', '` + at + `')`,
		`INSERT INTO credit_cleared(auth_id, peer_aid, pay_to, amount, at) VALUES('ov-clear', '` +
			peer + `', '` + victim + `', 0, '` + at + `')`,
		`INSERT INTO hub_cleared(auth_id, peer_aid, amount, at) VALUES('ov-discharge', '` + peer + `', -5, '` + at + `')`,
		`INSERT INTO hub_owed(peer_aid, amount) VALUES('` + peer + `', -1000)`,
		`UPDATE credit_balance SET credits = -910 WHERE aid = '` + victim + `'`,
		`INSERT INTO credit_issuance(seq, id, prev_id, kind, aid, amount, reason, at, record) VALUES(1, 'rec-1', 'g', ` +
			`'anet.credit.retired', '` + attacker + `', -1000, 'x', 1756684800000, x'00')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	conn, err = db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	heads, rows = auditSections(t, conn)
	for n, want := range map[string]string{
		"1": "ov-settle", "1b": attacker, "2": "ov-redeem", "3": "ov-clear", "4": "ov-discharge",
		"5": peer, "6": victim, "8": "anet.credit.retired", "9": attacker,
	} {
		got := strings.Join(rows[section(t, heads, n)], "\n")
		if !strings.Contains(got, want) {
			t.Errorf("section %s does not list %s:\n%s", n, want, got)
		}
	}
	if got := strings.Join(rows[section(t, heads, "9")], "\n"); !strings.Contains(got, victim) || !strings.Contains(got, peer) {
		t.Errorf("section 9 does not name the victim and the peer:\n%s", got)
	}
	// Read only: the script's PRAGMA holds on the connection it ran on.
	if _, err := conn.ExecContext(context.Background(), `DELETE FROM credit_settled`); err == nil {
		t.Error("a write succeeded on the connection the audit set query_only on")
	}
}
