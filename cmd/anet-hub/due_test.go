package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// owe makes the hub in dir owe peer amount (hub_due), as forwarded
// settlements would have.
func owe(t *testing.T, dir, peer string, amount int64) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO hub_due(peer_aid, amount) VALUES(?,?)
		ON CONFLICT(peer_aid) DO UPDATE SET amount = amount + excluded.amount`, peer, amount); err != nil {
		t.Fatal(err)
	}
}

// anet-hub due (hub-payment-privacy PAY-U2) lists what this hub owes, by
// peer hub, one per line as data (AID, tab, credits), in AID order; nothing
// owed prints nothing; --json gives the same as a list. A debt paid down to
// 0 is not listed.
func TestDueListsWhatThisHubOwesByPeer(t *testing.T) {
	dir := hubDir(t)
	expectOut(t, cli(t, "en", "-data", dir, "due"), "")
	expectOut(t, cli(t, "en", "-data", dir, "due", "--json"), "[]\n")
	_, p1 := newAID(t)
	_, p2 := newAID(t)
	if p2 < p1 {
		p1, p2 = p2, p1
	}
	owe(t, dir, p2, 7)
	owe(t, dir, p1, 120)
	_, p3 := newAID(t)
	owe(t, dir, p3, 0)
	for _, lang := range []string{"en", "zh"} {
		expectOut(t, cli(t, lang, "-data", dir, "due"), p1+"\t120\n"+p2+"\t7\n")
	}
	expectOut(t, cli(t, "en", "due", "--json", "--data", dir),
		"[\n  {\n    \"peer\": \""+p1+"\",\n    \"amount\": 120\n  },\n  {\n    \"peer\": \""+p2+"\",\n    \"amount\": 7\n  }\n]\n")
	// The usage line for anything else; a directory with no hub says so.
	if r := cli(t, "en", "-data", dir, "due", "extra"); r.code != 2 || r.stderr != "usage: anet-hub due [--json]\n" {
		t.Errorf("due with an argument: %+v", r)
	}
	missing := filepath.Join(t.TempDir(), "none")
	expectErr(t, cli(t, "en", "-data", missing, "due"), 1, sentenceOf("en", "data.missing", map[string]string{"path": missing}))
}
