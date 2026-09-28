package aghub_test

import (
	"fmt"
	"strings"
	"testing"
)

// SI-2 over the whole store: a send adds no row, in any table, that names
// its sender. TestTheRelayDoesNotStoreTheSender checks the relay table's
// columns and rows; a sender kept anywhere else (a meta row, a log table,
// a counter keyed by sender) is the same social graph in another place.
// Found by mutation: the handler writing the sender of each queued
// envelope into hub_meta left every other relay test green (0026).
func TestASendLeavesTheSenderInNoTable(t *testing.T) {
	dir := t.TempDir()
	srv, _, _ := newHubAt(t, dir)
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	before := rowsNaming(t, dir, sender.AID())
	for i := 0; i < 3; i++ {
		if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), []byte{byte(i)})); code != 200 {
			t.Fatalf("send %d: %d %s", i, code, b)
		}
	}
	after := rowsNaming(t, dir, sender.AID())
	if len(after) == 0 {
		t.Fatal("no row names the sender at all; the search is not reading the store")
	}
	for row := range after {
		if !before[row] {
			t.Errorf("a send left a row naming its sender: %.200s", row)
		}
	}
}

// rowsNaming reads every table of the hub database and returns each row in
// which some column contains aid, as "table: v1|v2|…".
func rowsNaming(t *testing.T, dir, aid string) map[string]bool {
	t.Helper()
	db := openDB(t, dir)
	names, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for names.Next() {
		var n string
		if err := names.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	names.Close()
	out := map[string]bool{}
	for _, tb := range tables {
		rows, err := db.Query(`SELECT * FROM "` + strings.ReplaceAll(tb, `"`, `""`) + `"`)
		if err != nil {
			t.Fatalf("read %s: %v", tb, err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatalf("read %s: %v", tb, err)
			}
			parts := make([]string, len(vals))
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					parts[i] = string(b)
				} else {
					parts[i] = fmt.Sprint(v)
				}
			}
			if line := strings.Join(parts, "|"); strings.Contains(line, aid) {
				out[tb+": "+line] = true
			}
		}
		rows.Close()
	}
	return out
}
