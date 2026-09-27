package admin

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
)

// An operator delete takes the agent's A2A card and its skill and tag
// index rows with the agent row, and leaves every other agent's alone
// (hub brief 05 H2: DeleteAgent used to leave orphan rows behind).
func TestDeleteAgentRemovesTheA2ACardAndItsIndexes(t *testing.T) {
	dir, provAID, reqAID := buildHubDB(t)
	db := a2aRowsFor(t, dir, provAID, reqAID)
	hub, err := OpenHubDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	if err := hub.DeleteAgent(provAID); err != nil {
		t.Fatal(err)
	}
	checkA2ARows(t, db, map[string]int{provAID: 0, reqAID: 1})
	// A delete of an AID that is not registered still says so and removes
	// nothing.
	if err := hub.DeleteAgent("bafyunknown"); err == nil {
		t.Error("deleting an unknown AID reported success")
	}
}

// The keep-list prune removes agent rows in bulk; the A2A rows of every
// pruned agent go with them.
func TestPruneRemovesTheA2ACardsOfPrunedAgents(t *testing.T) {
	dir, provAID, reqAID := buildHubDB(t)
	db := a2aRowsFor(t, dir, provAID, reqAID)
	if _, _, removed, err := PruneAgentsExcept(dir, []string{reqAID}); err != nil || removed != 1 {
		t.Fatalf("prune: removed %d, %v", removed, err)
	}
	checkA2ARows(t, db, map[string]int{provAID: 0, reqAID: 1})
}

// a2aRowsFor writes, for each aid, rows as admission writes them (the card
// bytes are irrelevant here) and returns a handle on hub.db.
func a2aRowsFor(t *testing.T, dir string, aids ...string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, aid := range aids {
		for _, q := range []string{
			`INSERT INTO agent_a2a_card(aid, card, stored_at, verified_at) VALUES(?, '{}', 'now', 'now')`,
			`INSERT INTO agent_skill(aid, skill_id, name) VALUES(?, 'echo', 'Echo')`,
			`INSERT INTO agent_tag(aid, tag) VALUES(?, 'text')`,
		} {
			if _, err := db.Exec(q, aid); err != nil {
				t.Fatal(err)
			}
		}
	}
	return db
}

// checkA2ARows asserts how many rows each A2A table holds per aid.
func checkA2ARows(t *testing.T, db *sql.DB, want map[string]int) {
	t.Helper()
	for _, table := range []string{"agent_a2a_card", "agent_skill", "agent_tag"} {
		for aid, n := range want {
			var got int
			if err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE aid=?`, aid).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != n {
				t.Errorf("%s has %d rows for %s, want %d", table, got, aid, n)
			}
		}
	}
}

// An operator delete of an agent whose A2A card federates puts a
// withdrawal on the hub's /fed/v2/cards stream, after every entry already
// there, so a peer that learned the card delists it; a hub-local agent's
// delete names nothing on the stream. The same for the keep-list prune.
func TestAnOperatorDeleteWithdrawsAFederatedA2ACard(t *testing.T) {
	for _, prune := range []bool{false, true} {
		dir, provAID, reqAID := buildHubDB(t)
		db := a2aRowsFor(t, dir, provAID, reqAID)
		for _, q := range []struct {
			sql string
			arg []any
		}{
			{`UPDATE agent SET visibility=? WHERE aid=?`, []any{aghub.VisibilityFederated, provAID}},
			{`UPDATE agent_a2a_card SET fed_seq=5 WHERE aid=?`, []any{provAID}},
			{`UPDATE agent_a2a_card SET fed_seq=6 WHERE aid=?`, []any{reqAID}},
		} {
			if _, err := db.Exec(q.sql, q.arg...); err != nil {
				t.Fatal(err)
			}
		}
		if prune {
			if _, _, _, err := PruneAgentsExcept(dir, []string{"bafykeep"}); err != nil {
				t.Fatal(err)
			}
		} else {
			hub, err := OpenHubDB(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, aid := range []string{provAID, reqAID} {
				if err := hub.DeleteAgent(aid); err != nil {
					t.Fatal(err)
				}
			}
			hub.Close()
		}
		hs, err := aghub.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		entries, _, err := hs.A2ACardsSince(0, 100, "https://hub.example")
		hs.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Format != federation.FormatWithdrawal || entries[0].FedSeq != 7 ||
			!strings.Contains(string(entries[0].Card), provAID) {
			t.Fatalf("prune=%v: the stream after the delete: %+v", prune, entries)
		}
	}
}
