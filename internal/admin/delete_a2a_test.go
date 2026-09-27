package admin

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// An operator delete takes the agent's A2A card and its skill and tag
// index rows with the agent row, and leaves every other agent's alone
// (hub brief 05 H2: DeleteAgent used to leave orphan rows behind).
func TestDeleteAgentRemovesTheA2ACardAndItsIndexes(t *testing.T) {
	dir, provAID, reqAID := buildHubDB(t)
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Rows as admission writes them; the card bytes are irrelevant here.
	for _, aid := range []string{provAID, reqAID} {
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
	hub, err := OpenHubDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	if err := hub.DeleteAgent(provAID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"agent_a2a_card", "agent_skill", "agent_tag"} {
		for aid, want := range map[string]int{provAID: 0, reqAID: 1} {
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE aid=?`, aid).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != want {
				t.Errorf("%s has %d rows for %s after deleting %s, want %d", table, n, aid, provAID, want)
			}
		}
	}
	// A delete of an AID that is not registered still says so and removes
	// nothing.
	if err := hub.DeleteAgent("bafyunknown"); err == nil {
		t.Error("deleting an unknown AID reported success")
	}
}
