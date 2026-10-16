package aghub_test

import (
	"testing"
	"time"
)

// An agent that is registered here and also has a card from a peer hub is one
// entry of the merged directory, not two: max_bits is computed from the
// number of agents, so counting it twice would make the buckets too narrow
// (sealed-sender SSR-H18, SSR-W18).
func TestMaxBitsCountsALocalAgentWithAPeerCardOnce(t *testing.T) {
	_, store, agents := dirHubWith(t, 90)
	before, err := store.DirMaxBits()
	if err != nil {
		t.Fatal(err)
	}
	db := store.DBForTest()
	for _, c := range agents {
		if _, err := db.Exec(`INSERT INTO fed_a2a_card(aid, seq, payload_hash, card, kel, keys, home, peer_aid, verified_at, stored_at)
		    VALUES(?, 1, x'00', '{}', x'00', x'00', 'https://peer.example', 'peer', ?, ?)`,
			c.AID(), time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	store.ForgetDirMaxBitsForTest()
	after, err := store.DirMaxBits()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("max_bits %d with 90 local agents, %d once a peer holds a card of each of them", before, after)
	}
}
