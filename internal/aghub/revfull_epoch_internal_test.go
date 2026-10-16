package aghub

import (
	"crypto/rand"
	"errors"
	"testing"
)

// RT-SSRC-14: after an owner replaced its mailbox key because the hub's
// revocation list was full (SS §4.3.8 item 4), the hub still holds the full
// list (revocations are not dropped when the epoch rises), so the next
// revocation is refused again.
func TestRevocationListFreedWhenTheEpochRises(t *testing.T) {
	h := newRelayHub(t)
	a := h.agent() // epoch 1
	now := h.clock().UnixMilli()
	tx, err := h.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxRevocationsPerOwner; i++ {
		id := make([]byte, 16)
		rand.Read(id)
		if _, err := tx.Exec(`INSERT INTO cap_revocation(owner, cap_id, revoked_at) VALUES(?,?,?)`, a.aid, id, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	one := func() [][]byte { id := make([]byte, 16); rand.Read(id); return [][]byte{id} }
	if _, _, err := h.store.RevokeCaps(a.aid, one()); !errors.Is(err, ErrRevocationListFull) {
		t.Fatalf("with a full list: %v", err)
	}
	h.publish(a, 2) // the daemon's answer to revocation_list_full: epoch + 1
	n, err := h.store.RevocationCount(a.aid)
	t.Logf("after the epoch rose to 2: %d revocations held (err %v)", n, err)
	_, _, err = h.store.RevokeCaps(a.aid, one())
	t.Logf("next revocation under epoch 2: %v", err)
	if errors.Is(err, ErrRevocationListFull) {
		t.Errorf("the list is still full after the mailbox key was replaced")
	}
}
