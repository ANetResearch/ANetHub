package aghub

import (
	"crypto/rand"
	"testing"
	"time"
)

// RT-SSRC-2: /relay/status is anonymous, so RelayStatus must not take the
// database write lock. With another writer holding it, a status check of
// rows that need no cut still answers at once.
func TestRelayStatusTakesNoWriteLock(t *testing.T) {
	h := newRelayHub(t)
	items := make([]StatusItem, 8)
	for i := range items {
		items[i] = StatusItem{RID: make([]byte, 16), Handle: make([]byte, 16)}
		rand.Read(items[i].RID)
		rand.Read(items[i].Handle)
	}
	hold, err := h.store.db.Begin() // IMMEDIATE: holds the write lock
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	done := make(chan error, 1)
	go func() { _, err := h.store.RelayStatus(items); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RelayStatus waits for the write lock")
	}
}
