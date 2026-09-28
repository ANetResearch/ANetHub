package aghub_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// RelayEnqueue reads the recipient's quota and then inserts, in one
// transaction. Begun deferred, that transaction starts as a reader and must
// upgrade to a writer at the INSERT; if another connection wrote in between
// — SeenPolling marks every poll, outside the store mutex — SQLite answers
// SQLITE_BUSY_SNAPSHOT (517), or SQLITE_BUSY at once without waiting on
// busy_timeout, since waiting could deadlock. /relay/send then answered 500
// and a federation forward 502 "database is locked": the lab soak (ANet
// docs/notes/0036 F2) saw eleven in four hours on two hubs, every one
// retried by the sender's outbox. Transactions begin IMMEDIATE, taking the
// write lock up front, where busy_timeout does apply.
func TestRelayEnqueueSurvivesConcurrentWriters(t *testing.T) {
	s, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const to = "bafyreirecipientforbusytest"
	env := testEnvelope(t, to, nil)

	stop := make(chan struct{})
	var writers sync.WaitGroup
	for i := 0; i < 4; i++ { // agents polling: a write per poll, outside s.mu
		writers.Add(1)
		go func() {
			defer writers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.SeenPolling(to)
				}
			}
		}()
	}
	var failed atomic.Int32
	var first atomic.Value
	var senders sync.WaitGroup
	deadline := time.Now().Add(3 * time.Second)
	for i := 0; i < 8; i++ {
		senders.Add(1)
		go func() {
			defer senders.Done()
			for time.Now().Before(deadline) {
				id, err := s.RelayEnqueue(to, env)
				if err != nil {
					if failed.Add(1) == 1 {
						first.Store(err.Error())
					}
					continue
				}
				if _, err := s.RelayAck(to, []int64{id}); err != nil {
					if failed.Add(1) == 1 {
						first.Store("ack: " + err.Error())
					}
				}
			}
		}()
	}
	senders.Wait()
	close(stop)
	writers.Wait()
	if n := failed.Load(); n > 0 {
		t.Fatalf("%d relay writes failed under concurrent polling, first: %v", n, first.Load())
	}
}
