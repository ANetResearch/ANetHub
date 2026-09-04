package federation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
)

// FED-2: hForward wrote the payload CID into the 7-day idempotency window
// before checking whether the destination AID was registered here. A
// forward that arrived before the recipient registered was refused with
// UNKNOWN_DESTINATION and still left the CID recorded, so the peer's later
// legitimate redelivery of the same bytes was answered 200 DUPLICATE and
// never queued — both hubs saw success and the message was lost.
func TestRefusedForwardLeavesNoIdempotencyTrace(t *testing.T) {
	r := newRig(t)
	env := signedEnvelope(t, r, func(e *Envelope, payload []byte) []byte {
		e.DestAID = "aid:carol" // not registered on B yet
		return payload
	})

	if code, out := postRaw(t, r, env); code != 404 || out["error"] != "UNKNOWN_DESTINATION" {
		t.Fatalf("forward for an unregistered AID must be refused: %d %v", code, out)
	}
	if got := r.bLocal.delivered(); len(got) != 0 {
		t.Fatalf("refused forward must not enqueue: %v", got)
	}

	// carol registers on B, then the peer redelivers the same envelope.
	r.bLocal.register("aid:carol")
	code, out := postRaw(t, r, env)
	if code != 202 {
		t.Fatalf("redelivery after registration must be accepted, got %d %v", code, out)
	}
	if got := r.bLocal.delivered(); len(got) != 1 || got[0] != "payload-bytes" {
		t.Fatalf("redelivery must actually reach the mailbox: %v", got)
	}
}

// The window must still close behind a forward that was accepted, or the
// FED-2 fix would trade a swallowed redelivery for a duplicated one.
func TestAcceptedForwardStillClosesTheWindow(t *testing.T) {
	r := newRig(t)
	env := signedEnvelope(t, r, nil) // dest aid:bob, registered on B

	if code, out := postRaw(t, r, env); code != 202 {
		t.Fatalf("first delivery must be accepted: %d %v", code, out)
	}
	code, out := postRaw(t, r, env)
	if code != 200 || out["status"] != "DUPLICATE" {
		t.Fatalf("second delivery of the same payload must be DUPLICATE: %d %v", code, out)
	}
	if got := r.bLocal.delivered(); len(got) != 1 {
		t.Fatalf("duplicate must not double-enqueue: %v", got)
	}
}

// The dedupe row and the kernel mailbox are separate stores, so the claim
// is taken first and released if the mailbox write fails. Without the
// release, a transient enqueue failure would poison the CID for seven days
// exactly the way an early-arriving forward used to.
func TestFailedEnqueueReleasesTheIdempotencyClaim(t *testing.T) {
	r := newRig(t)
	r.bLocal.setEnqueueErr(errors.New("mailbox unavailable"))
	env := signedEnvelope(t, r, nil)

	if code, out := postRaw(t, r, env); code != 500 {
		t.Fatalf("a failed enqueue must be reported as a failure: %d %v", code, out)
	}
	r.bLocal.setEnqueueErr(nil)
	code, out := postRaw(t, r, env)
	if code != 202 {
		t.Fatalf("retry after a failed enqueue must be accepted, got %d %v", code, out)
	}
	if got := r.bLocal.delivered(); len(got) != 1 || got[0] != "payload-bytes" {
		t.Fatalf("retry must reach the mailbox: %v", got)
	}
}

// The claim is taken before the mailbox write, not after, so two inbound
// forwards of one payload cannot both enqueue. The first request is held
// inside Enqueue while the second arrives; the second must be refused as a
// duplicate rather than queued a second time.
func TestConcurrentDuplicateEnqueuesOnce(t *testing.T) {
	r := newRig(t)
	// Released on every exit path: a parked request would otherwise keep
	// the test server's Close from returning and turn a failed assertion
	// into a hung package.
	release, entered := r.bLocal.holdFirstEnqueue()
	defer release()
	env := signedEnvelope(t, r, nil)

	first := make(chan int, 1)
	go func() { first <- postCode(r, env) }()
	<-entered // request 1 is inside the mailbox write

	code, out := postRaw(t, r, env)
	if code != 200 || out["status"] != "DUPLICATE" {
		t.Fatalf("concurrent duplicate must be refused as DUPLICATE: %d %v", code, out)
	}
	release()
	if code := <-first; code != 202 {
		t.Fatalf("first delivery must be accepted: %d", code)
	}
	if got := r.bLocal.delivered(); len(got) != 1 {
		t.Fatalf("concurrent duplicate must not double-enqueue: %v", got)
	}
}

// postCode is postRaw without the *testing.T, safe to call from a
// non-test goroutine (t.Fatal there is undefined behaviour).
func postCode(r *rig, env Envelope) int {
	b, _ := json.Marshal(env)
	resp, err := http.Post(r.bSrv.URL+"/fed/v1/forward", "application/json", bytes.NewReader(b))
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
