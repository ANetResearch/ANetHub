package aghub

import (
	"errors"
	"testing"
)

// The relayauth v2 replay cache refuses a signature it has seen within its
// window, refuses new signatures when it is full of live entries (the
// caller answers 503) instead of evicting one, and frees expired entries
// at a sweep. While full, it sweeps at most once a second, so a stream of
// refused requests does not each walk the whole cache.
func TestTheReplayCacheIsBoundedAndSweptAtMostOnceASecondWhenFull(t *testing.T) {
	c := newReplayCache(2)
	now := int64(5_000_000)
	if err := c.admit("aid-a", []byte("sig-1"), now+10, now); err != nil {
		t.Fatal(err)
	}
	if err := c.admit("aid-a", []byte("sig-1"), now+10, now+5); !errors.Is(err, errReplayed) {
		t.Fatalf("the same signature again inside its window: %v, want errReplayed", err)
	}
	// Another signer with the same signature bytes is a different entry.
	if err := c.admit("aid-b", []byte("sig-1"), now+5000, now); err != nil {
		t.Fatalf("another signer: %v", err)
	}
	if err := c.admit("aid-a", []byte("sig-2"), now+5000, now); !errors.Is(err, errReplayCacheFull) {
		t.Fatalf("a new signature into a full cache: %v, want errReplayCacheFull", err)
	}
	// aid-a/sig-1 expired at now+10, but the last sweep was at now.
	if err := c.admit("aid-a", []byte("sig-2"), now+5000, now+20); !errors.Is(err, errReplayCacheFull) {
		t.Fatalf("within a second of the last sweep: %v, want errReplayCacheFull", err)
	}
	if err := c.admit("aid-a", []byte("sig-2"), now+5000, now+1001); err != nil {
		t.Fatalf("after the next sweep: %v", err)
	}
}
