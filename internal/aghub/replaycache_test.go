package aghub

import (
	"errors"
	"fmt"
	"testing"
)

// size is the number of live entries and of signers holding them.
func (c *replayCache) size() (entries, signers int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.expiry), len(c.signers)
}

// The relayauth v2 replay cache refuses a signature it has seen within its
// window, keys entries by signer and signature, and lets an entry go as
// soon as its window has ended: no sweep interval stands between an
// expired entry and the room it frees.
func TestTheReplayCacheRefusesARepeatAndDropsEntriesAsTheyExpire(t *testing.T) {
	c := newReplayCache(2, 2)
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
		t.Fatalf("a new signature from a signer at its even share of a full cache: %v, want errReplayCacheFull", err)
	}
	// aid-a/sig-1 expired at now+10: it is gone at once, and so is aid-a.
	if err := c.admit("aid-a", []byte("sig-2"), now+5000, now+20); err != nil {
		t.Fatalf("after aid-a's entry expired: %v", err)
	}
	if n, signers := c.size(); n != 2 || signers != 2 {
		t.Fatalf("cache holds %d entries of %d signers, want 2 of 2", n, signers)
	}
	c.expire(now + 5001)
	if n, signers := c.size(); n != 0 || signers != 0 {
		t.Fatalf("after every window ended the cache holds %d entries of %d signers", n, signers)
	}
}

// [redteam:F4] One signer fills its own share of the cache and no more:
// past perSigner live entries it alone is refused (errReplaySignerFull,
// 429), and another signer is admitted as before. Once its own entries
// expire, it is admitted again.
func TestOneSignerFillsOnlyItsOwnShareOfTheReplayCache(t *testing.T) {
	c := newReplayCache(1000, 4)
	now := int64(5_000_000)
	for i := 0; i < 4; i++ {
		if err := c.admit("attacker", []byte(fmt.Sprint("sig-", i)), now+600_000, now); err != nil {
			t.Fatalf("attacker %d: %v", i, err)
		}
	}
	if err := c.admit("attacker", []byte("sig-4"), now+600_000, now); !errors.Is(err, errReplaySignerFull) {
		t.Fatalf("attacker past its share: %v, want errReplaySignerFull", err)
	}
	if err := c.admit("victim", []byte("sig-0"), now+300_000, now); err != nil {
		t.Fatalf("another signer after one filled its share: %v", err)
	}
	if err := c.admit("attacker", []byte("sig-4"), now+600_000, now+600_001); err != nil {
		t.Fatalf("attacker after its entries expired: %v", err)
	}
}

// [redteam:F4] When all signers together fill the cache, only those that
// hold at least an even share are refused (errReplayCacheFull, 503); a
// signer below it is admitted. The cache used to refuse everyone at its
// bound, so whoever kept it full stopped every signed request on the hub.
func TestAFullReplayCacheRefusesOnlySignersHoldingAnEvenShare(t *testing.T) {
	c := newReplayCache(8, 100)
	now := int64(5_000_000)
	for i := 0; i < 8; i++ {
		if err := c.admit("attacker", []byte(fmt.Sprint("sig-", i)), now+600_000, now); err != nil {
			t.Fatalf("attacker %d: %v", i, err)
		}
	}
	if err := c.admit("attacker", []byte("sig-8"), now+600_000, now); !errors.Is(err, errReplayCacheFull) {
		t.Fatalf("attacker into the full cache it filled: %v, want errReplayCacheFull", err)
	}
	// Two signers: an even share is 4. The victim is admitted up to it.
	for i := 0; i < 4; i++ {
		if err := c.admit("victim", []byte(fmt.Sprint("sig-", i)), now+300_000, now); err != nil {
			t.Fatalf("victim %d into a cache someone else filled: %v", i, err)
		}
	}
	if err := c.admit("victim", []byte("sig-4"), now+300_000, now); !errors.Is(err, errReplayCacheFull) {
		t.Fatalf("victim at an even share of a full cache: %v, want errReplayCacheFull", err)
	}
	// A third signer is below an even share (8/3 = 2) and is admitted.
	if err := c.admit("third", []byte("sig-0"), now+300_000, now); err != nil {
		t.Fatalf("a third signer: %v", err)
	}
	// The total passed max only by signers below an even share.
	if n, _ := c.size(); n != 13 {
		t.Fatalf("cache holds %d entries, want 13", n)
	}
	// A bound below the number of signers still leaves each one entry.
	d := newReplayCache(1, 100)
	if err := d.admit("a", []byte("s"), now+10, now); err != nil {
		t.Fatal(err)
	}
	if err := d.admit("b", []byte("s"), now+10, now); err != nil {
		t.Fatalf("a signer holding nothing, cache full: %v", err)
	}
}

// The per-signer bound leaves room for what the send bucket alone lets a
// sender sign, so raising -relay-send-rate does not turn a sender's own
// sends into replay-cache refusals.
func TestThePerSignerBoundCoversTheSendBucket(t *testing.T) {
	l := DefaultLimits()
	if got := replayPerSignerFor(l); got != defaultReplayPerSigner {
		t.Fatalf("default limits: per-signer bound %d, want %d", got, defaultReplayPerSigner)
	}
	l.SendRate = 200
	if got, sends := replayPerSignerFor(l), 200*600; got < sends {
		t.Fatalf("send rate 200/s: per-signer bound %d, below the %d sends of a 10-minute window", got, sends)
	}
}
