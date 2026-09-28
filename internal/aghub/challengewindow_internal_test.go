package aghub

import (
	"encoding/base64"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
)

// The wire-1 challenge the task board authenticates with is accepted only
// within relayauth.MaxSkewMillis of the hub's clock. The window was
// computed as |int64(now) - int64(ts)|, which overflows for a ts 2^63
// away: at ts = now + 2^63 the difference is math.MinInt64, its negation
// is itself, and "skew > MaxSkew" was false, so a challenge dated 2^63 ms
// from now was accepted (FuzzTaskboardChallengeTime, cd72ed938e6a0969,
// ANet docs/notes/0033). verifyV2 and the federation key lookup already
// refuse a ts above 2^62 for this reason; the challenge now does too.
func TestAChallengeDatedHalfTheClockAwayIsRefused(t *testing.T) {
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	const now = uint64(1_790_000_000_000)
	sign := func(ts uint64) string {
		sig, _ := c.Sign(relayauth.Preimage("task.create", c.AID(), ts))
		return base64.StdEncoding.EncodeToString(sig)
	}
	for _, ts := range []uint64{now + 1<<63, now + 1<<63 + 1, now + 1<<62 + 1, now - relayauth.MaxSkewMillis - 1,
		now + relayauth.MaxSkewMillis + 1} {
		if err := verifyChallengeAt(c.KEL(), "task.create", c.AID(), ts, 0, sign(ts), now); err == nil {
			t.Errorf("a challenge dated %d was accepted at %d", ts, now)
		}
	}
	for _, ts := range []uint64{now, now - relayauth.MaxSkewMillis, now + relayauth.MaxSkewMillis} {
		if err := verifyChallengeAt(c.KEL(), "task.create", c.AID(), ts, 0, sign(ts), now); err != nil {
			t.Errorf("a challenge dated %d was refused at %d: %v", ts, now, err)
		}
	}
}
