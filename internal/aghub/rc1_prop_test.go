package aghub

import (
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"
)

// P-PAY-4 (hub-payment-privacy §7.2): random times, including times up to
// MaxSkew in the future, random sweeps (the hub's clock jumping forward,
// and now and then back), and a valve that trips:
//
//  1. a time is accepted at most once for a signer, sweeps, clock steps
//     and the valve notwithstanding (after a sweep, nothing accepted
//     before is accepted again);
//  2. a time at or below the signer's floor is never accepted, and a
//     ts_stale names a floor at or above the time;
//  3. what a signer is told does not depend on how many other signers
//     there are or what they sign: no pool, no share (below the valve,
//     for any order of times);
//  4. a client handing out times from relayauth.MonoClock is never refused
//     with one request in flight, whatever the valve does, and with two in
//     flight needs at most one request signed again.
//
// Each property runs over many seeds; a failure names its seed.

const rc1PropSeeds = 300

// rc1PropAIDs are the signers of a run besides the noise.
var rc1PropAIDs = []string{"alpha", "bravo", "charlie", "delta"}

// floorOf is the floor a signer is held to now: its own, or its part's
// for a signer without state.
func (r *rc1State) floorOf(aid string) uint64 {
	sh := r.shard(aid)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if s := sh.signers[aid]; s != nil {
		return s.floor
	}
	return sh.gone
}

// Properties 1 and 2.
func TestRC1PropAtMostOnceAndNeverAtOrBelowTheFloor(t *testing.T) {
	for seed := uint64(0); seed < rc1PropSeeds; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewPCG(seed, 0x5243_3150))
			high, low := int64(rc1Big), int64(rc1Big)
			if rng.IntN(3) == 0 { // a valve that trips: a few signers' worth
				high = int64(300 + rng.IntN(1500))
				low = high * 7 / 8
			}
			shards := 1 + rng.IntN(4)
			now := rc1T0
			r := newRC1(now, shards, high, low)
			accepted := map[string]map[uint64]bool{}
			var all []struct {
				aid string
				ts  uint64
			}
			for step := 0; step < 400; step++ {
				switch x := rng.IntN(100); {
				case x < 6: // the clock jumps forward past the window
					now += relayauth.MaxSkewMillis + int64(rng.IntN(3*relayauth.MaxSkewMillis))
				case x < 8: // the clock steps back
					now -= int64(rng.IntN(2 * relayauth.MaxSkewMillis))
				case x < 40:
					now += int64(rng.IntN(20_000))
				}
				aid := rc1PropAIDs[rng.IntN(len(rc1PropAIDs))]
				if rng.IntN(5) == 0 {
					aid = fmt.Sprint("noise", rng.IntN(40))
				}
				var ts uint64
				switch x := rng.IntN(100); {
				case x < 15 && len(all) > 0: // a replay of something accepted lately,
					// still above its signer's floor unless the valve raised it
					p := all[len(all)-1-rng.IntN(min(len(all), 16))]
					aid, ts = p.aid, p.ts
				case x < 30 && len(all) > 0: // a replay of anything accepted
					p := all[rng.IntN(len(all))]
					aid, ts = p.aid, p.ts
				case x < 40: // at or around the floor
					ts = r.floorOf(aid) + uint64(rng.IntN(3)) - 1
				case x < 55: // up to MaxSkew in the future
					ts = uint64(now) + uint64(rng.IntN(relayauth.MaxSkewMillis+1))
				default: // around now, sometimes outside the window
					ts = uint64(now + int64(rng.IntN(2*relayauth.MaxSkewMillis+20_000)) - relayauth.MaxSkewMillis - 10_000)
				}
				k := []int{1, 2, rc1KNew, rc1KAgent}[rng.IntN(4)]
				floor := r.floorOf(aid)
				v, told := r.accept(aid, ts, k, now)
				switch v {
				case rc1Accepted:
					if accepted[aid][ts] {
						t.Fatalf("step %d: %s's time %d accepted a second time (now %d)", step, aid, ts, now)
					}
					if ts <= floor {
						t.Fatalf("step %d: %s's time %d accepted at or below its floor %d", step, aid, ts, floor)
					}
					if accepted[aid] == nil {
						accepted[aid] = map[uint64]bool{}
					}
					accepted[aid][ts] = true
					all = append(all, struct {
						aid string
						ts  uint64
					}{aid, ts})
				case rc1Stale:
					if told < ts {
						t.Fatalf("step %d: ts_stale for %d named the floor %d below it", step, ts, told)
					}
				case rc1Replayed:
					if !accepted[aid][ts] {
						t.Fatalf("step %d: %s's time %d called replayed but never accepted", step, aid, ts)
					}
				case rc1Outside:
					if rc1InWindow(ts, now) {
						t.Fatalf("step %d: %d called outside the window at %d", step, ts, now)
					}
				}
			}
			// After every signer's state could have gone: everything
			// accepted is refused, at any hub time, the past included.
			for _, back := range []int64{now + 3*relayauth.MaxSkewMillis, rc1T0} {
				r.accept("sweeper", uint64(now+3*relayauth.MaxSkewMillis), rc1KAgent, now+3*relayauth.MaxSkewMillis)
				for i := range r.shards {
					sh := &r.shards[i]
					sh.mu.Lock()
					r.sweepLocked(sh, now+3*relayauth.MaxSkewMillis)
					sh.mu.Unlock()
				}
				for _, p := range all {
					if v, _ := r.accept(p.aid, p.ts, rc1KAgent, back); v == rc1Accepted {
						t.Fatalf("%s's time %d accepted again at %d after its state went", p.aid, p.ts, back)
					}
				}
			}
		})
	}
}

// Property 3: one signer's verdicts are the same alone and among others,
// whatever the others sign, below the valve. One part, so that every
// signer shares the lock and the map.
func TestRC1PropASignerIsJudgedOnItsOwnTimesOnly(t *testing.T) {
	for seed := uint64(0); seed < rc1PropSeeds; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewPCG(seed, 0x5243_3151))
			k := []int{rc1KNew, rc1KAgent}[rng.IntN(2)]
			now := rc1T0 + 100_000
			type req struct {
				ts  uint64
				now int64
			}
			var own []req
			for i := 0; i < 150; i++ {
				now += int64(rng.IntN(800))
				// Out of order inside W and a little past it, sometimes
				// repeated: everything a client in a hurry sends.
				ts := uint64(now) - uint64(rng.IntN(rc1W+5_000))
				if i > 0 && rng.IntN(10) == 0 {
					ts = own[rng.IntN(len(own))].ts
				}
				own = append(own, req{ts, now})
			}
			alone := newRC1(rc1T0, 1, rc1Big, rc1Big)
			crowd := newRC1(rc1T0, 1, rc1Big, rc1Big)
			others := 1 + rng.IntN(200)
			for i, q := range own {
				for j := 0; j < 1+rng.IntN(8); j++ {
					o := fmt.Sprint("other", rng.IntN(others))
					crowd.accept(o, uint64(q.now)-uint64(rng.IntN(rc1W))+uint64(rng.IntN(relayauth.MaxSkewMillis)),
						[]int{1, rc1KNew, rc1KAgent, rc1KPeerHub}[rng.IntN(4)], q.now)
				}
				va, fa := alone.accept("me", q.ts, k, q.now)
				vc, fc := crowd.accept("me", q.ts, k, q.now)
				if va != vc || fa != fc {
					t.Fatalf("request %d (ts %d): alone %d (floor %d), among %d others %d (floor %d)",
						i, q.ts, va, fa, others, vc, fc)
				}
			}
		})
	}
}

// Property 4: a MonoClock client among a crowd that keeps the valve
// tripping. With one request in flight it is never refused; with two in
// flight a ts_stale is answered by raising the clock and signing again,
// which is accepted.
func TestRC1PropAMonoClockClientIsNeverStuck(t *testing.T) {
	for seed := uint64(0); seed < rc1PropSeeds; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewPCG(seed, 0x5243_3152))
			now := rc1T0 + 100_000
			r := newRC1(rc1T0, 1+rng.IntN(8), int64(3000+rng.IntN(5000)), int64(1500+rng.IntN(1000)))
			var clock relayauth.MonoClock
			const hub = "hub"
			k := []int{rc1KNew, rc1KAgent}[rng.IntN(2)]
			var inFlight []uint64
			for i := 0; i < 300; i++ {
				now += int64(rng.IntN(300))
				for j := 0; j < rng.IntN(12); j++ {
					o := fmt.Sprint("crowd", rng.IntN(300))
					r.accept(o, uint64(now)-uint64(rng.IntN(rc1W))+uint64(rng.IntN(60_000)), rc1KAgent, now)
				}
				two := rng.IntN(2) == 0
				inFlight = append(inFlight[:0], uint64(clock.Next(hub, now)))
				if two {
					inFlight = append(inFlight, uint64(clock.Next(hub, now)))
					if rng.IntN(2) == 0 { // the later one arrives first
						inFlight[0], inFlight[1] = inFlight[1], inFlight[0]
					}
				}
				for n, ts := range inFlight {
					v, floor := r.accept("me", ts, k, now)
					if v == rc1Accepted {
						continue
					}
					if v != rc1Stale || !two || n == 0 {
						t.Fatalf("request %d.%d (ts %d, two in flight %v): verdict %d", i, n, ts, two, v)
					}
					if !clock.Raise(hub, int64(floor), now) {
						t.Fatalf("request %d.%d: the floor %d was not adopted at %d", i, n, floor, now)
					}
					again := uint64(clock.Next(hub, now))
					if v, f := r.accept("me", again, k, now); v != rc1Accepted {
						t.Fatalf("request %d.%d signed again at %d: verdict %d (floor %d)", i, n, again, v, f)
					}
				}
			}
		})
	}
}

// FuzzRC1 drives one RC1 state with operations read from the input (who
// signs, which time, how the hub clock moves, which K, how small the
// valve) and checks after each one: a time is accepted at most once per
// signer and never at or below the floor that held before; replayed is said
// only of an accepted time; a ts_stale names a floor at or above the time;
// every signer's recent times are ascending, above its floor and at most
// the largest K it was given; and the state's byte count is the sum of its
// signers'.
func FuzzRC1(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte("\x01\x10\x00\x00\x02\x00\x01\x00\x01\x10\x00\x00\x02\x00\x01\x00\x02\xff\xff\xff\x00\x10\x03\x01"))
	f.Add([]byte("\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x08\x80\x80\x02\x02\x00\x00\x00\x10\x00\x00\x00\x00"))
	// A valve that cannot get low says so once per state; with a state per
	// input that is a line per input.
	prev := log.Writer()
	log.SetOutput(io.Discard)
	f.Cleanup(func() { log.SetOutput(prev) })
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) < 1 {
			return
		}
		valve := int64(in[0]) * 64
		if valve == 0 {
			valve = rc1Big
		}
		in = in[1:]
		r := newRC1(rc1T0, 3, valve, valve*7/8)
		now := rc1T0
		accepted := map[string]map[uint64]bool{}
		maxK := map[string]int{}
		for len(in) >= 8 {
			op := in[:8]
			in = in[8:]
			aid := fmt.Sprint("s", op[0]%6)
			// ts: now plus a signed offset of up to about ±8.4 minutes
			off := int64(int32(uint32(op[1])<<24|uint32(op[2])<<16|uint32(op[3])<<8)) >> 14
			ts := uint64(now + off)
			if op[0]&0x80 != 0 { // the floor itself, or just above it
				ts = r.floorOf(aid) + uint64(op[0]>>6&1)
			}
			k := []int{1, 2, 3, rc1KNew, rc1KAgent, rc1KPeerHub}[int(op[4])%6]
			maxK[aid] = max(maxK[aid], k)
			floor := r.floorOf(aid)
			v, told := r.accept(aid, ts, k, now)
			switch v {
			case rc1Accepted:
				if accepted[aid][ts] || ts <= floor {
					t.Fatalf("%s's time %d accepted again or at or below the floor %d", aid, ts, floor)
				}
				if accepted[aid] == nil {
					accepted[aid] = map[uint64]bool{}
				}
				accepted[aid][ts] = true
			case rc1Replayed:
				if !accepted[aid][ts] {
					t.Fatalf("%s's time %d called replayed but never accepted", aid, ts)
				}
			case rc1Stale:
				if told < ts {
					t.Fatalf("ts_stale for %d named the floor %d", ts, told)
				}
			}
			// the hub clock: forward by up to about 9 minutes, now and then back
			dt := int64(int16(uint16(op[5])<<8|uint16(op[6]))) * 16
			if op[7]&3 != 0 && dt < 0 {
				dt = -dt
			}
			now += dt
			var sum int64
			for i := range r.shards {
				sh := &r.shards[i]
				sh.mu.Lock()
				for a, s := range sh.signers {
					sum += signerBytes(a, s)
					if !slices.IsSorted(s.recent) || len(s.recent) > maxK[a] || (len(s.recent) > 0 && s.recent[0] <= s.floor) {
						t.Fatalf("%s: recent %v, floor %d, K up to %d", a, s.recent, s.floor, maxK[a])
					}
				}
				sh.mu.Unlock()
			}
			if got := r.bytes.Load(); got != sum {
				t.Fatalf("the state counts %d bytes, its signers hold %d", got, sum)
			}
		}
	})
}
