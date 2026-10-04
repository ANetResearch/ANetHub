package aghub

import (
	"fmt"
	"slices"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"
)

// RC1 (hub-payment-privacy §4.2.5) at the level of the state: the verdict
// of each signed time, the floor, the recent set, K, the sweep and the
// valve. rc1_prop_test.go has the random properties (P-PAY-4); the HTTP
// face is in rc1_relay_test.go.

// rc1Big is a valve no test of the rules below reaches.
const rc1Big = 1 << 40

// rc1T0 is a hub time (ms) the tests start at, well past the epoch so that
// now − MaxSkew is positive.
const rc1T0 = int64(1_790_000_000_000)

// view is one signer's state, or zeros when it has none.
func (r *rc1State) view(aid string) (floor, maxSeen uint64, recent []uint64, ok bool) {
	sh := r.shard(aid)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	s := sh.signers[aid]
	if s == nil {
		return 0, 0, nil, false
	}
	return s.floor, s.maxSeen, slices.Clone(s.recent), true
}

// signers is the number of signers holding state.
func (r *rc1State) signerCount() int {
	n := 0
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		n += len(sh.signers)
		sh.mu.Unlock()
	}
	return n
}

func mustAccept(t *testing.T, r *rc1State, aid string, ts uint64, k int, now int64) {
	t.Helper()
	if v, floor := r.accept(aid, ts, k, now); v != rc1Accepted {
		t.Fatalf("%s ts %d at %d: verdict %d (floor %d), want accepted", aid, ts, now, v, floor)
	}
}

// PAY-R2 and PAY-R5: a time is accepted once; a time at or below the floor
// is stale and the answer says the floor; times may arrive out of order by
// up to W; the floor follows the largest time at W.
func TestRC1AcceptsEachTimeOnceAndFollowsTheLargestAtW(t *testing.T) {
	r := newRC1(rc1T0, 4, rc1Big, rc1Big)
	now := rc1T0 + 100_000
	t1 := uint64(now)
	mustAccept(t, r, "a", t1, rc1KAgent, now)
	if v, _ := r.accept("a", t1, rc1KAgent, now); v != rc1Replayed {
		t.Fatalf("the same time again: verdict %d, want replayed", v)
	}
	// Out of order, inside W: accepted, once.
	mustAccept(t, r, "a", t1-rc1W+1, rc1KAgent, now)
	if v, _ := r.accept("a", t1-rc1W+1, rc1KAgent, now); v != rc1Replayed {
		t.Fatalf("the out-of-order time again: verdict %d, want replayed", v)
	}
	// At maxSeen − W: the floor.
	if v, floor := r.accept("a", t1-rc1W, rc1KAgent, now); v != rc1Stale || floor != t1-rc1W {
		t.Fatalf("a time at the floor: verdict %d floor %d, want stale with floor %d", v, floor, t1-rc1W)
	}
	// A later time moves the floor and drops what fell below it.
	t2 := t1 + 20_000
	mustAccept(t, r, "a", t2, rc1KAgent, now)
	floor, maxSeen, recent, _ := r.view("a")
	if floor != t2-rc1W || maxSeen != t2 || !slices.Equal(recent, []uint64{t1, t2}) {
		t.Fatalf("state after %d: floor %d maxSeen %d recent %v, want %d, %d, [%d %d]",
			t2, floor, maxSeen, recent, t2-rc1W, t2, t1, t2)
	}
	// Another signer's times are its own.
	mustAccept(t, r, "b", t1, rc1KAgent, now)
	mustAccept(t, r, "b", t1-rc1W+1, rc1KAgent, now)
}

// PAY-R5 step 4: past K times the floor rises to the smallest; K is the
// signer's class (core G17).
func TestRC1KeepsAtMostKTimes(t *testing.T) {
	for _, k := range []int{rc1KNew, rc1KAgent, rc1KPeerHub} {
		t.Run(fmt.Sprint(k), func(t *testing.T) {
			r := newRC1(rc1T0, 1, rc1Big, rc1Big)
			now := rc1T0 + 100_000
			base := uint64(now) - 20_000 // all inside W of each other
			for i := 0; i < k+3; i++ {
				mustAccept(t, r, "s", base+uint64(i), k, now)
			}
			floor, _, recent, _ := r.view("s")
			if len(recent) != k || floor != base+2 || recent[0] != base+3 {
				t.Fatalf("after %d times: %d kept, floor %d, smallest %d; want %d kept, floor %d, smallest %d",
					k+3, len(recent), floor, recent[0], k, base+2, base+3)
			}
			if v, f := r.accept("s", base+2, k, now); v != rc1Stale || f != base+2 {
				t.Fatalf("the time the floor rose to: verdict %d floor %d, want stale", v, f)
			}
		})
	}
}

// The window is MaxSkew either way, and a time above 2^62 is refused
// before any arithmetic.
func TestRC1RefusesTimesOutsideTheWindow(t *testing.T) {
	r := newRC1(rc1T0, 1, rc1Big, rc1Big)
	now := rc1T0 + 10*60_000
	for _, ts := range []uint64{uint64(now) - relayauth.MaxSkewMillis - 1, uint64(now) + relayauth.MaxSkewMillis + 1,
		uint64(now) + 1<<63, 1<<62 + 1, 0} {
		if v, _ := r.accept("s", ts, rc1KAgent, now); v != rc1Outside {
			t.Errorf("ts %d at %d: verdict %d, want outside", ts, now, v)
		}
	}
	if r.signerCount() != 0 {
		t.Fatal("a refused time left state")
	}
	for _, ts := range []uint64{uint64(now) - relayauth.MaxSkewMillis, uint64(now) + relayauth.MaxSkewMillis} {
		mustAccept(t, r, fmt.Sprint("edge", ts), ts, rc1KAgent, now)
	}
}

// PAY-R6: a signer's state goes once everything it had accepted is older
// than MaxSkew, judged by its largest time and not by when it was last
// active: a time signed MaxSkew ahead keeps it for twice MaxSkew.
func TestRC1DropsASignerOnlyWhenTheWindowCoversItsLargestTime(t *testing.T) {
	r := newRC1(rc1T0, 1, rc1Big, rc1Big)
	now := rc1T0 + 1000
	future := uint64(now) + relayauth.MaxSkewMillis - 10
	mustAccept(t, r, "s", future, rc1KAgent, now)
	// Long after its last request, but its future time is still inside
	// the window: the state stays and the time stays refused.
	later := now + relayauth.MaxSkewMillis + rc1SweepEvery + 1
	if v, _ := r.accept("other", uint64(later), rc1KAgent, later); v != rc1Accepted {
		t.Fatal("other signer refused")
	}
	if _, _, _, ok := r.view("s"); !ok {
		t.Fatal("the state of a signer whose future time is inside the window was dropped")
	}
	if v, _ := r.accept("s", future, rc1KAgent, later); v != rc1Replayed {
		t.Fatalf("the future time after its signer went quiet: verdict %d, want replayed", v)
	}
	// Once its largest time is older than MaxSkew the state goes.
	gone := int64(future) + relayauth.MaxSkewMillis + rc1SweepEvery + 1
	mustAccept(t, r, "other", uint64(gone), rc1KAgent, gone)
	if _, _, _, ok := r.view("s"); ok {
		t.Fatal("the state outlived its largest time by more than MaxSkew")
	}
}

// What is dropped leaves its largest time as the floor of a signer without
// state in its part, and a part starts at the time the state was made: a
// hub clock that steps back by more than MaxSkew, or a restart, does not
// let an accepted time through again.
func TestRC1DroppedTimesStayRefusedWhenTheClockStepsBack(t *testing.T) {
	r := newRC1(rc1T0, 1, rc1Big, rc1Big)
	if v, floor := r.accept("s", uint64(rc1T0)-1, rc1KAgent, rc1T0); v != rc1Stale || floor != uint64(rc1T0)-1 {
		t.Fatalf("a time signed before the state was made: verdict %d floor %d, want stale at %d", v, floor, rc1T0-1)
	}
	now := rc1T0 + 1000
	ts := uint64(now)
	mustAccept(t, r, "s", ts, rc1KAgent, now)
	far := now + 2*relayauth.MaxSkewMillis
	mustAccept(t, r, "other", uint64(far), rc1KAgent, far) // sweeps: "s" is dropped
	if _, _, _, ok := r.view("s"); ok {
		t.Fatal("not dropped")
	}
	// The clock steps back to when ts was signed.
	if v, floor := r.accept("s", ts, rc1KAgent, now); v != rc1Stale || floor != ts {
		t.Fatalf("a dropped time after the clock stepped back: verdict %d floor %d, want stale at %d", v, floor, ts)
	}
	mustAccept(t, r, "s", ts+1, rc1KAgent, now)
}

// PAY-R7: past the valve's high mark the signers with the oldest largest
// times become strictly monotonic until the state is below the low mark;
// nobody is refused; a monotonic signer's next later time is accepted.
func TestRC1TheValveMakesTheOldestSignersMonotonic(t *testing.T) {
	now := rc1T0 + 100_000
	// One signer with 8 times is rc1SignerBytes + len(aid) + 8·8 bytes. The
	// valve trips when the 20th such signer holds its 8 times, and goes
	// down past what making 10 of them monotonic frees.
	per := int64(rc1SignerBytes + len("s00") + 8*8)
	r := newRC1(rc1T0, 4, 20*per-1, 20*per-10*8*8)
	for i := 0; i < 19; i++ {
		aid := fmt.Sprintf("s%02d", i)
		for j := 0; j < 8; j++ {
			mustAccept(t, r, aid, uint64(now)-1000+uint64(i*10+j), rc1KAgent, now)
		}
	}
	for i := 0; i < 19; i++ {
		if _, _, recent, _ := r.view(fmt.Sprintf("s%02d", i)); len(recent) != 8 {
			t.Fatalf("below the valve s%02d kept %d times, want 8", i, len(recent))
		}
	}
	for j := 0; j < 8; j++ { // the 20th signer passes the high mark
		mustAccept(t, r, "s19", uint64(now)-1000+uint64(190+j), rc1KAgent, now)
	}
	if b := r.bytes.Load(); b >= r.low {
		t.Fatalf("after the valve the state is %d bytes, want below %d", b, r.low)
	}
	// The monotonic ones are the oldest: s00, s01, … up to some point.
	compacted, kept := 0, 0
	for i := 0; i < 20; i++ {
		aid := fmt.Sprintf("s%02d", i)
		floor, maxSeen, recent, ok := r.view(aid)
		if !ok {
			t.Fatalf("%s lost its state", aid)
		}
		if len(recent) > 0 {
			kept++
			continue
		}
		if kept > 0 {
			t.Fatalf("%s was made monotonic although an older signer kept its times", aid)
		}
		compacted++
		if floor != maxSeen {
			t.Fatalf("%s monotonic with floor %d below its largest time %d", aid, floor, maxSeen)
		}
		// Its own times are refused; its next later time is accepted.
		if v, _ := r.accept(aid, maxSeen, rc1KAgent, now); v != rc1Stale {
			t.Fatalf("%s: its largest time after the valve: verdict %d, want stale", aid, v)
		}
		mustAccept(t, r, aid, maxSeen+1, rc1KAgent, now)
	}
	if compacted < 10 || kept == 0 {
		t.Fatalf("%d signers made monotonic and %d kept their times; want at least 10, and the rest kept", compacted, kept)
	}
}

// The valve cannot go below the fixed cost of the signers it holds; it then
// stops trying for a while rather than walking every signer on every
// request, and still refuses nobody.
func TestRC1AValveThatCannotGetLowRunsAgainLater(t *testing.T) {
	now := rc1T0 + 100_000
	r := newRC1(rc1T0, 2, 1, 1)
	for i := 0; i < 50; i++ {
		mustAccept(t, r, fmt.Sprint("s", i), uint64(now)+uint64(i), rc1KAgent, now)
	}
	if next := r.nextValve.Load(); next != now+rc1ValveEvery {
		t.Fatalf("next valve run at %d, want %d", next, now+rc1ValveEvery)
	}
	for i := 0; i < 50; i++ {
		if _, _, recent, _ := r.view(fmt.Sprint("s", i)); len(recent) > 1 {
			t.Fatalf("s%d kept %d times", i, len(recent))
		}
	}
}

// Every part is swept while requests come in, whoever signs them: a part no
// request lands in is swept in turn.
func TestRC1EveryPartIsSweptInTurn(t *testing.T) {
	r := newRC1(rc1T0, rc1Shards, rc1Big, rc1Big)
	now := rc1T0 + 1000
	for i := 0; i < 500; i++ {
		mustAccept(t, r, fmt.Sprint("old", i), uint64(now), rc1KAgent, now)
	}
	if r.signerCount() != 500 {
		t.Fatal("setup")
	}
	later := now + relayauth.MaxSkewMillis + rc1SweepEvery + 1
	for i := 0; i < rc1Shards; i++ {
		mustAccept(t, r, "busy", uint64(later)+uint64(i), rc1KAgent, later)
	}
	if n := r.signerCount(); n != 1 {
		t.Fatalf("%d signers left after every part had its turn, want 1", n)
	}
	if b := r.bytes.Load(); b != signerBytesOf(r, "busy") {
		t.Fatalf("the state accounts %d bytes for one signer of %d", b, signerBytesOf(r, "busy"))
	}
}

func signerBytesOf(r *rc1State, aid string) int64 {
	sh := r.shard(aid)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return signerBytes(aid, sh.signers[aid])
}
