package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// fakePeer is a peer hub that keeps RC1 for one signer the simple way:
// a time is accepted when it is above the largest accepted so far, or
// it answers 401 ts_stale with that floor. floorBump, when set, is added to
// the floor it names (a peer whose floor is ahead of the signer's clock).
type fakePeer struct {
	t         *testing.T
	self      *hubid.Identity
	signer    *hubid.Identity
	mu        sync.Mutex
	floor     uint64
	floorBump uint64
	staleOnce bool // answer the next request ts_stale whatever its time
	seen      []uint64
	srv       *httptest.Server
}

func newFakePeer(t *testing.T, signer *hubid.Identity) *fakePeer {
	t.Helper()
	self, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &fakePeer{t: t, self: self, signer: signer}
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakePeer) serve(w http.ResponseWriter, r *http.Request) {
	a, err := parseHubAuth(r)
	if err != nil || a.aid != p.signer.AID {
		http.Error(w, "unsigned", http.StatusUnauthorized)
		return
	}
	pre := relayauth.PreimageV2(actionFedKeys, a.aid, p.self.AID, a.ts, r.Method, r.URL.RequestURI(), nil)
	if err := identity.VerifyObject(p.signer.Ctrl.KEL(), a.aid, a.seq, a.ts, pre, a.sig); err != nil {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, a.ts)
	if p.staleOnce || a.ts <= p.floor {
		p.staleOnce = false
		floor := max(p.floor, a.ts) + p.floorBump
		w.Header().Set(headerTSFloor, strconv.FormatUint(floor, 10))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"reason":"ts_stale","error":"stale","floor":` + strconv.FormatUint(floor, 10) + "}\n"))
		return
	}
	p.floor = a.ts
	w.WriteHeader(http.StatusOK)
}

func (p *fakePeer) ask(t *testing.T, s *Signer) (int, error) {
	t.Helper()
	resp, err := s.Do(context.Background(), p.self.AID, actionFedKeys,
		Request{Method: http.MethodGet, URL: p.srv.URL + "/fed/v2/keys/aid:x"})
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func newTestSigner(t *testing.T) (*hubid.Identity, *Signer) {
	t.Helper()
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return id, NewSigner(id, http.DefaultClient)
}

// PAY-R9 and core G17: this hub's requests to one peer carry strictly
// increasing times, even many in one millisecond and from many goroutines
// at once, so a peer's RC1 never refuses one of them for another.
func TestTheSignerHandsEachPeerIncreasingTimes(t *testing.T) {
	id, s := newTestSigner(t)
	frozen := time.Now()
	s.now = func() time.Time { return frozen } // every request in one millisecond
	p := newFakePeer(t, id)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				resp, err := s.Do(context.Background(), p.self.AID, actionFedKeys,
					Request{Method: http.MethodGet, URL: p.srv.URL + "/fed/v2/keys/aid:x"})
				if err != nil {
					errs <- err
					return
				}
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := map[uint64]bool{}
	for _, ts := range p.seen {
		if seen[ts] {
			t.Fatalf("two requests to one peer carried the time %d", ts)
		}
		seen[ts] = true
	}
	if len(p.seen) < 64 {
		t.Fatalf("the peer saw %d requests, want at least 64", len(p.seen))
	}
}

// PAY-R11: a ts_stale is answered by raising the clock to the peer's floor
// and signing the request again, once; the second answer is the answer.
func TestTheSignerSignsAgainAboveAStaleFloorOnce(t *testing.T) {
	id, s := newTestSigner(t)
	p := newFakePeer(t, id)
	floor0 := uint64(time.Now().UnixMilli()) + 60_000 // a minute ahead of this hub's clock
	p.floor = floor0
	if code, err := p.ask(t, s); err != nil || code != http.StatusOK {
		t.Fatalf("after a stale floor a minute ahead: %d %v, want 200 on the second try", code, err)
	}
	p.mu.Lock()
	seen := append([]uint64(nil), p.seen...)
	p.mu.Unlock()
	if len(seen) != 2 || seen[0] > floor0 || seen[1] <= floor0 {
		t.Fatalf("the peer saw %v, want two requests, the second above the floor", seen)
	}
	// A second ts_stale on the request signed again is returned as is:
	// signing again once is all the client does for one request.
	p.mu.Lock()
	p.staleOnce, p.floorBump = true, 0
	p.floor = uint64(time.Now().UnixMilli()) + 120_000
	p.mu.Unlock()
	resp, err := s.Do(context.Background(), p.self.AID, actionFedKeys,
		Request{Method: http.MethodGet, URL: p.srv.URL + "/fed/v2/keys/aid:x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	p.mu.Lock()
	n := len(p.seen)
	p.mu.Unlock()
	if n != 4 {
		t.Fatalf("the peer saw %d requests, want 4 (two for this one request)", n)
	}
}

// PAY-R11 and PAY-R12: a floor further ahead than now + MaxSkew − 60 s is
// not adopted (the request fails with ErrFloorNotAdopted and is not sent
// again), and one peer's floor does not move the times sent to another.
func TestTheSignerRefusesAFloorFromTheFutureAndKeepsPeersApart(t *testing.T) {
	id, s := newTestSigner(t)
	far, other := newFakePeer(t, id), newFakePeer(t, id)
	far.floor = uint64(time.Now().UnixMilli()) + relayauth.MaxSkewMillis
	if _, err := far.ask(t, s); !errors.Is(err, ErrFloorNotAdopted) {
		t.Fatalf("a floor at the edge of the window: %v, want ErrFloorNotAdopted", err)
	}
	far.mu.Lock()
	if len(far.seen) != 1 {
		t.Fatalf("the far peer saw %d requests, want 1", len(far.seen))
	}
	far.mu.Unlock()
	// Raise the clock for one peer, a minute ahead.
	near := newFakePeer(t, id)
	near.floor = uint64(time.Now().UnixMilli()) + 60_000
	if code, err := near.ask(t, s); err != nil || code != http.StatusOK {
		t.Fatalf("near peer: %d %v", code, err)
	}
	before := uint64(time.Now().UnixMilli())
	if code, err := other.ask(t, s); err != nil || code != http.StatusOK {
		t.Fatalf("other peer: %d %v", code, err)
	}
	other.mu.Lock()
	defer other.mu.Unlock()
	if ts := other.seen[0]; ts > before+10_000 {
		t.Fatalf("another peer's floor moved this peer's time to %d (now %d)", ts, before)
	}
}

// Only a 401 with one canonical X-ANet-TS-Floor below 2^62 is a ts_stale
// the client acts on.
func TestStaleFloorReadsOnlyACanonicalFloor(t *testing.T) {
	for _, tc := range []struct {
		code  int
		vals  []string
		floor int64
		ok    bool
	}{
		{401, []string{"1790000000000"}, 1790000000000, true},
		{401, []string{"0"}, 0, true},
		{403, []string{"1790000000000"}, 0, false},
		{401, nil, 0, false},
		{401, []string{"1", "2"}, 0, false},
		{401, []string{"01"}, 0, false},
		{401, []string{"+1"}, 0, false},
		{401, []string{"1e3"}, 0, false},
		{401, []string{strconv.FormatUint(1<<62+1, 10)}, 0, false},
		{401, []string{strings.Repeat("9", 30)}, 0, false},
	} {
		h := http.Header{}
		for _, v := range tc.vals {
			h.Add(headerTSFloor, v)
		}
		floor, ok := staleFloor(&http.Response{StatusCode: tc.code, Header: h})
		if ok != tc.ok || floor != tc.floor {
			t.Errorf("%d %q: %d %v, want %d %v", tc.code, tc.vals, floor, ok, tc.floor, tc.ok)
		}
	}
}

// FuzzStaleFloor: a floor is read only from a 401, and only when the one
// header value is the canonical decimal spelling of a number up to 2^62.
func FuzzStaleFloor(f *testing.F) {
	for _, s := range []string{"0", "1790000000000", "01", "-1", "4611686018427387904", "4611686018427387905", " 1", "1\n"} {
		f.Add(401, s, "")
	}
	f.Add(401, "5", "6")
	f.Fuzz(func(t *testing.T, code int, v1, v2 string) {
		h := http.Header{}
		if v1 != "" {
			h.Add(headerTSFloor, v1)
		}
		if v2 != "" {
			h.Add(headerTSFloor, v2)
		}
		floor, ok := staleFloor(&http.Response{StatusCode: code, Header: h})
		if !ok {
			if floor != 0 {
				t.Fatalf("refused with floor %d", floor)
			}
			return
		}
		if code != http.StatusUnauthorized || v2 != "" || floor < 0 || uint64(floor) > uint64(1)<<62 ||
			strconv.FormatInt(floor, 10) != v1 {
			t.Fatalf("code %d %q %q read as floor %d", code, v1, v2, floor)
		}
	})
}
