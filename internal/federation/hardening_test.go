package federation

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// TestFedBodyReadDeadline (sealed-sender SSR-H16, 2026-10-10): a /fed/v3
// request that passed the header checks and then stops sending its body is
// answered and its connection closed once the read deadline passes, and
// what it held of the budget is given back; a request beside it is served
// as usual meanwhile.
func TestFedBodyReadDeadline(t *testing.T) {
	a, b := newTestHub(t), newTestHub(t)
	a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, nil)
	a.k.maxEnvelope = 2 << 20
	bodyReadDeadline = 700 * time.Millisecond
	t.Cleanup(func() { bodyReadDeadline = fedBodyReadDeadline })
	payload := bytes.Repeat([]byte{7}, 1<<20)
	req := a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", payload, 0, nil)

	conn, err := net.Dial("tcp", a.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var head strings.Builder
	fmt.Fprintf(&head, "POST /fed/v3/forward HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n", req.URL.Host, len(payload))
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	head.WriteString("\r\n")
	if _, err := io.WriteString(conn, head.String()); err != nil {
		t.Fatal(err)
	}
	half := len(payload) / 2
	if _, err := conn.Write(payload[:half]); err != nil {
		t.Fatal(err)
	}
	// The half that was sent is held.
	deadline := time.Now().Add(10 * time.Second)
	for a.svc.bodies.held() != int64(half) {
		if time.Now().After(deadline) {
			t.Fatalf("%d held, want %d", a.svc.bodies.held(), half)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Beside it, a forward is served.
	if code, body, _ := do(t, a.signedReq(b.id, relayauth.ActionFedForward, http.MethodPost, "/fed/v3/forward", []byte("beside"), 0, nil)); code != 200 {
		t.Fatalf("a forward beside the stalled one: %d %s", code, body)
	}
	// Past the deadline: answered, closed, and nothing held.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer to the stalled request: %v", err)
	}
	rest, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 400 || reasonOf(rest) != "bad_request" {
		t.Fatalf("the stalled request: %d %s", resp.StatusCode, rest)
	}
	one := make([]byte, 1)
	n, err := conn.Read(one)
	var ne net.Error
	if n != 0 || err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the connection stayed open: %d %v", n, err)
	}
	if n := a.svc.bodies.held(); n != 0 {
		t.Fatalf("%d still held after the deadline", n)
	}
	if got := a.k.forwarded(); len(got) != 1 || string(got[0].body) != "beside" {
		t.Fatalf("the kernel got %d forwards", len(got))
	}
	if fedBodyReadDeadline != 120*time.Second {
		t.Errorf("fedBodyReadDeadline = %s", fedBodyReadDeadline)
	}
}

// rtFunc is a RoundTripper of a function.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// answerWire is a 200 stating wire.
func answerWire(wire string) *http.Response {
	h := http.Header{}
	if wire != "" {
		h.Set(wire3.Header, wire)
	}
	return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader("{}"))}
}

// TestAStoppedPeerIsAskedAgainByOneRequest (SSR-H16a): once the stop of a
// peer that answered with another wire is over, exactly one request goes to
// it; the requests made while that one is out fail at once, unsent. When it
// gets no answer of either kind, the next request is the one that asks.
func TestAStoppedPeerIsAskedAgainByOneRequest(t *testing.T) {
	var calls atomic.Int32
	var mu sync.Mutex
	answer := func(*http.Request) (*http.Response, error) { return answerWire("2"), nil }
	pw := newPeerWire(rtFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		mu.Lock()
		f := answer
		mu.Unlock()
		return f(r)
	}), nil)
	now := time.Now()
	var nowMu sync.Mutex
	pw.now = func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	advance := func(d time.Duration) { nowMu.Lock(); now = now.Add(d); nowMu.Unlock() }
	set := func(f func(*http.Request) (*http.Response, error)) { mu.Lock(); answer = f; mu.Unlock() }
	ask := func() error {
		req, _ := http.NewRequest(http.MethodGet, "http://peer.test/hub/identity", nil)
		resp, err := pw.RoundTrip(req)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	burst := func(n int) []error {
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Add(1)
			go func() { defer wg.Done(); errs[i] = ask() }()
		}
		wg.Wait()
		return errs
	}
	waitCalls := func(want int32) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for calls.Load() != want {
			if time.Now().After(deadline) {
				t.Fatalf("%d calls, want %d", calls.Load(), want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	if err := ask(); !errors.Is(err, ErrPeerWire) || calls.Load() != 1 {
		t.Fatalf("an answer of wire 2: %v, %d calls", err, calls.Load())
	}
	// The stop is over; the peer is upgraded but slow to answer.
	advance(peerWireRetry)
	release := make(chan struct{})
	var held atomic.Bool
	set(func(*http.Request) (*http.Response, error) {
		if held.CompareAndSwap(false, true) {
			<-release // the first request to reach the peer waits
		}
		return answerWire("3"), nil
	})
	probe := make(chan error, 1)
	go func() { probe <- ask() }()
	waitCalls(2)
	for i, err := range burst(8) {
		if !errors.Is(err, ErrPeerWire) {
			t.Fatalf("request %d while the one asking again is out: %v", i, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("%d requests reached the peer while one asked again, want 1", calls.Load()-1)
	}
	close(release)
	if err := <-probe; err != nil {
		t.Fatalf("the request asking again: %v", err)
	}
	for _, err := range burst(4) {
		if err != nil {
			t.Fatalf("after the peer answered wire 3: %v", err)
		}
	}
	waitCalls(6)
	// Stopped again; this time the one asking again gets no answer.
	set(func(*http.Request) (*http.Response, error) { return answerWire("4"), nil })
	if err := ask(); !errors.Is(err, ErrPeerWire) {
		t.Fatalf("an answer of wire 4: %v", err)
	}
	advance(peerWireRetry)
	set(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") })
	if err := ask(); err == nil || errors.Is(err, ErrPeerWire) {
		t.Fatalf("the one asking again, unanswered: %v", err)
	}
	before := calls.Load()
	set(func(*http.Request) (*http.Response, error) { return answerWire("3"), nil })
	if err := ask(); err != nil || calls.Load() != before+1 {
		t.Fatalf("the next request after an unanswered one: %v, %d calls", err, calls.Load()-before)
	}
}
