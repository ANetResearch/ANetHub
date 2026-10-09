package federation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// The bytes of /fed/v3 request bodies this hub holds at once (sealed-sender
// SSR-H16, 2026-10-09).
//
// A peer's signature covers its request body, so authPeer reads the body
// before it can tell the peer from someone using the peer's public AID. A
// forward's body may be as large as an envelope (96 MiB by default), so
// without a bound, a few concurrent requests naming a peer would make this
// hub buffer more than it has. Every /fed/v3 request reserves what it reads
// from one budget, fedBodyBudget bytes for the whole hub, and gives it back
// when its handler returns; a request that does not fit is 429 source_rate
// with Retry-After 1 (the origin answers its sender 502, SSR-H13), before
// it reads past the budget. A declared Content-Length is reserved whole
// before any byte is read; a body of unknown length reserves what it reads
// as it reads it.

// fedBodyBudget is the bytes of /fed/v3 request bodies held at once. A code
// constant, not configuration.
const fedBodyBudget = 256 << 20

// bodyBudget is the reservations against fedBodyBudget.
type bodyBudget struct {
	mu    sync.Mutex
	limit int64
	used  int64
}

func newBodyBudget(limit int64) *bodyBudget { return &bodyBudget{limit: limit} }

// take reserves n bytes, or reports false when they do not fit.
func (b *bodyBudget) take(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > b.limit-b.used {
		return false
	}
	b.used += n
	return true
}

// give returns n bytes.
func (b *bodyBudget) give(n int64) {
	b.mu.Lock()
	b.used -= n
	b.mu.Unlock()
}

// held is the bytes reserved now.
func (b *bodyBudget) held() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// bodyHold is what one request reserved; it is given back at once when the
// request's handler returns.
type bodyHold struct {
	budget *bodyBudget
	mu     sync.Mutex
	n      int64
}

func (h *bodyHold) take(n int64) bool {
	if !h.budget.take(n) {
		return false
	}
	h.mu.Lock()
	h.n += n
	h.mu.Unlock()
	return true
}

func (h *bodyHold) release() {
	h.mu.Lock()
	n := h.n
	h.n = 0
	h.mu.Unlock()
	h.budget.give(n)
}

// bodyHoldKey is the context key of a request's bodyHold.
type bodyHoldKey struct{}

// holdBodies wraps the /fed/v3 routes: each request gets a bodyHold, given
// back when the route's handler returns.
func (s *Service) holdBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := &bodyHold{budget: s.bodies}
		defer h.release()
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), bodyHoldKey{}, h)))
	})
}

// holdOf is r's bodyHold. A request that did not come through holdBodies
// (a test calling a route directly) gets one given back when its context
// ends.
func (s *Service) holdOf(r *http.Request) *bodyHold {
	if h, ok := r.Context().Value(bodyHoldKey{}).(*bodyHold); ok {
		return h
	}
	h := &bodyHold{budget: s.bodies}
	context.AfterFunc(r.Context(), h.release)
	return h
}

// errOverBudget is a body that does not fit in fedBodyBudget now.
var errOverBudget = errors.New("federation: the request bodies held at once are at their bound")

// testHookPeerBodyRead, when a test sets it, is called each time authPeer
// starts to read a request body.
var testHookPeerBodyRead func()

// readPeerBody is step 5 of authPeer: the body of r, at most limit bytes,
// within the budget. It answers 413 too_large, 429 source_rate or 400
// bad_request and returns false when it cannot.
func (s *Service) readPeerBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	tooLarge := func() ([]byte, bool) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonTooLarge,
			Error: fmt.Sprintf("A request of this route is at most %d bytes; send a smaller one.", limit)})
		return nil, false
	}
	overBudget := func() ([]byte, bool) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonSourceRate, RetryAfter: time.Second,
			Error: "This hub is reading as many federation requests as it holds at once; send again after the seconds in Retry-After."})
		return nil, false
	}
	if r.ContentLength > limit {
		return tooLarge()
	}
	hold := s.holdOf(r)
	if r.ContentLength >= 0 && !hold.take(r.ContentLength) {
		return overBudget()
	}
	if testHookPeerBodyRead != nil {
		testHookPeerBodyRead()
	}
	src := io.Reader(http.MaxBytesReader(w, r.Body, limit))
	if r.ContentLength < 0 {
		src = &budgetReader{r: src, hold: hold}
	}
	body, err := io.ReadAll(src)
	if err != nil {
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig):
			return tooLarge()
		case errors.Is(err, errOverBudget):
			return overBudget()
		}
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest, Error: "The request body could not be read; send it again."})
		return nil, false
	}
	return body, true
}

// budgetReader reserves what it reads, for a body of unknown length.
type budgetReader struct {
	r    io.Reader
	hold *bodyHold
}

func (b *budgetReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 && !b.hold.take(int64(n)) {
		return 0, errOverBudget
	}
	return n, err
}
