package federation

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Every response of a peer hub states the hub wire it speaks (core
// CORE-V1). A peer that answers with another wire, or with none, does not
// speak this hub's contract: its answers cannot be read as this hub reads
// them, and its 200 to a forward is not a statement that it queued
// anything. So this hub stops talking to it: the next requests to that peer
// fail at once, without being sent, until peerWireRetry has passed; then
// one request goes through again, and a peer that has been upgraded is
// talked to as before. Each mismatch is counted (PeerWireMismatches) and
// logged when the stop begins.
//
// A response with no X-ANet-Wire and a 5xx status is not counted: it comes
// from whatever stands in front of the hub (a reverse proxy whose upstream
// is down), not from a hub of another wire, and the caller treats it as the
// peer being unreachable, which it is.

// peerWireRetry is how long this hub stops talking to a peer whose answer
// stated another wire.
const peerWireRetry = 10 * time.Minute

// ErrPeerWire is the error of a request to a peer this hub has stopped
// talking to, or whose answer stated another hub wire.
var ErrPeerWire = errors.New("federation: the peer hub does not speak hub wire 3")

// peerWire checks the X-ANet-Wire of every response a peer sends, keyed by
// the peer's scheme and host.
type peerWire struct {
	base    http.RoundTripper
	now     func() time.Time
	mu      sync.Mutex
	stopped map[string]time.Time // origin → until when no request is sent
	count   atomic.Int64
}

func newPeerWire(base http.RoundTripper, now func() time.Time) *peerWire {
	return &peerWire{base: base, now: now, stopped: map[string]time.Time{}}
}

// RoundTrip implements http.RoundTripper.
func (p *peerWire) RoundTrip(req *http.Request) (*http.Response, error) {
	origin := req.URL.Scheme + "://" + strings.ToLower(req.URL.Host)
	p.mu.Lock()
	until, stopped := p.stopped[origin]
	now := p.now()
	if stopped && now.Before(until) {
		p.mu.Unlock()
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("%w: %s answered with another wire; this hub asks it again after %s",
			ErrPeerWire, origin, until.Sub(now).Round(time.Second))
	}
	p.mu.Unlock()
	resp, err := p.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	vs := resp.Header.Values(wire3.Header)
	switch {
	case len(vs) == 1 && vs[0] == strconv.Itoa(wire3.Version):
		if stopped {
			p.mu.Lock()
			delete(p.stopped, origin)
			p.mu.Unlock()
			log.Printf("hub: federation peer %s speaks hub wire %d again; talking to it again", origin, wire3.Version)
		}
		return resp, nil
	case len(vs) == 0 && resp.StatusCode >= 500:
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	p.count.Add(1)
	stated := "no wire"
	if len(vs) > 0 {
		stated = "wire " + strings.Join(vs, ",")
	}
	p.mu.Lock()
	p.stopped[origin] = p.now().Add(peerWireRetry)
	p.mu.Unlock()
	log.Printf("hub: federation peer %s answered with %s, not hub wire %d; this hub stops talking to it for %s (upgrade it to anet-hub %s or later)",
		origin, stated, wire3.Version, peerWireRetry, wire3.RequiredAnet)
	return nil, fmt.Errorf("%w: %s answered with %s", ErrPeerWire, origin, stated)
}

// PeerWireMismatches is how many answers of peers stated another hub wire
// than 3, or none, since the process started.
func (s *Service) PeerWireMismatches() int64 { return s.wire.count.Load() }
