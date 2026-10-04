package federation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// Signer makes the requests this hub signs to peer hubs, with relayauth v2
// headers under the hub's own identity (hub-payment-privacy PAY-R9, core
// G17).
//
// A peer accepts each X-ANet-TS of a signer at most once, and never at or
// below the floor it keeps for the signer (RC1, PAY-R2). The signing times
// therefore come from one relayauth.MonoClock per process, a counter per
// peer: two requests to one peer never share a time, and one peer's floor
// never moves the times sent to another (PAY-R12). A peer that answers
// ts_stale names its floor; the clock is raised to it and the request is
// signed again and sent once more, unless the floor is further ahead than
// the window every hub accepts, which is not adopted (PAY-R11).
//
// One Signer per process: every part of the process that signs requests
// to peers goes through the same one, or their times would collide.
type Signer struct {
	id     *hubid.Identity
	client *http.Client
	clock  relayauth.MonoClock
	// now is the clock the signing times start from (time.Now; a test's).
	now func() time.Time
}

// NewSigner returns the signer for hub identity id, sending with client.
func NewSigner(id *hubid.Identity, client *http.Client) *Signer {
	return &Signer{id: id, client: client, now: time.Now}
}

// ErrFloorNotAdopted is Do's error when the peer answered ts_stale with a
// floor further ahead than now + MaxSkew − 60 s: adopting it would make
// this hub sign times other hubs refuse as being from the future.
var ErrFloorNotAdopted = errors.New("federation: the peer asked for signing times further ahead than the window hubs accept")

// Request is one request to a peer, before it is signed.
type Request struct {
	Method string
	// URL is absolute; its request target as sent is what is signed.
	URL string
	// ContentType is sent when not empty.
	ContentType string
	// Body is nil for a request without one.
	Body []byte
}

// headerTSFloor carries a peer's floor in a ts_stale refusal (core
// §2.12.1).
const headerTSFloor = "X-ANet-TS-Floor"

// Do sends r to the peer hub peerAID, signed for action. The response is
// the caller's to close.
//
// After a ts_stale from the peer it raises the clock to the peer's floor
// and signs and sends the request once more; that second response is
// returned whatever it is. A floor it does not adopt is ErrFloorNotAdopted.
func (s *Signer) Do(ctx context.Context, peerAID, action string, r Request) (*http.Response, error) {
	resp, err := s.send(ctx, peerAID, action, r)
	if err != nil {
		return nil, err
	}
	floor, stale := staleFloor(resp)
	if !stale {
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if !s.clock.Raise(peerAID, floor, s.now().UnixMilli()) {
		return nil, fmt.Errorf("%w (floor %d)", ErrFloorNotAdopted, floor)
	}
	return s.send(ctx, peerAID, action, r)
}

// send signs and sends the request once, at the next time for peerAID.
func (s *Signer) send(ctx context.Context, peerAID, action string, r Request) (*http.Response, error) {
	var rd io.Reader
	if r.Body != nil {
		rd = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, rd)
	if err != nil {
		return nil, err
	}
	if r.ContentType != "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	ts := uint64(s.clock.Next(peerAID, s.now().UnixMilli()))
	sig, seq := s.id.Ctrl.Sign(relayauth.PreimageV2(action, s.id.AID, peerAID, ts, req.Method, req.URL.RequestURI(), r.Body))
	req.Header.Set(relayauth.HeaderAID, s.id.AID)
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	return s.client.Do(req)
}

// staleFloor reads the floor of a ts_stale refusal: a 401 with one
// X-ANet-TS-Floor in canonical decimal, below 2^62 (any time a hub
// accepts is). Anything else is not a ts_stale this client acts on.
func staleFloor(resp *http.Response) (int64, bool) {
	if resp.StatusCode != http.StatusUnauthorized {
		return 0, false
	}
	vs := resp.Header.Values(headerTSFloor)
	if len(vs) != 1 {
		return 0, false
	}
	n, err := strconv.ParseUint(vs[0], 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != vs[0] || n > uint64(1)<<62 {
		return 0, false
	}
	return int64(n), true
}
