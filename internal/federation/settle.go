package federation

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Cross-hub settlement (hub-payment-privacy §2.4, PAY-L4, PAY-L5, PAY-U2;
// core §2.12.2, G3):
//
//	POST /fed/v3/settle  a payment on this hub's ledger, forwarded by the hub
//	                     of its payee; answered with the x402 SettlementResponse
//	POST /fed/v3/clear   a peer's signed statement that it has paid what it
//	                     owed this hub
//
// Both are signed by the asking hub, for fed_settle and fed_clear, and
// checked by authPeer like every /fed/v3 route; the kernel answers them
// through the Clearing seam. This hub's own requests to them go through the
// one Signer (s.signer.Do), so a peer's RC1 and the wire check of its answers
// apply as for every other federation request.

// Clearing is what the settlement routes need from the hub kernel
// (internal/aghub implements it on *aghub.Server; cmd/anet-hub wires it with
// SetClearing). Its methods answer a request the peer hub peerAID signed,
// whose body is body.
type Clearing interface {
	// ServeFedSettle settles a payment the peer forwarded for its own
	// payee, and answers the SettlementResponse with 200.
	ServeFedSettle(w http.ResponseWriter, peerAID string, body []byte)
	// ServeFedClear applies the peer's discharge statement.
	ServeFedClear(w http.ResponseWriter, peerAID string, body []byte)
}

// SetClearing wires the kernel the settlement routes answer through.
// Without it they refuse every request (not_peer).
func (s *Service) SetClearing(c Clearing) { s.clearing = c }

// Bounds of the settlement routes: a request body, and the answer this hub
// reads of a peer's.
const (
	settleBodyLimit   = 1 << 20  // an x402 FacilitatorRequest, as /x402/settle takes
	clearBodyLimit    = 64 << 10 // an AID and one discharge statement
	settleAnswerLimit = 1 << 20
)

// clearingOpen reports whether the settlement routes are served: while
// federation is on in either sub-plane, as SettleAtPeer forwards and
// PeerAIDs advertises, and the kernel is wired.
func (s *Service) clearingOpen() bool {
	return (s.Enabled() || s.DiscoveryEnabled()) && s.clearing != nil
}

// hSettle serves POST /fed/v3/settle.
func (s *Service) hSettle(w http.ResponseWriter, r *http.Request) {
	peer, body, ok := s.authPeer(w, r, relayauth.ActionFedSettle, s.clearingOpen(), settleBodyLimit, nil)
	if !ok {
		return
	}
	s.clearing.ServeFedSettle(w, peer.AID, body)
}

// hClear serves POST /fed/v3/clear.
func (s *Service) hClear(w http.ResponseWriter, r *http.Request) {
	peer, body, ok := s.authPeer(w, r, relayauth.ActionFedClear, s.clearingOpen(), clearBodyLimit, nil)
	if !ok {
		return
	}
	s.clearing.ServeFedClear(w, peer.AID, body)
}

// SettleAtPeer asks the hub that owns a ledger to settle a payment on it:
// POST /fed/v3/settle, body being the x402 v2 FacilitatorRequest, signed by
// this hub for fed_settle (PAY-L5).
//
// The provider's hub cannot settle a balance it does not keep, and
// refusing would make a paid capability unusable across a federation. So
// it forwards, signed, and the answer comes back with the settling hub's
// signed receipt — which is what lets the asking hub credit its own payee
// on another hub's word and still be able to show what that word was. The
// signature is what lets the settling hub know whom it now owes: a
// settlement for a payee elsewhere is refused unless a peer signed for it.
//
// Only allowlisted peers, and only the peer whose AID the network names.
// A settlement request routed by the caller would be a request to credit
// whoever the caller chose.
//
// It returns the answer's status and body, and the peer's AID. A refusal of
// the signing time is signed again above the peer's floor once
// (Signer.Do), and a replayed one is sent once more with a new time, as a
// forward is: RC1 refuses a request before the kernel sees it, so nothing
// was settled. A peer this hub stopped talking to (peerwire.go), a network
// failure and no answer are errors; the outcome is then unknown.
func (s *Service) SettleAtPeer(ctx context.Context, network string, body []byte) (status int, answer []byte, peerAID string, err error) {
	if !s.DiscoveryEnabled() && !s.Enabled() {
		return 0, nil, "", fmt.Errorf("federation disabled")
	}
	const prefix = "hub:"
	if !strings.HasPrefix(network, prefix) {
		return 0, nil, "", fmt.Errorf("not a hub ledger: %q", network)
	}
	peerAID = strings.TrimPrefix(network, prefix)
	p := s.peer(peerAID)
	if p == nil {
		return 0, nil, "", fmt.Errorf("hub %s is not a peer of this one", peerAID)
	}
	req := Request{Method: http.MethodPost, URL: strings.TrimSuffix(p.Endpoint, "/") + "/fed/v3/settle",
		ContentType: "application/json", Body: body}
	resp, err := doRetryingReplayed(ctx, s.signer, p.AID, relayauth.ActionFedSettle, req)
	if err != nil {
		return 0, nil, p.AID, err
	}
	defer resp.Body.Close()
	answer, err = io.ReadAll(io.LimitReader(resp.Body, settleAnswerLimit))
	return resp.StatusCode, answer, p.AID, err
}

// clearTimeout bounds one discharge sent by anet-hub clear.
const clearTimeout = 30 * time.Second

// ClearAtPeer sends body, a discharge statement (aghub.ClearRequest), to the
// peer hub peerAID at endpoint: POST /fed/v3/clear, signed by the hub id for
// fed_clear (anet-hub clear, PAY-U2). The response is the caller's to read
// and close.
//
// It runs in a process beside the running hub, with a signing clock of its
// own that can meet a time the hub used for the same peer: a ts_stale is
// signed again above the peer's floor and a replayed sent once more with a
// new time, so an operator's discharge is not refused for the hub's own
// traffic. The answer's wire is checked as every peer answer is.
func ClearAtPeer(ctx context.Context, id *hubid.Identity, peerAID, endpoint string, body []byte) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, clearTimeout)
	signer := NewSigner(id, &http.Client{Transport: newPeerWire(wire3.Transport(nil), time.Now)})
	resp, err := doRetryingReplayed(ctx, signer, peerAID, relayauth.ActionFedClear, Request{Method: http.MethodPost,
		URL: strings.TrimSuffix(endpoint, "/") + "/fed/v3/clear", ContentType: "application/json", Body: body})
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = cancelOnClose{resp.Body, cancel}
	return resp, nil
}

// doRetryingReplayed is signer.Do, sent once more with a new time when the
// peer answered replayed.
func doRetryingReplayed(ctx context.Context, signer *Signer, peerAID, action string, req Request) (*http.Response, error) {
	resp, err := signer.Do(ctx, peerAID, action, req)
	if err == nil && refusedFor(resp, wire3.ReasonReplayed) {
		resp.Body.Close()
		resp, err = signer.Do(ctx, peerAID, action, req)
	}
	return resp, err
}
