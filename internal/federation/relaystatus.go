package federation

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// POST /fed/v3/relay-status (p2p-receipts §2.5, DLV-W-19, DLV-H-8; core
// §2.12.2, G3).
//
// A sender whose envelope was forwarded to the recipient's home hub was
// given that hub's rid and via_hub. It asks its own hub, anonymously, and
// its hub asks the home: this route, signed by the asking hub for
// fed_status and checked by authPeer like every /fed/v3 route. The request
// is the sender's status check without via_hub, and carries nothing of the
// sender; the answer is the home's /relay/status answer for its own
// mailbox. The kernel answers it through the DeliveryStatus seam; this
// hub's own requests to a peer go through the one Signer (s.signer.Do).

// DeliveryStatus is what /fed/v3/relay-status needs from the hub kernel
// (internal/aghub implements it on *aghub.Server; cmd/anet-hub wires it with
// SetDeliveryStatus).
type DeliveryStatus interface {
	// FedStatusEmpty reports, without taking a token, whether the peer
	// hub's bucket of status checks is empty, and how long until it is not:
	// authPeer's gate, before the body is read.
	FedStatusEmpty(peerAID string) (empty bool, wait time.Duration)
	// ServeFedRelayStatus answers a status check the peer hub peerAID
	// signed, whose body is body.
	ServeFedRelayStatus(w http.ResponseWriter, peerAID string, body []byte)
}

// SetDeliveryStatus wires the kernel /fed/v3/relay-status answers through.
// Without it the route refuses every request (not_peer).
func (s *Service) SetDeliveryStatus(d DeliveryStatus) { s.status = d }

// relayStatusBodyLimit bounds a /fed/v3/relay-status body, as /relay/status
// bounds its own (16 KiB).
const relayStatusBodyLimit = 16 << 10

// relayStatusTimeout bounds one status check at a peer (DLV-W-18).
const relayStatusTimeout = 5 * time.Second

// sentenceStatusLimited is the error of a peer's status check refused by
// its bucket (p2p-receipts §2.4.4).
const sentenceStatusLimited = "Too many status checks from your hub; retry after the given seconds."

// hRelayStatus serves POST /fed/v3/relay-status: open while delivery
// federation is on and the kernel is wired, as the forward that queued the
// envelopes is.
func (s *Service) hRelayStatus(w http.ResponseWriter, r *http.Request) {
	peer, body, ok := s.authPeer(w, r, relayauth.ActionFedStatus, s.Enabled() && s.status != nil,
		relayStatusBodyLimit, s.statusGate)
	if !ok {
		return
	}
	s.status.ServeFedRelayStatus(w, peer.AID, body)
}

// statusGate is the peer's bucket of status checks, looked at without
// taking a token before the body is read; the kernel takes the token once
// the request is the peer's (DLV-W-19a).
func (s *Service) statusGate(w http.ResponseWriter, peerAID string) bool {
	if empty, wait := s.status.FedStatusEmpty(peerAID); empty {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait, Error: sentenceStatusLimited})
		return false
	}
	return true
}

// RelayStatus asks the delivery peer peerAID about envelopes it queued:
// POST /fed/v3/relay-status, body being the JSON status check without
// via_hub, signed by this hub for fed_status. The response is the caller's
// to read and close. A ts_stale is signed again above the peer's floor
// (Signer.Do) and a replayed sent once more with a new time; a peer that is
// not a delivery peer, a peer this hub stopped talking to, a network
// failure and no answer within relayStatusTimeout are errors.
func (s *Service) RelayStatus(ctx context.Context, peerAID string, body []byte) (*http.Response, error) {
	p := s.deliveryPeer(peerAID)
	if p == nil {
		return nil, errNotADeliveryPeer(peerAID)
	}
	ctx, cancel := context.WithTimeout(ctx, relayStatusTimeout)
	resp, err := doRetryingReplayed(ctx, s.signer, p.AID, relayauth.ActionFedStatus, Request{Method: http.MethodPost,
		URL: strings.TrimSuffix(p.Endpoint, "/") + "/fed/v3/relay-status", ContentType: "application/json", Body: body})
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = cancelOnClose{resp.Body, cancel}
	return resp, nil
}
