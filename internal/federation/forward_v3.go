package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// POST /fed/v3/forward (sealed-sender §2.8, §4.2.6, §4.2.7).
//
// The origin hub (the sender's) has checked the credential of a send whose
// recipient is registered at a peer, resolved that one home hub and taken
// the sender's own bucket; it hands the envelope on to that hub, and to no
// other (SI-17). The request is the envelope itself with its X-ANet-Access,
// signed by the origin hub for fed_forward. It carries nothing about the
// sender: a first contact was authenticated by the origin, a send under a
// credential names no sender at all. There is one hop: the destination is
// the recipient's home and forwards nothing further.
//
// The destination answers in the order of §4.2.7. Steps 1 to 4 (the peer
// table, the source hub's bucket, the body, the signature and RC1) are
// authPeer's; steps 5 to 13 (the headers, the credential, the envelope,
// the recipient, the buckets and the mailbox) are the kernel's
// (Kernel.ServeForward), because they are the kernel's own checks and
// state.

// forwardTimeout bounds one forward at the origin (sealed-sender SSR-H13):
// past it the sender is told home_unreachable.
const forwardTimeout = 30 * time.Second

// hForward serves POST /fed/v3/forward.
func (s *Service) hForward(w http.ResponseWriter, r *http.Request) {
	limit := int64(defaultMaxEnvelope)
	if s.kernel != nil {
		limit = s.kernel.MaxEnvelope()
	}
	peer, body, ok := s.authPeer(w, r, relayauth.ActionFedForward, s.Enabled(), limit, s.sourceGate)
	if !ok {
		return
	}
	s.kernel.ServeForward(w, r, peer.AID, body)
}

// sourceGate is step 2 of /fed/v3/forward: the asking hub's bucket, looked
// at without taking a token. It is keyed by the AID the request names,
// before the signature is checked, which is why it only looks: a caller
// naming a peer it is not cannot drain that peer's bucket.
func (s *Service) sourceGate(w http.ResponseWriter, peerAID string) bool {
	if empty, wait := s.kernel.ForwardSourceEmpty(peerAID); empty {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonSourceRate, RetryAfter: wait})
		return false
	}
	return true
}

// Forward hands one envelope on to the peer hub peerAID with POST
// /fed/v3/forward (the origin's half of SSR-H13): the envelope as the body,
// access as X-ANet-Access, signed for fed_forward. The response is the
// caller's to read and close; the kernel maps it to its answer to the
// sender.
//
// A refusal for the signing time (ts_stale) is signed again above the
// peer's floor once (Signer.Do), and so is a replayed one: RC1 refuses a
// time it took before, which a retry of the origin's own makes with a new
// time. A peer that is not a delivery peer, a peer this hub stopped talking
// to (peerwire.go), a network failure and no answer within forwardTimeout
// are errors.
func (s *Service) Forward(ctx context.Context, peerAID string, envelope []byte, access string) (*http.Response, error) {
	p := s.deliveryPeer(peerAID)
	if p == nil {
		return nil, errNotADeliveryPeer(peerAID)
	}
	ctx, cancel := context.WithTimeout(ctx, forwardTimeout)
	req := Request{Method: http.MethodPost, URL: strings.TrimSuffix(p.Endpoint, "/") + "/fed/v3/forward",
		ContentType: envelopeContentType, Body: envelope, Header: http.Header{headerAccess: {access}}}
	resp, err := s.signer.Do(ctx, p.AID, relayauth.ActionFedForward, req)
	if err == nil && refusedFor(resp, wire3.ReasonReplayed) {
		resp.Body.Close()
		resp, err = s.signer.Do(ctx, p.AID, relayauth.ActionFedForward, req)
	}
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = cancelOnClose{resp.Body, cancel}
	return resp, nil
}

// The headers and the media type of a forward (core §2.12.1).
const (
	headerAccess        = "X-ANet-Access"
	envelopeContentType = "application/vnd.anet.envelope+cbor"
)

// refusedFor reports whether resp is a wire-3 refusal for reason. It reads
// at most the start of the body and puts it back.
func refusedFor(resp *http.Response, reason wire3.Reason) bool {
	if resp.StatusCode < 400 {
		return false
	}
	head, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
	var out struct {
		Reason string `json:"reason"`
	}
	return json.Unmarshal(head, &out) == nil && out.Reason == string(reason)
}

// cancelOnClose ends a request's context when its response body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
