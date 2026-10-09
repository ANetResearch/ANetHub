package federation

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Federation v3 (sealed-sender §2.8, core G3, G21): every /fed/v3 route is
// open to the hubs of the peer table only, and every request to one is
// signed with relayauth v2 under the asking hub's identity, for the route's
// fed_* action. authPeer is the one place that checks it (SSR-H16); the
// routes of other areas (fed_status, fed_settle, fed_reviews, fed_clear)
// use it too.

// Kernel is what the federation routes need from the hub kernel
// (internal/aghub implements it on *aghub.Server; cmd/anet-hub wires it with
// SetKernel). Its methods take standard types only, so neither package
// imports the other for it (K207).
type Kernel interface {
	// PeerRC1 is RC1 (hub-payment-privacy §4.2.5) for a verified signature
	// of the peer hub aid at ts, with K = 4096 (core G17). It answers false
	// after writing the refusal, the same bodies an agent gets: ts_stale
	// with the floor, replayed, unauthorized.
	PeerRC1(w http.ResponseWriter, aid string, ts uint64) bool
	// ForwardSourceEmpty reports, without taking a token, whether the
	// source-hub bucket of the peer aid is empty, and how long until it is
	// not (/fed/v3/forward step 2).
	ForwardSourceEmpty(aid string) (empty bool, wait time.Duration)
	// ServeForward answers /fed/v3/forward from step 5 on (sealed-sender
	// §4.2.7) for a request the peer aid signed, whose body is body.
	ServeForward(w http.ResponseWriter, r *http.Request, aid string, body []byte)
	// ServeBucket answers /fed/v3/directory:bucket for a request a peer
	// signed, whose body is body: the bucket of this hub's own entries.
	ServeBucket(w http.ResponseWriter, body []byte)
	// MaxEnvelope is the largest envelope this hub carries.
	MaxEnvelope() int64
}

// SetKernel wires the kernel the /fed/v3 routes answer through. Without one
// /fed/v3/forward and /fed/v3/directory:bucket refuse every request.
func (s *Service) SetKernel(k Kernel) { s.kernel = k }

// hubAuth is the parsed relayauth v2 header tuple of a hub-to-hub request.
type hubAuth struct {
	aid string
	ts  uint64
	seq uint64
	sig []byte
}

// parseHubAuth reads the four relayauth headers, each exactly once, the
// numbers in canonical decimal.
func parseHubAuth(r *http.Request) (hubAuth, error) {
	get := func(name string) (string, bool) {
		vs := r.Header.Values(name)
		if len(vs) != 1 || vs[0] == "" {
			return "", false
		}
		return vs[0], true
	}
	aid, ok1 := get(relayauth.HeaderAID)
	ts, ok2 := get(relayauth.HeaderTS)
	seq, ok3 := get(relayauth.HeaderSeq)
	sig, ok4 := get(relayauth.HeaderSig)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return hubAuth{}, errors.New("A federation request is signed by the asking hub with " + relayauth.HeaderAID +
			", " + relayauth.HeaderTS + ", " + relayauth.HeaderSeq + " and " + relayauth.HeaderSig + "; sign it and send it again.")
	}
	var a hubAuth
	var err error
	a.aid = aid
	if a.ts, err = strconv.ParseUint(ts, 10, 64); err != nil || strconv.FormatUint(a.ts, 10) != ts {
		return hubAuth{}, errors.New(relayauth.HeaderTS + " is not a time in canonical decimal; sign the request again.")
	}
	if a.seq, err = strconv.ParseUint(seq, 10, 64); err != nil || strconv.FormatUint(a.seq, 10) != seq {
		return hubAuth{}, errors.New(relayauth.HeaderSeq + " is not a key state in canonical decimal; sign the request again.")
	}
	if a.sig, err = relayauth.DecodeSig(sig); err != nil {
		return hubAuth{}, errors.New(relayauth.HeaderSig + " is not a signature; sign the request again.")
	}
	return a, nil
}

// peerGate is a check a route makes between knowing which peer asks and
// reading the body (/fed/v3/forward step 2). It writes its refusal and
// answers false to stop.
type peerGate func(w http.ResponseWriter, peerAID string) bool

// authPeer authenticates one /fed/v3 request for action (SSR-H16, core G3),
// in this order (sealed-sender §4.2.7 steps 1 to 4):
//
//  1. the signer the request names (X-ANet-AID, once) is a hub of the peer
//     table (open is the route's switch): 403 not_peer, before anything
//     else of the request is looked at; a request that names no signer is
//     not signed: 401 unauthorized;
//  2. the other three relayauth headers: 401 unauthorized;
//  3. gate, when the route has one (the source-hub bucket of a forward);
//  4. the body, at most limit bytes: 413 too_large;
//  5. the signing time within MaxSkew of this hub's clock, then the
//     signature over the L22 preimage (action, the peer, this hub, the time,
//     method, request target and body) under the peer's pinned KEL:
//     401 unauthorized, or key_retired for a key the peer has rotated away
//     from;
//  6. RC1 for the peer (K = 4096, Kernel.PeerRC1): 401 ts_stale, replayed.
//
// It returns the peer and the body, or false once it has answered.
func (s *Service) authPeer(w http.ResponseWriter, r *http.Request, action string, open bool, limit int64, gate peerGate) (*Peer, []byte, bool) {
	if vs := r.Header.Values(relayauth.HeaderAID); len(vs) == 1 && vs[0] != "" {
		if !open || s.peer(vs[0]) == nil || s.kernel == nil {
			wire3.Refuse(w, wire3.ReasonNotPeer)
			return nil, nil, false
		}
	}
	a, err := parseHubAuth(r)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized, Error: err.Error()})
		return nil, nil, false
	}
	peer := s.peer(a.aid)
	if gate != nil && !gate(w, peer.AID) {
		return nil, nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonTooLarge,
				Error: fmt.Sprintf("A request of this route is at most %d bytes; send a smaller one.", limit)})
			return nil, nil, false
		}
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest, Error: "The request body could not be read; send it again."})
		return nil, nil, false
	}
	if !withinMaxSkew(a.ts, s.now()) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized,
			Error: fmt.Sprintf("%s is more than %d minutes from this hub's clock; correct the clock and sign again.",
				relayauth.HeaderTS, relayauth.MaxSkewMillis/60_000)})
		return nil, nil, false
	}
	kel, err := s.peerKEL(peer)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized,
			Error: "This hub could not obtain your hub's key history from your /hub/identity; make it reachable and send again."})
		return nil, nil, false
	}
	pre := relayauth.PreimageV2(action, a.aid, s.id.AID, a.ts, r.Method, r.URL.RequestURI(), body)
	if err := verifyPeerSignature(kel, a, pre); err != nil {
		var ve *identity.VErr
		if errors.As(err, &ve) && ve.Reason == "REVOKED_KEY" {
			wire3.Refuse(w, wire3.ReasonKeyRetired)
			return nil, nil, false
		}
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized,
			Error: "The signature does not verify against the key history this hub holds for your hub, for action " +
				strconv.Quote(action) + "; sign it again with your hub's current key."})
		return nil, nil, false
	}
	if !s.kernel.PeerRC1(w, a.aid, a.ts) {
		return nil, nil, false
	}
	return peer, body, true
}

// verifyPeerSignature is identity.VerifyObject for a peer's request
// signature; a test counts the verifications through it.
var verifyPeerSignature = func(kel []identity.SignedEvent, a hubAuth, pre []byte) error {
	return identity.VerifyObject(kel, a.aid, a.seq, a.ts, pre, a.sig)
}

// withinMaxSkew reports whether the unix-ms time ts is within
// relayauth.MaxSkewMillis of now.
func withinMaxSkew(ts uint64, now time.Time) bool {
	if ts > uint64(1)<<62 {
		return false
	}
	d := now.UnixMilli() - int64(ts)
	if d < 0 {
		d = -d
	}
	return d <= relayauth.MaxSkewMillis
}
