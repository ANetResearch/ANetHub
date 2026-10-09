package federation

import (
	"crypto/ed25519"
	"errors"
	"fmt"
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
	// PeerFloor is RC1's floor for the peer hub aid now, without taking
	// anything: a signing time at or below it is refused whatever its
	// signature, so authPeer refuses it before it reads the body (SSR-H16).
	PeerFloor(aid string) uint64
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
//  3. what the headers alone settle, before a byte of the body is read
//     (SSR-H16, 2026-10-09): the signing time within MaxSkew of this
//     hub's clock, above the peer's RC1 floor (Kernel.PeerFloor), and a key
//     state the pinned key history of the peer reaches (one past it has the
//     pin refreshed once, at most once a minute per peer; KEL H-15): 401
//     unauthorized. A signing time at or below the floor is refused as a
//     bad signature is, without the floor: a caller whose signature has not
//     been checked learns no floor (hub-payment-privacy PAY-R8);
//  4. gate, when the route has one (the source-hub bucket of a forward);
//  5. the body, at most limit bytes (a declared length over it is 413
//     too_large before any is read), within the bytes every /fed/v3
//     request holds at once (fedBodyBudget): 429 source_rate, Retry-After
//     1, past them;
//  6. the signature over the L22 preimage (action, the peer, this hub, the
//     time, method, request target and body), under the tip of the peer's
//     pinned key history only (core CORE-K16): 401 unauthorized, or
//     key_retired for a key the peer has rotated away from;
//  7. RC1 for the peer (K = 4096, Kernel.PeerRC1): 401 ts_stale, replayed.
//
// It returns the peer and the body, or false once it has answered.
func (s *Service) authPeer(w http.ResponseWriter, r *http.Request, action string, open bool, limit int64, gate peerGate) (*Peer, []byte, bool) {
	var peer *Peer
	if vs := r.Header.Values(relayauth.HeaderAID); len(vs) == 1 && vs[0] != "" {
		if peer = s.peer(vs[0]); !open || peer == nil || s.kernel == nil {
			wire3.Refuse(w, wire3.ReasonNotPeer)
			return nil, nil, false
		}
	}
	a, err := parseHubAuth(r)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized, Error: err.Error()})
		return nil, nil, false
	}
	if peer == nil || peer.AID != a.aid {
		// parseHubAuth read the one signer checked above; anything else
		// is no peer.
		wire3.Refuse(w, wire3.ReasonNotPeer)
		return nil, nil, false
	}
	kel, ok := s.peerHeaders(w, peer, a, action)
	if !ok {
		return nil, nil, false
	}
	if gate != nil && !gate(w, peer.AID) {
		return nil, nil, false
	}
	body, ok := s.readPeerBody(w, r, limit)
	if !ok {
		return nil, nil, false
	}
	pre := relayauth.PreimageV2(action, a.aid, s.id.AID, a.ts, r.Method, r.URL.RequestURI(), body)
	if retired, err := peerSignatureFailure(kel, a, pre); err != nil {
		if retired {
			wire3.Refuse(w, wire3.ReasonKeyRetired)
			return nil, nil, false
		}
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized, Error: peerSignatureRefusal(action)})
		return nil, nil, false
	}
	if !s.kernel.PeerRC1(w, a.aid, a.ts) {
		return nil, nil, false
	}
	return peer, body, true
}

// peerSignatureRefusal is the error of a request whose signature, or whose
// signing time, this hub does not take; the two are told alike (step 3).
func peerSignatureRefusal(action string) string {
	return "The signature does not verify for action " + strconv.Quote(action) +
		" against the key history this hub holds for your hub, or its time is not later than the times this hub " +
		"already took from your hub; sign the request again with your hub's current key at the current time."
}

// peerHeaders is step 3 of authPeer: what the relayauth headers of a settle
// before the body is read. It returns the peer's pinned key history, which
// reaches the key state a names, or false once it has answered.
func (s *Service) peerHeaders(w http.ResponseWriter, peer *Peer, a hubAuth, action string) ([]identity.SignedEvent, bool) {
	if !withinMaxSkew(a.ts, s.now()) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized,
			Error: fmt.Sprintf("%s is more than %d minutes from this hub's clock; correct the clock and sign again.",
				relayauth.HeaderTS, relayauth.MaxSkewMillis/60_000)})
		return nil, false
	}
	if a.ts <= s.kernel.PeerFloor(peer.AID) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized, Error: peerSignatureRefusal(action)})
		return nil, false
	}
	kel, err := s.peerKEL(peer)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized,
			Error: "This hub could not obtain your hub's key history from your /hub/identity; make it reachable and send again."})
		return nil, false
	}
	if a.seq >= uint64(len(kel)) {
		// Signed under a key state past the pin: the peer rotated since.
		if kel, err = s.RefreshPeerKEL(peer.AID); err != nil || a.seq >= uint64(len(kel)) {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized, Error: peerSignatureRefusal(action)})
			return nil, false
		}
	}
	return kel, true
}

// peerSignatureFailure checks a's signature over pre under kel, the peer's
// pinned key history, which reaches a.seq (core CORE-K16, KEL H-3 for
// hubs): a request speaks for the peer now only under the tip of its key
// history, while that tip is active. A signature that verifies under an
// earlier key state, one the peer has retired, is retired; anything else
// is an error.
func peerSignatureFailure(kel []identity.SignedEvent, a hubAuth, pre []byte) (retired bool, err error) {
	if err := verifyPeerSignature(kel, a, pre); err != nil {
		return false, err
	}
	states, err := identity.Replay(kel)
	if err != nil || states[len(states)-1].AID != a.aid {
		return false, errors.New("the pinned key history does not replay to the peer")
	}
	if tip := states[len(states)-1]; a.seq != tip.KeyStateSeq || tip.Status != identity.StatusActive {
		return true, fmt.Errorf("signed at key state %d; the peer's key history is at %d", a.seq, tip.KeyStateSeq)
	}
	return false, nil
}

// verifyPeerSignature checks a peer's request signature under the key the
// key state a.seq of kel names; a test counts the verifications through it.
// Whether that key state may still sign requests is peerSignatureFailure's
// rule, not a time's: a key the peer retired is told apart (key_retired).
var verifyPeerSignature = func(kel []identity.SignedEvent, a hubAuth, pre []byte) error {
	if a.seq >= uint64(len(kel)) || len(kel[a.seq].Event.Keys) != 1 ||
		len(kel[a.seq].Event.Keys[0]) != ed25519.PublicKeySize || len(a.sig) != ed25519.SignatureSize {
		return errors.New("no key of the peer at that key state")
	}
	if !ed25519.Verify(kel[a.seq].Event.Keys[0], pre, a.sig) {
		return errors.New("the signature does not verify")
	}
	return nil
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
