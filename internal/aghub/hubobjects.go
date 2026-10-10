package aghub

import (
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

// What a peer hub signed, checked here (KEL H-34, core CORE-L8): a witness
// notice in a peer's directory entry (fed_home.go), a settlement receipt
// (ClearFromPeer), a clearing statement (SettleOwed), a review attestation
// on the peer's review stream (reviews.go checkPeerAttestation). Each is
// verified under the peer's key history as it was when the object was
// signed: VerifyObject at the object's own time (the receipt's settle_at,
// the notice's observed_at, the attestation's day), not at now. A receipt a
// peer signed before it rotated stays good; a key the peer retired signs
// nothing dated after it.
//
// The peer's key history is the one the federation module pinned, which
// only grows (KEL H-15). A peer that rotated signs under a key state past
// the pin at once; the pin is then fetched again, once, and at most once a
// minute per peer (peerKELFor). relayauth fed_* is not here: a request
// speaks for the peer now, under the tip of its key history only (core
// CORE-K16; federation authPeer).

// SetPeerKELRefresher installs the federation hook that fetches a peer
// hub's key history again, for an object it signed under a key state past
// the pinned one. Without it (a build without federation) the pin is all
// there is.
func (s *Store) SetPeerKELRefresher(f func(aid string) ([]identity.SignedEvent, error)) {
	s.refreshPeerKEL = f
}

// peerKELFor is the key history of peer hub aid that get resolves, fetched
// again (refreshPeerKEL) when it does not reach the key state seq an object
// names.
func (s *Store) peerKELFor(get func(string) ([]identity.SignedEvent, error), aid string, seq uint64) ([]identity.SignedEvent, error) {
	kel, err := get(aid)
	if err == nil && seq < uint64(len(kel)) {
		return kel, nil
	}
	if s.refreshPeerKEL == nil {
		return kel, err
	}
	if fresh, ferr := s.refreshPeerKEL(aid); ferr == nil {
		return fresh, nil
	}
	return kel, err
}

// receiptSeq is the key state a receipt names its signer under, 0 for an
// unsigned one (which does not verify anyway).
func receiptSeq(r *payment.Receipt) uint64 {
	if r == nil || r.Envelope == nil {
		return 0
	}
	return r.Envelope.KeyStateSeq
}
