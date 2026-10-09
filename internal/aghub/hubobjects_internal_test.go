package aghub

import (
	"errors"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
)

// KEL H-34, H-15: an object a peer hub signed under a key state past the
// key history the resolver holds has that history fetched again, once; one
// the history reaches does not.
func TestPeerKELForFetchesAgainForALaterKeyState(t *testing.T) {
	peer, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	b, err := peer.Export()
	if err != nil {
		t.Fatal(err)
	}
	stale, err := identity.Restore(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := identitytest.Rotate(peer, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	get := func(string) ([]identity.SignedEvent, error) { return stale.KEL(), nil }
	s := &Store{}
	if kel, err := s.peerKELFor(get, peer.AID(), 1); err != nil || len(kel) != 1 {
		t.Fatalf("without federation the resolver's history is all there is: %d %v", len(kel), err)
	}
	fetched := 0
	s.SetPeerKELRefresher(func(aid string) ([]identity.SignedEvent, error) {
		fetched++
		if aid != peer.AID() {
			return nil, errors.New("not the peer")
		}
		return peer.KEL(), nil
	})
	if kel, err := s.peerKELFor(get, peer.AID(), 1); err != nil || len(kel) != 2 || fetched != 1 {
		t.Fatalf("a later key state: %d events, fetched %d times, %v", len(kel), fetched, err)
	}
	if kel, err := s.peerKELFor(get, peer.AID(), 0); err != nil || len(kel) != 1 || fetched != 1 {
		t.Fatalf("a key state the history reaches: %d events, fetched %d times, %v", len(kel), fetched, err)
	}
	// A resolver that fails is helped by the fetch too.
	failing := func(string) ([]identity.SignedEvent, error) { return nil, errors.New("down") }
	if kel, err := s.peerKELFor(failing, peer.AID(), 0); err != nil || len(kel) != 2 {
		t.Fatalf("a failing resolver: %d %v", len(kel), err)
	}
}
