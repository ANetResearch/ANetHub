package aghub

import (
	"errors"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
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

// KEL H-34, H-15, wired as cmd/anet-hub wires them: a peer's directory
// entry carries the notice its witness hub signed. When that hub rotated
// after this one pinned its key history, the notice names a key state past
// the pin; the pin is fetched again, extended, and the entry is taken.
func TestAPeerNoticeUnderANewKeyFetchesTheKeyHistoryAgain(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	a.store.SetPeerKELRefresher(a.fed.RefreshPeerKEL)
	if kel, err := a.fed.PeerKEL(b.hubAID); err != nil || len(kel) != 1 {
		t.Fatalf("A's pin of B: %d events, %v", len(kel), err)
	}
	// B rotates (its first rotation reveals its icp's hot key).
	if err := b.hubID.Rotate(nil, identitytest.NewNext(), false, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	// An agent registered at B, which B witnesses, with B's notice signed
	// under B's new key in its directory entry.
	ctl, err := identitytest.Agent()
	if err != nil {
		t.Fatal(err)
	}
	if err := identitytest.SwitchWitness(ctl, b.hubAID, identitytest.InceptTS+1000); err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(ctl.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.store.PutAgent(ctl.AID(), "witnessed", nil, kel); err != nil {
		t.Fatal(err)
	}
	states, err := identity.Replay(ctl.KEL())
	if err != nil {
		t.Fatal(err)
	}
	tip := states[len(states)-1]
	notice, err := identity.SignNotice(b.hubID.Ctrl, identity.NoticeBody{AID: ctl.AID(), Seq: tip.KeyStateSeq,
		Head: tip.LastEventID, ObservedAt: b.nowMS()})
	if err != nil {
		t.Fatal(err)
	}
	if _, env, err := identity.DecodeNotice(notice); err != nil || env.KeyStateSeq != 1 {
		t.Fatalf("B's notice is not under its new key: %v", err)
	}
	b.store.SetDirNoticeForTest(func(aid string) []byte {
		if aid == ctl.AID() {
			return notice
		}
		return nil
	})
	ag := &relayAgent{c: ctl, aid: ctl.AID()}
	b.publish(ag, 1)
	h, _ := dirbox.Hash(ag.aid)
	entries, _, err := b.store.DirBucket(h, dirbox.HashBits, nil)
	if err != nil || len(entries) != 1 {
		t.Fatalf("B's entry: %v %v", entries, err)
	}
	pe := peerEntry{h: mustB64(t, entries[0].H), box: mustB64(t, entries[0].Box)}
	if _, ok := a.srv.verifyEntry(ag.aid, b.hubAID, pe, a.clock()); !ok {
		t.Fatal("an entry whose witness notice is under the witness's new key was not taken")
	}
	if kel, err := a.fed.PeerKEL(b.hubAID); err != nil || len(kel) != 2 {
		t.Fatalf("A's pin of B after the entry: %d events, %v", len(kel), err)
	}
}
