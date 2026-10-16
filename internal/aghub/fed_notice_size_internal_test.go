package aghub

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// A notice that is about the tip but is larger than a notice is (or is the
// size of one with bytes behind it) is not kept from a peer's card stream.
func TestFedNoticeToStoreKeepsOnlyNoticeSized(t *testing.T) {
	c, err := NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	witness, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	states, err := identity.Replay(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	tip := states[len(states)-1]
	n, err := identity.SignNotice(witness.Ctrl, identity.NoticeBody{AID: c.AID(), Seq: tip.KeyStateSeq,
		Head: tip.LastEventID, ObservedAt: uint64(time.Now().UnixMilli())})
	if err != nil {
		t.Fatal(err)
	}
	if got := fedNoticeToStore(tip, n); got == nil || !bytes.Equal(got.([]byte), n) {
		t.Fatalf("a notice of the tip was not kept: %v", got)
	}
	big := append(append([]byte{}, n...), []byte(strings.Repeat("x", maxFedNotice))...)
	if got := fedNoticeToStore(tip, big); got != nil {
		t.Fatalf("a notice of %d bytes was kept", len(big))
	}
}
