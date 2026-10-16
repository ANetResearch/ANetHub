package aghub_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// The A2A card stream carries the witness notice of each card's KEL tip
// (core §2.12.2 key_state_notice): the home hub serves the notice its
// directory entry carries, and a peer keeps it with the card when it
// decodes as a notice about that agent and is no larger than a notice is,
// and drops it otherwise (it is advisory, as the key set is: a reader
// verifies it itself).
func TestTheCardStreamCarriesTheNotice(t *testing.T) {
	hub := newFedHub(t)
	agent, other := twoAgents(t)
	federate(t, hub, agent, "Noticed", []string{"n"})
	witness, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	noticeOf := func(c *identity.Controller) []byte {
		t.Helper()
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
		return n
	}
	notice := noticeOf(agent)
	// A notice about the agent that decodes, but whose head is no event id:
	// a peer could fill a row with it.
	oversized, err := identity.SignNotice(witness.Ctrl, identity.NoticeBody{AID: agent.AID(), Seq: 1,
		Head: strings.Repeat("h", 8<<10), ObservedAt: uint64(time.Now().UnixMilli())})
	if err != nil {
		t.Fatal(err)
	}
	hub.store.SetDirNoticeForTest(func(aid string) []byte {
		if aid == agent.AID() {
			return notice
		}
		return nil
	})
	// Through the seam the federation module reads the kernel by.
	views, _, err := aghub.FedDirectory{S: hub.store}.A2ACardsSince(0, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	var entry *federation.FedA2ACardView
	for i, e := range views {
		if e.Format == federation.FormatA2ACard && bytes.Equal(e.Notice, notice) {
			entry = &views[i]
		}
	}
	if entry == nil {
		t.Fatalf("no card entry of the stream carries the agent's notice: %+v", views)
	}
	for _, tc := range []struct {
		name   string
		notice []byte
		kept   bool
	}{
		{"the agent's notice", notice, true},
		{"another agent's notice", noticeOf(other), false},
		{"not a notice", []byte("not a notice"), false},
		{"a notice larger than a notice is", oversized, false},
		{"none", nil, false},
	} {
		peer := openPeerStore(t)
		e := *entry
		e.Notice = tc.notice
		if err := (aghub.FedDirectory{S: peer}).AdmitFedA2ACard(homePeerAID, e); err != nil {
			t.Fatalf("%s: the card was refused: %v", tc.name, err)
		}
		got := peer.FedCardNoticeForTest(agent.AID())
		if tc.kept != (got != nil) || tc.kept && !bytes.Equal(got, tc.notice) {
			t.Errorf("%s: kept %x", tc.name, got)
		}
	}
}
