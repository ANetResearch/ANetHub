package aghub_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/seal"
)

// A peer hub's cached key set of a foreign agent: a set a holder of the agent's key signed with seq 2^62
// stays the high-water mark after the agent rotates, so the agent's new keys never replace it.
func TestFedKeySetPoisonDoesNotSurviveRotation(t *testing.T) {
	peer := openPeerStore(t)
	agent, _ := twoAgents(t)
	unsigned := a2aCardFor(agent, 1)
	e1 := a2aEntry(t, agent, signA2A(t, agent, unsigned))
	e1.Keys, _ = mintKeySet(t, agent, uint64(time.Now().UnixMilli()))
	if err := peer.AdmitFedA2ACard(homePeerAID, e1); err != nil {
		t.Fatal(err)
	}
	e2 := a2aEntry(t, agent, signA2A(t, agent, unsigned))
	e2.Keys, _ = mintKeySet(t, agent, uint64(1)<<62)
	if err := peer.AdmitFedA2ACard(homePeerAID, e2); err != nil {
		t.Fatal(err)
	}
	if err := identitytest.Rotate(agent, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	e3 := a2aEntry(t, agent, signA2A(t, agent, unsigned))
	e3.Keys, _ = mintKeySet(t, agent, uint64(time.Now().UnixMilli()))
	if err := peer.AdmitFedA2ACard(homePeerAID, e3); err != nil {
		t.Fatalf("admit after rotation: %v", err)
	}
	ks, kel, err := peer.FedA2ACardKeys(agent.AID())
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := seal.UnmarshalSignedEncKeySet(ks)
	if !bytes.Equal(ks, mustSigned(t, e3.Keys)) {
		t.Fatal("the key set the agent signed after its rotation was not stored")
	}
	t.Logf("stored key set is the new one: %v ; is the poisoned one: %v ; signed under key_state_seq %d (KEL has %d bytes)",
		bytes.Equal(ks, mustSigned(t, e3.Keys)), bytes.Equal(ks, mustSigned(t, e2.Keys)), signed.KeyStateSeq, len(kel))
}

func mustSigned(t *testing.T, b []byte) []byte {
	s, err := seal.UnmarshalSignedEncKeySet(b)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := s.Marshal()
	return c
}
