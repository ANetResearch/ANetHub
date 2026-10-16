package aghub_test

import (
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity/identitytest"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// T-1: a holder of the agent's signing key lists a card with a huge params.seq; after the owner rotates,
// the owner's own cards are refused as a rollback (card_status conflict), seq after seq.
func TestCardSeqPoisonDoesNotSurviveRotation(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	if got := registerA2A(t, hub.srv, agent, "Agent", nil, signA2A(t, agent, a2aCardFor(agent, 1))); got.CardStatus != aghub.CardStatusOK {
		t.Fatalf("first card: %+v", got)
	}
	const huge = uint64(1) << 62
	got := registerA2A(t, hub.srv, agent, "Agent", nil, signA2A(t, agent, a2aCardFor(agent, huge)))
	t.Logf("thief card seq 2^62: %+v", got)
	if err := identitytest.Rotate(agent, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	registerA2A(t, hub.srv, agent, "Agent", nil, nil)
	// The card the old key signed cannot be replayed under the rotated key state, so its seq is no
	// floor: the owner's cards are admitted at any seq (T-1 RT-F1b).
	got = registerA2A(t, hub.srv, agent, "Agent", nil, signA2A(t, agent, a2aCardFor(agent, 2)))
	if got.CardStatus != aghub.CardStatusOK {
		t.Fatalf("owner card seq 2 after rotation: status=%q error=%q", got.CardStatus, got.CardError)
	}
}
