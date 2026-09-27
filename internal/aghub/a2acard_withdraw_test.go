package aghub_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
)

// 0017 Q6: "a2a_card": null withdraws the agent's card — card and index
// rows deleted, card_status "withdrawn", a peer told on /fed/v2/cards when
// the agent federates, the declared name and capabilities standing — while
// an absent field still changes nothing. The card can be published again.
func TestANullCardWithdrawsTheCard(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	card := signA2A(t, agent, a2aCardFor(agent, 1, withSkills([]string{"echo", "Echo", "text"})))
	if got := registerA2A(t, hub.srv, agent, "Agent", []string{"declared.cap"}, card); got.CardStatus != aghub.CardStatusOK {
		t.Fatalf("register: %+v", got)
	}
	setVisibility(t, hub.srv, agent, aghub.VisibilityFederated)
	_, cursor := a2aStream(t, hub.store, 0)

	// Absent: nothing changes.
	if got := registerA2A(t, hub.srv, agent, "Agent", []string{"declared.cap"}, nil); got.CardStatus != aghub.CardStatusAbsent {
		t.Fatalf("absent field: %+v", got)
	}
	if len(registryAIDs(registry(t, hub.srv, "?skill=echo"))) != 1 {
		t.Fatal("a registration without the field unpublished the card")
	}

	got := registerA2A(t, hub.srv, agent, "Agent", []string{"declared.cap"}, json.RawMessage("null"))
	if got.CardStatus != aghub.CardStatusWithdrawn || got.CardError != "" {
		t.Fatalf("null: %+v", got)
	}
	if aids := registryAIDs(registry(t, hub.srv, "")); len(aids) != 0 {
		t.Fatalf("the withdrawn card is still listed: %v", aids)
	}
	if code, _ := getJSON(t, hub.srv.URL+"/a2a/v1/agents/"+agent.AID()+"/card"); code != http.StatusNotFound {
		t.Fatalf("card endpoint after withdrawal: %d", code)
	}
	if e := directoryEntry(t, hub.srv, "declared.cap", agent.AID()); e == nil {
		t.Fatal("the declared capability no longer names the agent")
	}
	if e := directoryEntry(t, hub.srv, "echo", agent.AID()); e != nil {
		t.Fatal("the withdrawn card's skill still names the agent")
	}
	entries, cursor := a2aStream(t, hub.store, cursor)
	if len(entries) != 1 {
		t.Fatalf("stream after the withdrawal: %+v", entries)
	}
	if aid, reason := withdrawnAID(t, entries[0]); aid != agent.AID() || reason != "card-withdrawn" {
		t.Fatalf("withdrawal names %q for %q", aid, reason)
	}

	// Again: still withdrawn, nothing more on the stream.
	if got := registerA2A(t, hub.srv, agent, "Agent", nil, json.RawMessage("null")); got.CardStatus != aghub.CardStatusWithdrawn {
		t.Fatalf("second null: %+v", got)
	}
	if more, _ := a2aStream(t, hub.store, cursor); len(more) != 0 {
		t.Fatalf("a second withdrawal went on the stream: %+v", more)
	}

	// Published again, after the withdrawal.
	again := signA2A(t, agent, a2aCardFor(agent, 2, withSkills([]string{"echo", "Echo", "text"})))
	if got := registerA2A(t, hub.srv, agent, "Agent", nil, again); got.CardStatus != aghub.CardStatusOK {
		t.Fatalf("republish: %+v", got)
	}
	if len(registryAIDs(registry(t, hub.srv, "?skill=echo"))) != 1 {
		t.Fatal("the republished card is not listed")
	}
	if all, _ := a2aStream(t, hub.store, 0); len(all) != 1 || all[0].Format != federation.FormatA2ACard {
		t.Fatalf("the full stream after republishing: %+v", all)
	}
}

// A position on the A2A card stream is never given out twice: a card
// withdrawn from the head by an agent that does not federate (so no
// withdrawal takes its place) does not hand its position to the next card.
func TestTheA2ACardStreamNeverReusesAPosition(t *testing.T) {
	hub := newFedHub(t)
	quiet, loud := twoAgents(t)
	if got := registerA2A(t, hub.srv, quiet, "Quiet", nil, signA2A(t, quiet, a2aCardFor(quiet, 1))); got.CardStatus != aghub.CardStatusOK {
		t.Fatalf("quiet: %+v", got)
	}
	if got := registerA2A(t, hub.srv, quiet, "Quiet", nil, json.RawMessage("null")); got.CardStatus != aghub.CardStatusWithdrawn {
		t.Fatalf("quiet withdraws: %+v", got)
	}
	registerA2A(t, hub.srv, loud, "Loud", nil, nil)
	setVisibility(t, hub.srv, loud, aghub.VisibilityPublic)
	if got := registerA2A(t, hub.srv, loud, "Loud", nil, signA2A(t, loud, a2aCardFor(loud, 1))); got.CardStatus != aghub.CardStatusOK {
		t.Fatalf("loud: %+v", got)
	}
	entries, _ := a2aStream(t, hub.store, 0)
	if len(entries) != 1 || entries[0].FedSeq <= 1 {
		t.Fatalf("stream %+v: the withdrawn card's position 1 was given out again", entries)
	}
}

// homeHub is the configured public base URL when there is one, else the
// origin the request came in at.
func TestHomeHubIsTheConfiguredPublicURL(t *testing.T) {
	srv := newHub(t)
	agent, _ := twoAgents(t)
	registerA2A(t, srv, agent, "Agent", nil, signA2A(t, agent, a2aCardFor(agent, 1)))
	if l := registry(t, srv, ""); len(l.Agents) != 1 || l.Agents[0].HomeHub != srv.URL {
		t.Fatalf("without a public URL: %+v", l.Agents)
	}
	s := serverOf(t, srv)
	for _, bad := range []string{"hub.example.org", "ftp://hub.example.org", "https://u:p@hub.example.org", "https://hub.example.org/?x=1"} {
		if err := s.SetPublicURL(bad); err == nil {
			t.Errorf("%q accepted as a public URL", bad)
		}
	}
	if err := s.SetPublicURL("https://hub.example.org/"); err != nil {
		t.Fatal(err)
	}
	if l := registry(t, srv, ""); len(l.Agents) != 1 || l.Agents[0].HomeHub != "https://hub.example.org" {
		t.Fatalf("with a public URL: %+v", l.Agents)
	}
}
