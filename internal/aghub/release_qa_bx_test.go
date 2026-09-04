package aghub_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// rfc3339Ago renders a timestamp d in the past the way the hub stores one.
func rfc3339Ago(d time.Duration) string {
	return time.Now().UTC().Add(-d).Format(time.RFC3339)
}

// An agent that registered and then never once collected mail used to be
// permanently exempt from the thirty-day rule, because Browsable
// returned true for an empty LastSeen without looking any further. The
// shape of row most likely to be abandoned was the one shape that could
// never be delisted.
//
// The fallback must not go the other way either: "registered, has not
// polled yet" is unknown, not dead, and gets the same window everybody
// else gets.
func TestAnAgentThatNeverPolledIsJudgedByItsRegistrationDate(t *testing.T) {
	for _, tc := range []struct {
		name string
		av   aghub.AgentView
		want bool
	}{
		{"registered long ago, never polled", aghub.AgentView{
			RegisteredAt: rfc3339Ago(aghub.AbandonedAfter + 24*time.Hour)}, false},
		{"registered just now, never polled", aghub.AgentView{
			RegisteredAt: rfc3339Ago(time.Minute)}, true},
		{"registered long ago but polling", aghub.AgentView{
			RegisteredAt: rfc3339Ago(aghub.AbandonedAfter + 24*time.Hour),
			LastSeen:     rfc3339Ago(time.Minute)}, true},
		{"registered recently, stopped polling long ago", aghub.AgentView{
			RegisteredAt: rfc3339Ago(time.Minute),
			LastSeen:     rfc3339Ago(aghub.AbandonedAfter + 24*time.Hour)}, false},
		// A timestamp we cannot read says nothing about whether the
		// agent answers, so it must not be read as "dead".
		{"no timestamps at all", aghub.AgentView{}, true},
		{"unparseable registration date", aghub.AgentView{RegisteredAt: "last tuesday"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.av.Browsable(); got != tc.want {
				t.Fatalf("Browsable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Leaving a hub removes the routing and keeps the evidence. That was
// true in storage and false over HTTP: every read of a review hung off
// the registration row, so deregistering left the reviews, the receipts
// they anchor and the departed KEL in the database with no way for a
// third party to reach them. The claim is only worth making if somebody
// outside can still check it.
func TestReviewsStayReadableAfterTheAgentLeaves(t *testing.T) {
	srv := newHub(t)
	prov, _ := identity.Incept()
	req, _ := identity.Incept()
	register(t, srv, prov, "Provider", []string{"bakery"})
	register(t, srv, req, "Requester", nil)
	if code, b := post(t, srv.URL+"/reviews", makeEvidence(t, prov, req, "ix_leave", 5, "")); code != 200 {
		t.Fatalf("setup: review upload %d %s", code, b)
	}
	// What the reviews look like while it is still registered. The
	// invariant is that deregistering changes the routing and nothing
	// about this, so compare against it rather than against a hand-
	// written expectation that could drift from the fixture.
	codeBefore, bodyBefore := getJSON(t, srv.URL+"/agents/"+prov.AID())
	if codeBefore != 200 {
		t.Fatalf("setup: live agent reads %d", codeBefore)
	}
	var before struct {
		Reviews json.RawMessage `json:"reviews"`
	}
	if err := json.Unmarshal(bodyBefore, &before); err != nil {
		t.Fatal(err)
	}

	if code, _ := leave(t, srv, prov); code != 200 {
		t.Fatal("setup: deregister failed")
	}

	code, body := getJSON(t, srv.URL+"/agents/"+prov.AID())
	if code != 200 {
		t.Fatalf("departed agent: got %d, want 200 — the evidence has no HTTP surface", code)
	}
	var got struct {
		Agent struct {
			AID         string  `json:"aid"`
			Departed    bool    `json:"departed"`
			Registered  bool    `json:"registered"`
			Listed      bool    `json:"listed"`
			ReviewCount int     `json:"review_count"`
			AvgRating   float64 `json:"avg_rating"`
		} `json:"agent"`
		Reviews json.RawMessage `json:"reviews"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Agent.Departed {
		t.Error("departed flag not set — a caller cannot tell this from a live agent")
	}
	if got.Agent.Registered || got.Agent.Listed {
		t.Error("a departed agent must not read as registered or listed")
	}
	if got.Agent.ReviewCount != 1 || got.Agent.AvgRating != 5 {
		t.Errorf("aggregate lost: count=%d avg=%v", got.Agent.ReviewCount, got.Agent.AvgRating)
	}
	// The detail, not just the aggregate number: the interaction content
	// and its content anchors are what let a third party re-derive the
	// hashes in the receipt, which is the whole point of keeping it.
	if string(got.Reviews) != string(before.Reviews) {
		t.Errorf("review payload changed when the agent left\n before: %s\n  after: %s",
			before.Reviews, got.Reviews)
	}
	if !strings.Contains(string(got.Reviews), "ix_leave") ||
		!strings.Contains(string(got.Reviews), "receipt_cid") {
		t.Errorf("review detail missing after departure: %s", got.Reviews)
	}
}

// An AID this hub has never seen is not a departure. Answering 200 for
// every unknown string would make the departed view meaningless.
func TestAnUnknownAIDStillGets404(t *testing.T) {
	srv := newHub(t)
	stranger, _ := identity.Incept()
	if code, _ := getJSON(t, srv.URL+"/agents/"+stranger.AID()); code != 404 {
		t.Fatalf("unknown AID: got %d, want 404", code)
	}
	// And an agent that leaves without ever being reviewed has no
	// evidence to preserve, so it is unknown too.
	quitter, _ := identity.Incept()
	register(t, srv, quitter, "Quitter", nil)
	if code, _ := leave(t, srv, quitter); code != 200 {
		t.Fatal("setup: deregister failed")
	}
	if code, _ := getJSON(t, srv.URL+"/agents/"+quitter.AID()); code != 404 {
		t.Fatalf("departed with no reviews: got %d, want 404", code)
	}
}

// The register path bounds the capability list, but a card carries its
// own list and reaches the same /agents responses by a different route.
// Bounding one entrance only moves which request opens the amplification.
func TestCardAdmissionBoundsTheCapabilityList(t *testing.T) {
	st, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	c, _ := identity.Incept()
	kelBytes, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutAgent(c.AID(), "Carder", []string{"work.do"}, 0, kelBytes); err != nil {
		t.Fatal(err)
	}

	huge := make([]string, 300000)
	for i := range huge {
		huge[i] = "cap.flood"
	}
	card, _ := json.Marshal(map[string]any{
		"subject_did": c.AID(), "name": "Carder", "capabilities": huge,
	})
	err = st.AdmitCard(c.AID(), card, c.KEL())
	if err == nil {
		t.Fatal("a card declaring 300000 capabilities was admitted")
	}
	if !strings.Contains(err.Error(), "capabilities") {
		t.Errorf("refusal does not say what was wrong: %v", err)
	}

	long, _ := json.Marshal(map[string]any{
		"subject_did": c.AID(), "name": "Carder",
		"capabilities": []string{strings.Repeat("x", 100000)},
	})
	if err := st.AdmitCard(c.AID(), long, c.KEL()); err == nil {
		t.Fatal("a card with a 100000-byte capability id was admitted")
	}
}
