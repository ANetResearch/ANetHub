package aghub_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
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

// The landing figure and the directory have to be talking about the same
// set. GET /agents began merging peer-learned entries and Stats did not,
// so the hub's own two answers to "how many agents are here" differed by
// exactly the federated ones. Found by scripts/prodtest.sh against the
// live hub: /stats said 7 while /agents listed 8.
//
// The fix reports them separately rather than adding them together — a
// peer-learned agent is not registered here, and one number covering both
// would claim a reach this hub does not have. What must hold is that the
// two numbers together account for the directory.
//
// The federated entry is real, not assumed: an earlier version of this
// test used a hub with no peers, so the federated count was zero either
// way and removing the fix left it green.
func TestStatsAndTheDirectoryAgreeOnHowManyAgentsThereAre(t *testing.T) {
	// A hub that will learn one agent from a peer.
	home := newFedHub(t)
	remote, _ := identity.Incept()
	federate(t, home, remote, "Remote Provider", []string{"work.remote"})
	cards, _, err := home.store.CardsSince(0, 100, testHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 {
		t.Fatalf("setup: %d cards on the stream, want 1", len(cards))
	}

	// The hub under test: two local providers, one pure requester that
	// stays unlisted, plus the card learned from the peer.
	//
	// The federated directory hook has to be installed the way the
	// federation module installs it in production. Without it both /agents
	// and /stats simply see no peers, and this test would pass whether or
	// not the counting is right.
	store := openPeerStore(t)
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	server := aghub.NewServer(store)
	server.SetHubAID(id.AID)
	server.SetFederatedDirectory(store.FederatedAgents)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)

	for _, spec := range []struct {
		name string
		caps []string
	}{{"Local A", []string{"work.a"}}, {"Local B", []string{"work.b"}}, {"Watcher", nil}} {
		c, _ := identity.Incept()
		register(t, srv, c, spec.name, spec.caps)
	}
	if err := store.AdmitFedCard(homePeerAID, cards[0]); err != nil {
		t.Fatal(err)
	}

	code, body := getJSON(t, srv.URL+"/agents")
	if code != 200 {
		t.Fatalf("agents: %d", code)
	}
	var dir struct {
		Agents []struct {
			AID     string `json:"aid"`
			Listed  bool   `json:"listed"`
			HomeHub string `json:"home_hub"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(body, &dir); err != nil {
		t.Fatal(err)
	}
	listed, fromPeer := 0, 0
	for _, a := range dir.Agents {
		if !a.Listed {
			continue
		}
		listed++
		if a.HomeHub != "" {
			fromPeer++
		}
	}
	if fromPeer != 1 {
		t.Fatalf("setup: the directory shows %d peer-learned agents, want 1 — "+
			"without one this test cannot tell the fix from its absence", fromPeer)
	}

	code, body = getJSON(t, srv.URL+"/stats")
	if code != 200 {
		t.Fatalf("stats: %d", code)
	}
	var st struct {
		Agents    int `json:"agents"`
		Federated int `json:"federated_agents"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if got := st.Agents + st.Federated; got != listed {
		t.Errorf("/stats accounts for %d listed agents (%d local + %d federated) but /agents lists %d",
			got, st.Agents, st.Federated, listed)
	}
	if st.Agents != 2 {
		t.Errorf("local listed agents = %d, want 2 (the pure requester is not listed)", st.Agents)
	}
	if st.Federated != 1 {
		t.Errorf("federated = %d, want 1", st.Federated)
	}
}

// A capped list that does not say it is capped is a list that lies by
// omission. Once an account passes the page size a new withdrawal pushes
// the oldest one out, so the length stops changing: a caller counting the
// list to see whether its withdrawal landed gets the same number forever,
// with no field telling it the answer was a page rather than the history.
//
// Found by scripts/prodtest.sh against the live hub: "did the redemption
// appear in the list" stayed red through sixty seconds of polling while
// the very next check found a matching record — one left by an earlier run.
// dmax had exactly 100 rows, the cap, and had had for a while.
//
// hLedger already carried this shape; the withdrawals list did not.
func TestTheRedemptionListSaysWhenItIsOnlyAPage(t *testing.T) {
	srv := newHub(t)
	agent, _ := identity.Incept()
	register(t, srv, agent, "Withdrawer", nil)
	fundAgent(t, srv, agent.AID(), 400)
	hubAID := hubAIDOf(t, srv)

	const made = 4
	for i := 0; i < made; i++ {
		opt := payment.PaymentOption{
			Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
			Amount: "10", Asset: payment.AssetCredit, PayTo: hubAID,
		}
		ref := fmt.Sprintf("inv-%02d", i)
		if code, b := post(t, srv.URL+"/x402/redeem", map[string]any{
			"x402Version":    payment.Version,
			"paymentPayload": json.RawMessage(mustPayload(t, agent, opt, "redeem:"+ref)),
			"reference":      ref,
		}); code != 200 {
			t.Fatalf("seed %d: %d %s", i, code, b)
		}
	}

	// Ask for fewer than exist, which is what the cap does to a busy
	// account without being asked.
	code, body := getJSON(t, srv.URL+"/agents/"+agent.AID()+"/redemptions?limit=2")
	if code != 200 {
		t.Fatalf("redemptions: %d", code)
	}
	var got struct {
		Redemptions []struct {
			Reference string `json:"reference"`
			Amount    uint64 `json:"amount"`
		} `json:"redemptions"`
		Total     int    `json:"total"`
		Sum       uint64 `json:"sum"`
		Returned  int    `json:"returned"`
		Truncated bool   `json:"truncated"`
		Note      string `json:"note"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Redemptions) >= made {
		t.Fatalf("the page was not capped (%d of %d) — this test cannot tell the fix from its absence",
			len(got.Redemptions), made)
	}
	if got.Total != made {
		t.Errorf("total = %d, want %d — the count must cover the account, not the page", got.Total, made)
	}
	if want := uint64(made * 10); got.Sum != want {
		t.Errorf("sum = %d, want %d — sum must cover every withdrawal", got.Sum, want)
	}
	if got.Returned != len(got.Redemptions) {
		t.Errorf("returned = %d but %d entries came back", got.Returned, len(got.Redemptions))
	}
	if !got.Truncated {
		t.Error("the response does not say the list is only a page")
	}
	if got.Note == "" {
		t.Error("truncated with no note saying what to reconcile against")
	}
	// Newest first, so the most recent withdrawal is visible even when the
	// oldest are not — that is what makes "did mine land" answerable.
	if len(got.Redemptions) == 0 || got.Redemptions[0].Reference != "inv-03" {
		t.Errorf("newest entry is %+v, want inv-03", got.Redemptions)
	}

	// And an untruncated answer must not claim to be one.
	_, body = getJSON(t, srv.URL+"/agents/"+agent.AID()+"/redemptions")
	var full struct {
		Truncated bool `json:"truncated"`
		Total     int  `json:"total"`
		Returned  int  `json:"returned"`
	}
	if err := json.Unmarshal(body, &full); err != nil {
		t.Fatal(err)
	}
	if full.Truncated {
		t.Errorf("a complete list (%d of %d) reported itself truncated", full.Returned, full.Total)
	}
}
