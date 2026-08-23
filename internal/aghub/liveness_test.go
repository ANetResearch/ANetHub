package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// A node that dies leaves the same hole a node that moved used to leave.
//
// `hub-leave` made moving clean and did nothing for dying: a machine shut
// down, a process killed, an operator gone — the agent stays listed and
// stays deliverable-to, work is accepted into a mailbox nobody will poll,
// and the requester waits for an answer that is not coming.
//
// The signal is the poll, because that is the thing that actually
// matters. A node collecting its mail will do the work; a node that has
// stopped collecting will not, whatever else it may still answer.
func TestPollingIsWhatSaysAnAgentIsStillThere(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Worker", []string{"work.do"})

	// Freshly registered and never polled: unknown, NOT dead. Reporting
	// quiet here would be the hub asserting something it does not know —
	// and every row from before this was tracked looks exactly like this.
	live, err := store.LivenessOf(agent.AID())
	if err != nil {
		t.Fatal(err)
	}
	if live.Quiet {
		t.Error("an agent that has never polled was reported quiet — unknown is not dead")
	}
	if live.LastSeen != "" {
		t.Errorf("last_seen = %q before any poll", live.LastSeen)
	}

	// It collects its mail. Now the hub knows.
	pollAs(t, srv, agent)
	live, err = store.LivenessOf(agent.AID())
	if err != nil {
		t.Fatal(err)
	}
	if live.LastSeen == "" {
		t.Fatal("collecting mail did not record that the agent is there")
	}
	if live.Quiet {
		t.Error("an agent that just polled was reported quiet")
	}
	seen, err := time.Parse(time.RFC3339, live.LastSeen)
	if err != nil {
		t.Fatalf("last_seen is not a timestamp: %q", live.LastSeen)
	}
	if time.Since(seen) > time.Minute {
		t.Errorf("last_seen is stale immediately: %s", live.LastSeen)
	}
}

// The sender finds out before it starts waiting.
func TestSendingToAQuietAgentIsAcceptedAndSaysSo(t *testing.T) {
	srv, store := newHubWithStore(t)
	provider, sender := twoAgents(t)
	register(t, srv, provider, "Worker", []string{"work.do"})
	register(t, srv, sender, "Sender", nil)

	// The provider collected its mail a long time ago and has not since.
	backdatePoll(t, store, provider.AID(), time.Now().Add(-6*time.Hour))

	code, b := post(t, srv.URL+"/relay/send", map[string]any{
		"to_aid": provider.AID(), "from_aid": sender.AID(), "kind": "delegate",
		"interaction_id": "ix-1", "payload": base64.StdEncoding.EncodeToString([]byte("work")),
	})
	if code != 200 {
		t.Fatalf("send refused: %d %s", code, b)
	}
	var out struct {
		Status  string `json:"status"`
		Quiet   bool   `json:"recipient_quiet"`
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	// Accepted, deliberately. This hub cannot know whether the agent is
	// coming back, and refusing would be asserting that it is not.
	if out.Status != "queued" {
		t.Errorf("status = %q — a quiet recipient is not a reason to refuse", out.Status)
	}
	if !out.Quiet || out.Warning == "" {
		t.Errorf("the sender was told nothing and will now wait: %s", b)
	}

	// And once it collects again, the warning stops.
	pollAs(t, srv, provider)
	_, b2 := post(t, srv.URL+"/relay/send", map[string]any{
		"to_aid": provider.AID(), "from_aid": sender.AID(), "kind": "delegate",
		"interaction_id": "ix-2", "payload": base64.StdEncoding.EncodeToString([]byte("work")),
	})
	var out2 struct {
		Quiet bool `json:"recipient_quiet"`
	}
	_ = json.Unmarshal(b2, &out2)
	if out2.Quiet {
		t.Error("an agent that just collected its mail is still reported quiet")
	}
}

// The directory says which of its agents have stopped answering.
func TestTheDirectorySaysWhoHasGoneQuiet(t *testing.T) {
	srv, store := newHubWithStore(t)
	live, quiet := twoAgents(t)
	register(t, srv, live, "Live", []string{"work.do"})
	register(t, srv, quiet, "Quiet", []string{"work.do"})
	pollAs(t, srv, live)
	backdatePoll(t, store, quiet.AID(), time.Now().Add(-6*time.Hour))

	agents := listAgents(t, srv, "?cap=work.do")
	if len(agents) != 2 {
		t.Fatalf("listed %d agents, want 2 — quiet is a fact to report, not a reason to hide",
			len(agents))
	}
	for _, a := range agents {
		switch a.AID {
		case live.AID():
			if a.Quiet {
				t.Error("a live agent was flagged quiet")
			}
		case quiet.AID():
			if !a.Quiet {
				t.Error("a quiet agent was listed with nothing to say it had stopped answering")
			}
		}
	}
}

// Gone for a month drops out of the browsable listing — and stays in the
// hub, with everything it owns.
func TestAnAbandonedAgentLeavesTheListingAndNothingElse(t *testing.T) {
	srv, store := newHubWithStore(t)
	gone, requester := twoAgents(t)
	register(t, srv, gone, "Gone", []string{"work.do"})
	register(t, srv, requester, "Requester", nil)
	uploadInterlockedReview(t, srv, gone, requester, 5, "good")
	fundAgent(t, srv, gone.AID(), 400)
	backdatePoll(t, store, gone.AID(), time.Now().Add(-40*24*time.Hour))

	if agents := listAgents(t, srv, "?cap=work.do"); len(agents) != 0 {
		t.Errorf("an agent gone 40 days is still in the browsable listing (%d)", len(agents))
	}
	// Everything it owns is untouched. Dropping out of a listing is not a
	// deregistration, and a hub that treated an outage as one would
	// orphan every agent's reviews and balance the first time a network
	// went down.
	if code, _ := getJSON(t, srv.URL+"/agents/"+gone.AID()); code != 200 {
		t.Error("the agent itself is no longer resolvable")
	}
	rep, err := store.ReputationOf(gone.AID())
	if err != nil || rep.Local.Reviews != 1 {
		t.Errorf("its reviews went with it: %+v %v", rep.Local, err)
	}
	bal, err := store.Balance(gone.AID())
	if err != nil || bal != 400+int64(aghub.RegistrationGrant) {
		t.Errorf("its balance went with it: %d %v", bal, err)
	}
	// And one poll brings it back.
	pollAs(t, srv, gone)
	if agents := listAgents(t, srv, "?cap=work.do"); len(agents) != 1 {
		t.Errorf("after collecting its mail it is still hidden (%d)", len(agents))
	}
}

// pollAs collects an agent's mail, which is how it says it is there.
func pollAs(t *testing.T, srv *httptest.Server, c *identity.Controller) {
	t.Helper()
	ts := uint64(time.Now().UnixMilli())
	sig, seq := c.Sign(relayauth.Preimage(relayauth.ActionPoll, c.AID(), ts))
	if code, b := post(t, srv.URL+"/relay/poll", map[string]any{
		"aid": c.AID(), "ts": ts, "key_state_seq": seq,
		"sig": base64.StdEncoding.EncodeToString(sig),
	}); code != 200 {
		t.Fatalf("poll: %d %s", code, b)
	}
}

// backdatePoll makes an agent look like it collected its mail a while
// ago, so the test does not have to wait an hour.
func backdatePoll(t *testing.T, store *aghub.Store, aid string, when time.Time) {
	t.Helper()
	if err := store.SetLastSeenForTest(aid, when); err != nil {
		t.Fatal(err)
	}
}

func listAgents(t *testing.T, srv *httptest.Server, query string) []aghub.AgentView {
	t.Helper()
	resp, err := http.Get(srv.URL + "/agents" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Agents []aghub.AgentView `json:"agents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Agents
}
