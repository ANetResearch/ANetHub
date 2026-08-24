package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

func leave(t *testing.T, srv *httptest.Server, c *identity.Controller) (int, []byte) {
	t.Helper()
	ts := uint64(time.Now().UnixMilli())
	sig, seq := c.Sign(relayauth.Preimage(relayauth.ActionProfile, c.AID(), ts))
	return post(t, srv.URL+"/agents/"+c.AID()+"/deregister", map[string]any{
		"ts": ts, "key_state_seq": seq, "sig": base64.StdEncoding.EncodeToString(sig)})
}

// An agent that moved to another hub must be able to stop being
// deliverable at the old one.
//
// Until this existed, it could not. The old hub went on listing it and
// went on accepting delegations for it into a mailbox nobody would poll
// again — accepted, queued, silently swallowed. Found in production, by
// a cross-hub call that was relayed into a dead mailbox instead of
// crossing, and never arrived.
func TestAnAgentCanLeaveAHub(t *testing.T) {
	srv := newHub(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Mover", []string{"work.do"})

	// Registered: findable, and its key history is served.
	if code, _ := getJSON(t, srv.URL+"/agents/"+agent.AID()+"/kel"); code != 200 {
		t.Fatal("setup: not registered")
	}
	found := agentsServing(t, srv, "work.do")
	if found != 1 {
		t.Fatalf("setup: %d agents serve work.do, want 1", found)
	}

	if code, b := leave(t, srv, agent); code != 200 {
		t.Fatalf("deregister: %d %s", code, b)
	}

	// Gone from routing: not in the directory, not resolvable, so nothing
	// new is addressed here.
	if found := agentsServing(t, srv, "work.do"); found != 0 {
		t.Errorf("still listed as serving work.do after leaving (%d)", found)
	}
	// The key history stays, and this assertion used to say the opposite.
	//
	// It treated the KEL as part of routing. It is part of proof: the hub
	// goes on storing and serving every receipt and review this agent
	// signed, and without the key none of them can be checked against
	// anything this hub can produce. Serving the evidence while
	// withholding the key that checks it is the contradiction, and it
	// broke `anet verify --receipt --hub` for every agent that had ever
	// left. Caught in production by prodtest 9q, against the sibling test
	// below that already said evidence survives.
	code, body := getJSON(t, srv.URL+"/agents/"+agent.AID()+"/kel")
	if code != 200 {
		t.Errorf("an agent left and its key history went with it (%d) — "+
			"the receipts it signed are now uncheckable here", code)
	}
	if !strings.Contains(string(body), "\"kel\"") {
		t.Errorf("the key history came back empty: %s", body)
	}
	// And leaving twice is an error, not a second success — the second
	// caller is telling the hub something it does not know.
	if code, _ := leave(t, srv, agent); code == 200 {
		t.Error("deregistering an unregistered agent reported success")
	}
}

// Only the agent may do it.
func TestOnlyTheAgentCanDeregisterItself(t *testing.T) {
	srv := newHub(t)
	agent, thief := twoAgents(t)
	register(t, srv, agent, "Agent", []string{"work.do"})
	register(t, srv, thief, "Thief", nil)

	// A real signature over a real challenge — the thief's own. It names
	// the thief, so it cannot authorise anything about the agent.
	ts := uint64(time.Now().UnixMilli())
	sig, seq := thief.Sign(relayauth.Preimage(relayauth.ActionProfile, thief.AID(), ts))
	code, _ := post(t, srv.URL+"/agents/"+agent.AID()+"/deregister", map[string]any{
		"ts": ts, "key_state_seq": seq, "sig": base64.StdEncoding.EncodeToString(sig)})
	if code == 200 {
		t.Fatal("one agent deregistered another")
	}
	if found := agentsServing(t, srv, "work.do"); found != 1 {
		t.Error("the victim was removed from the directory")
	}
}

// Leaving removes the routing, never the evidence.
//
// Reviews and ledger entries are records of things that happened, and
// they did happen. Deleting them because a party moved on would rewrite
// history to match the directory.
func TestLeavingDoesNotEraseWhatHappened(t *testing.T) {
	srv, store := newHubWithStore(t)
	provider, requester := twoAgents(t)
	register(t, srv, provider, "Provider", []string{"work.do"})
	register(t, srv, requester, "Requester", nil)
	uploadInterlockedReview(t, srv, provider, requester, 5, "good")
	fundAgent(t, srv, provider.AID(), 250)

	before, err := store.ReputationOf(provider.AID())
	if err != nil || before.Local.Reviews != 1 {
		t.Fatalf("setup: %+v %v", before, err)
	}

	if code, b := leave(t, srv, provider); code != 200 {
		t.Fatalf("deregister: %d %s", code, b)
	}

	after, err := store.ReputationOf(provider.AID())
	if err != nil {
		t.Fatal(err)
	}
	if after.Local.Reviews != 1 {
		t.Errorf("leaving erased a review that really happened: %d", after.Local.Reviews)
	}
	// And the review is still checkable, which is the half that was
	// missing. Keeping the record and dropping the key that verifies it
	// leaves a hub asserting something nobody can confirm — which is the
	// state everything else here exists to avoid.
	kelCode, kelBody := getJSON(t, srv.URL+"/agents/"+provider.AID()+"/kel")
	if kelCode != 200 {
		t.Fatalf("the key that verifies the kept review is gone (%d)", kelCode)
	}
	var got struct {
		KEL string `json:"kel"`
	}
	if err := json.Unmarshal(kelBody, &got); err != nil || got.KEL == "" {
		t.Fatalf("empty key history after leaving: %s", kelBody)
	}
	raw, derr := base64.StdEncoding.DecodeString(got.KEL)
	if derr != nil {
		t.Fatal(derr)
	}
	kel, kerr := identity.UnmarshalKEL(raw)
	if kerr != nil {
		t.Fatalf("the retained key history does not decode: %v", kerr)
	}
	// Not "some bytes came back" — the retained history must actually
	// verify a signature this agent made, which is the only property that
	// makes a kept receipt checkable.
	msg := []byte("anything this agent signed")
	sig, seq := provider.Sign(msg)
	if err := identity.VerifyObject(kel, provider.AID(), seq,
		uint64(time.Now().UnixMilli()), msg, sig); err != nil {
		t.Errorf("the retained key history does not verify this agent's signature: %v", err)
	}
	bal, err := store.Balance(provider.AID())
	if err != nil {
		t.Fatal(err)
	}
	if bal != 250+int64(aghub.RegistrationGrant) {
		t.Errorf("leaving moved the balance: %d", bal)
	}
}

// Undelivered mail is reported. Somebody sent that work and is waiting.
func TestLeavingWarnsAboutMailNobodyWillCollect(t *testing.T) {
	srv := newHub(t)
	provider, sender := twoAgents(t)
	register(t, srv, provider, "Provider", []string{"work.do"})
	register(t, srv, sender, "Sender", nil)
	if code, b := post(t, srv.URL+"/relay/send", map[string]any{
		"to_aid": provider.AID(), "from_aid": sender.AID(), "kind": "delegate",
		"interaction_id": "ix-orphan", "payload": base64.StdEncoding.EncodeToString([]byte("work")),
	}); code != 200 {
		t.Fatalf("send: %d %s", code, b)
	}
	code, b := leave(t, srv, provider)
	if code != 200 {
		t.Fatalf("deregister: %d %s", code, b)
	}
	var out struct {
		Undelivered int    `json:"undelivered"`
		Warning     string `json:"warning"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Undelivered < 1 {
		t.Errorf("queued mail was not counted: %s", b)
	}
	if out.Warning == "" {
		t.Error("mail that will never be delivered left without a word about it")
	}
}

func agentsServing(t *testing.T, srv *httptest.Server, capID string) int {
	t.Helper()
	resp, err := http.Get(srv.URL + "/agents?cap=" + capID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Agents []map[string]any `json:"agents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return len(out.Agents)
}

func getJSON(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b := make([]byte, 0)
	buf := make([]byte, 2048)
	for {
		n, rerr := resp.Body.Read(buf)
		b = append(b, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, b
}
