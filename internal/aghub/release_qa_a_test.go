package aghub_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

func mustIncept(t *testing.T) *identity.Controller {
	t.Helper()
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// storeOf is the store behind a test hub, for reading what the HTTP
// surface is supposed to be publishing (or no longer publishing).
func storeOf(t *testing.T, srv *httptest.Server) *aghub.Store {
	t.Helper()
	v, ok := testHubStores.Load(srv.URL)
	if !ok {
		t.Fatal("no store for this hub")
	}
	return v.(*aghub.Store)
}

// captureLog redirects the standard logger for one test. The hub writes
// operator-facing records with log.Printf, so that is where a test has to
// look for them.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	out, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(out); log.SetFlags(flags) })
	return &buf
}

// registerWithProfile is a registration carrying a long readme, for
// testing what the hub will accept as a body at all.
func registerWithProfile(t *testing.T, srv *httptest.Server, c *identity.Controller,
	name, readme string) (int, []byte) {
	t.Helper()
	kelB, _ := identity.MarshalKEL(c.KEL())
	ts := uint64(time.Now().UnixMilli())
	sig, seq := c.Sign(relayauth.Preimage(relayauth.ActionRegister, c.AID(), ts))
	return post(t, srv.URL+"/register", map[string]any{
		"aid": c.AID(), "name": name, "caps": []string{}, "readme": readme,
		"kel": base64.StdEncoding.EncodeToString(kelB),
		"ts":  ts, "key_state_seq": seq, "sig": base64.StdEncoding.EncodeToString(sig),
	})
}

// getAgents runs one directory query and returns the agents in the order
// the hub sent them, plus the HTTP status.
func getAgents(t *testing.T, srv *httptest.Server, query string) (int, []aghub.AgentView) {
	t.Helper()
	resp, err := http.Get(srv.URL + "/agents" + query)
	if err != nil {
		t.Fatalf("get /agents%s: %v", query, err)
	}
	defer resp.Body.Close()
	var out struct {
		Agents []aghub.AgentView `json:"agents"`
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode /agents%s: %v (%s)", query, err, body)
		}
	}
	return resp.StatusCode, out.Agents
}

// agentNames is the names of a directory answer, in the order served.
func agentNames(agents []aghub.AgentView) []string {
	var ns []string
	for _, a := range agents {
		ns = append(ns, a.Name)
	}
	return ns
}

// --- capindex/F4: one query string, one answer ---

// A capability id is a structured identifier a provider dispatches on,
// not prose. The exact branch compared bytes and the prefix branch went
// through SQLite's LIKE, which is ASCII case-insensitive, so the same
// string got two answers depending on a trailing "*": an agent registered
// under "Text.Digest" was absent from ?cap=text.digest and present in
// ?cap=text.*.
func TestCapabilityMatchingIsCaseSensitiveWithAndWithoutTheStar(t *testing.T) {
	srv := newHub(t)
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, c, "DigestNode", []string{"Text.Digest"})

	found := func(q string) bool {
		code, agents := getAgents(t, srv, "?cap="+url.QueryEscape(q))
		if code != http.StatusOK {
			t.Fatalf("cap=%q: %d", q, code)
		}
		return len(agents) == 1 && agents[0].Name == "DigestNode"
	}

	for _, tc := range []struct {
		q    string
		want bool
	}{
		{"Text.Digest", true},  // the id as registered
		{"text.digest", false}, // a different id
		{"TEXT.DIGEST", false},
		{"Text.dIgEsT", false},
	} {
		exact, prefix := found(tc.q), found(tc.q+"*")
		if exact != tc.want {
			t.Errorf("cap=%s found=%v, want %v", tc.q, exact, tc.want)
		}
		// The invariant the bug broke: adding "*" widens the query, it
		// never changes which characters have to match.
		if prefix != tc.want {
			t.Errorf("cap=%s* found=%v but cap=%s found=%v — one query string, two answers",
				tc.q, prefix, tc.q, exact)
		}
	}

	// Dropping LIKE also drops its pattern language. Nothing in a
	// capability id may act as a wildcard in either form.
	register(t, srv, mustIncept(t), "StoreNode", []string{"cas.put"})
	for _, q := range []string{"cas.%", "cas.%*", "cas._", "cas._*", "cas.pu_", "cas.pu_*"} {
		if code, agents := getAgents(t, srv, "?cap="+url.QueryEscape(q)); code != http.StatusOK {
			t.Fatalf("cap=%q: %d", q, code)
		} else if len(agents) != 0 {
			t.Errorf("cap=%s matched %v — a literal id was read as a pattern", q, agentNames(agents))
		}
	}
}

// --- capindex/F7: the capability index is bounded ---

// The limits are the ones documented on maxCapIDLen / maxCapsPerAgent in
// aghub.go. They are restated here rather than imported because this is
// an external test of the wire behaviour, and because raising a bound
// should make these cases fail loudly rather than silently pass.
const (
	qaACapIDLimit = 256
	qaACapCount   = 256
)

// capsOfLength builds count distinct capability ids of exactly n bytes.
func capsOfLength(n, count int) []string {
	caps := make([]string, count)
	for i := range caps {
		suffix := "." + strconv.Itoa(i)
		caps[i] = ("qa.a." + strings.Repeat("x", n))[:n-len(suffix)] + suffix
	}
	return caps
}

// One anonymous registration could declare a capability id of any length
// and any number of them; registering costs a locally generated key pair,
// so the index, the database and every later directory response were
// something any caller could grow without limit.
func TestAnOverlongCapabilityIDIsRefused(t *testing.T) {
	srv, store := newHubWithStore(t)
	c := mustIncept(t)
	caps := capsOfLength(qaACapIDLimit+1, 1)

	code, body := registerWithCard(t, srv, c, "Greedy", caps, mintCard(t, c, "Greedy", caps))
	if code != http.StatusBadRequest {
		t.Fatalf("an overlong capability id must be refused, got %d %s", code, body)
	}
	// The refusal has to say which bound was crossed; "400" alone sends
	// an operator to read hub source.
	if !strings.Contains(string(body), "capability id") {
		t.Errorf("the refusal does not name the reason: %s", body)
	}
	// Refused means nothing was written — not written and then rejected.
	if store.KnowsAgent(c.AID()) {
		t.Error("a refused registration was stored anyway")
	}
	if got, err := store.FindByCapability(caps[0]); err != nil {
		t.Fatal(err)
	} else if len(got) != 0 {
		t.Errorf("a refused capability reached the index: %v", got)
	}
}

func TestTooManyCapabilitiesAreRefused(t *testing.T) {
	srv, store := newHubWithStore(t)
	c := mustIncept(t)
	caps := capsOfLength(32, qaACapCount+1)

	code, body := registerWithCard(t, srv, c, "Greedy", caps, mintCard(t, c, "Greedy", caps))
	if code != http.StatusBadRequest {
		t.Fatalf("an oversized capability set must be refused, got %d %s", code, body)
	}
	if !strings.Contains(string(body), "capabilities declared") {
		t.Errorf("the refusal does not name the reason: %s", body)
	}
	if store.KnowsAgent(c.AID()) {
		t.Error("a refused registration was stored anyway")
	}
}

// The bound is a store invariant, not only a handler's opinion. The index
// is written here, and a second path into it — an admin tool, a restore,
// a future endpoint — would otherwise reopen what the handler closes.
func TestTheStoreRefusesAnUnboundedCapabilitySet(t *testing.T) {
	_, store := newHubWithStore(t)
	c := mustIncept(t)
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(c.AID(), "Greedy", capsOfLength(qaACapIDLimit+1, 1), 5, kel); err == nil {
		t.Error("the store accepted an overlong capability id")
	}
	if err := store.PutAgent(c.AID(), "Greedy", capsOfLength(32, qaACapCount+1), 5, kel); err == nil {
		t.Error("the store accepted an oversized capability set")
	}
	if store.KnowsAgent(c.AID()) {
		t.Error("a refused PutAgent wrote the agent row anyway")
	}
}

// The bounds are meant to be above anything real, so exactly at the bound
// must register and must be findable. A limit that also refuses the last
// legal value is a limit one lower than the one documented.
func TestACapabilitySetExactlyAtTheBoundIsAccepted(t *testing.T) {
	srv := newHub(t)
	c := mustIncept(t)
	caps := capsOfLength(qaACapIDLimit, qaACapCount)
	for _, id := range caps {
		if len(id) != qaACapIDLimit {
			t.Fatalf("test built a %d-byte id, want %d", len(id), qaACapIDLimit)
		}
	}

	code, body := registerWithCard(t, srv, c, "AtTheLimit", caps, mintCard(t, c, "AtTheLimit", caps))
	if code != http.StatusOK {
		t.Fatalf("a registration exactly at the bound must be accepted, got %d %s", code, body)
	}
	code, agents := getAgents(t, srv, "?cap="+url.QueryEscape(caps[0]))
	if code != http.StatusOK || len(agents) != 1 || agents[0].Name != "AtTheLimit" {
		t.Fatalf("an accepted capability is not findable: %d %v", code, agentNames(agents))
	}
}

// The root of the amplification was an unbounded request body: the caps
// limits only apply once the JSON has been read into memory.
func TestAnOversizedRegistrationBodyIsRefused(t *testing.T) {
	srv := newHub(t)
	c := mustIncept(t)
	code, body := registerWithProfile(t, srv, c, "Bulky", strings.Repeat("x", 1<<20))
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized registration body must be refused with 413, got %d %s", code, body)
	}
}

// --- capindex/F8: a blank filter is not the absence of a filter ---

// A filter built from an empty variable was read as "no filter" and
// answered with the whole directory: a plausible-looking answer to a
// question nobody asked, with nothing in the response to say so.
func TestABlankCapFilterIsRefusedRatherThanIgnored(t *testing.T) {
	srv := newHub(t)
	register(t, srv, mustIncept(t), "StoreNode", []string{"cas.put"})
	register(t, srv, mustIncept(t), "CameraNode", []string{"ptz.home"})

	for _, blank := range []string{"", "%20", "+", "%09", "%20%20"} {
		code, agents := getAgents(t, srv, "?cap="+blank)
		if code != http.StatusBadRequest {
			t.Errorf("?cap=%q returned %d with %v, want 400", blank, code, agentNames(agents))
		}
	}
	// And the absence of the parameter still means the whole directory.
	code, agents := getAgents(t, srv, "")
	if code != http.StatusOK || len(agents) != 2 {
		t.Fatalf("no cap parameter must list everything: %d %v", code, agentNames(agents))
	}
}

// --- admission/F-3: a refused registration is observable ---

// The admission gate's audit surface was its success side only: invite_use
// rows and the redeemers in -invite-list. A refusal left no log line, no
// row and nothing in -invite-list, so an operator running a closed hub
// could not tell whether anybody had been turned away.
func TestARefusedRegistrationLeavesARecord(t *testing.T) {
	logs := captureLog(t)
	srv, store := newHubWithStore(t)
	if err := store.SetInviteRequired(true); err != nil {
		t.Fatal(err)
	}
	c := mustIncept(t)

	if code, body := registerWithInvite(t, srv, c, "Uninvited", ""); code != http.StatusForbidden {
		t.Fatalf("an uninvited agent must be refused, got %d %s", code, body)
	}
	got := logs.String()
	if !strings.Contains(got, c.AID()) {
		t.Fatalf("the refusal does not name who was refused: %q", got)
	}
	if !strings.Contains(got, "refused") {
		t.Fatalf("the refusal is not identifiable as one: %q", got)
	}
	// And it says why, so "wrong token" and "hub is closed" stay apart.
	if !strings.Contains(got, "invite") {
		t.Fatalf("the refusal does not say why: %q", got)
	}
}

// --- federation/FED-1: the review stream belongs to the federation plane ---

// GET /federation/reviews served the same signed review stream as GET
// /fed/v1/reviews, but from the kernel router, so it obeyed neither the
// discovery switch nor the no_federation tag. A hub built without
// federation still published every review it held.
func TestTheKernelDoesNotServeTheFederationReviewStream(t *testing.T) {
	srv := newHub(t)
	prov, req := mustIncept(t), mustIncept(t)
	register(t, srv, prov, "Provider", []string{"bakery"})
	register(t, srv, req, "Requester", nil)
	// Opted in, so the review really is in the stream the kernel route
	// was handing out. Without this the endpoint would have been empty
	// for a reason that has nothing to do with the fix.
	setVisibility(t, srv, prov, "federated")
	if code, b := post(t, srv.URL+"/reviews", makeEvidence(t, prov, req, "ix_fed1", 5, "")); code != http.StatusOK {
		t.Fatalf("upload: %d %s", code, b)
	}

	resp, err := http.Get(srv.URL + "/federation/reviews")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("the kernel still answers the federation review stream: %d", resp.StatusCode)
	}
	if strings.Contains(string(body), "ix_fed1") {
		t.Errorf("a kernel route handed out signed reviews: %s", body)
	}
	// The evidence itself is untouched; only the ungoverned route is gone.
	if revs, _, err := storeOf(t, srv).ReviewsSince(0, 0); err != nil {
		t.Fatal(err)
	} else if len(revs) != 1 {
		t.Errorf("the review stream itself lost content: %d reviews", len(revs))
	}
}

// --- federation/FED-3: a peer-learned agent is visible to every query ---

// fakeFederatedDirectory implements the whole contract of
// Store.FederatedAgents, which is what the hub binary installs on this
// seam: an empty capFilter means every peer-learned agent, and a non-empty
// one applies the same comma-OR exact/prefix rules the local index
// applies. A fake that ignored capFilter would make ?cap= look correct
// while returning agents that do not serve the id asked for.
func fakeFederatedDirectory(agents []aghub.AgentView) func(string) ([]aghub.AgentView, error) {
	return func(capFilter string) ([]aghub.AgentView, error) {
		if capFilter == "" {
			return agents, nil
		}
		var out []aghub.AgentView
		for _, a := range agents {
			if capsServe(a.Caps, capFilter) {
				out = append(out, a)
			}
		}
		return out, nil
	}
}

func capsServe(caps []string, filter string) bool {
	for _, term := range strings.Split(filter, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		for _, c := range caps {
			if strings.HasSuffix(term, "*") {
				if strings.HasPrefix(c, strings.TrimSuffix(term, "*")) {
					return true
				}
				continue
			}
			if c == term {
				return true
			}
		}
	}
	return false
}

// Only ?cap= merged the federated directory. ?q= and the unfiltered
// listing queried the local agent table alone, so an agent learned from a
// peer could be found by an exact capability id and by nothing else:
// `anet find <text>` missed it and the starfield never drew it.
func TestPeerLearnedAgentsAppearInEveryDirectoryQuery(t *testing.T) {
	srv := newHub(t)
	local := mustIncept(t)
	register(t, srv, local, "LocalBakery", []string{"cas.put"})
	remote := aghub.AgentView{
		AID: "bafyremote", Name: "RemoteCamera", Caps: []string{"ptz.absolute"},
		Listed: true, HomeHub: "hub:peer",
	}
	// A peer-learned agent that advertises nothing must stay out of a
	// listing, exactly as an unlisted local one does.
	silent := aghub.AgentView{AID: "bafyresilent", Name: "RemoteRequester", HomeHub: "hub:peer"}
	serverOf(t, srv).SetFederatedDirectory(
		fakeFederatedDirectory([]aghub.AgentView{remote, silent}))

	byAID := func(query string) map[string]aghub.AgentView {
		t.Helper()
		code, agents := getAgents(t, srv, query)
		if code != http.StatusOK {
			t.Fatalf("/agents%s: %d", query, code)
		}
		out := map[string]aghub.AgentView{}
		for _, a := range agents {
			out[a.AID] = a
		}
		return out
	}

	for _, query := range []string{
		"?cap=ptz.absolute", // already worked
		"?cap=ptz.*",
		"?q=RemoteCamera", // the prose search
		"?q=remotecam",    // prose is case-insensitive, unlike a cap id
		"?q=ptz.absolute",
		"", // and the unfiltered listing the starfield asks for
	} {
		got, ok := byAID(query)["bafyremote"]
		if !ok {
			t.Errorf("/agents%s does not know the peer-learned agent", query)
			continue
		}
		if got.HomeHub != "hub:peer" {
			t.Errorf("/agents%s lost home_hub: %+v", query, got)
		}
	}
	if _, ok := byAID("")["bafyresilent"]; ok {
		t.Error("a peer-learned agent advertising nothing was listed")
	}

	// Local first, and the local agent is still there.
	code, agents := getAgents(t, srv, "")
	if code != http.StatusOK {
		t.Fatalf("/agents: %d", code)
	}
	if len(agents) != 2 || agents[0].AID != local.AID() || agents[1].AID != "bafyremote" {
		t.Fatalf("want the local agent first then the peer's, got %v", agentNames(agents))
	}
	if agents[0].HomeHub != "" {
		t.Errorf("a local agent was labelled with a home hub: %+v", agents[0])
	}

	// A query that matches only the local agent must not drag the peer's
	// in — the filter has to apply to both sides.
	if got := byAID("?q=LocalBakery"); len(got) != 1 || got[local.AID()].Name != "LocalBakery" {
		t.Errorf("?q=LocalBakery returned %v", got)
	}
}
