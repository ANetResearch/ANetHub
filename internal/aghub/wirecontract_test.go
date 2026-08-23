package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"github.com/ANetResearch/ANetCore/relayauth"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/version"
)

// The web UI declares TypeScript interfaces that mirror this package's
// JSON, and nothing checked that they still did.
//
// They had already drifted. The Go AgentView grew home_hub, last_seen and
// quiet; the TypeScript one did not — so the page could not tell a local
// agent from a federated one, nor show which agents had stopped
// collecting their mail. Nothing failed. TypeScript is perfectly happy to
// describe a shape narrower than what arrives, and the extra fields
// simply vanish at the boundary.
//
// This is the same defect as the daemon reading "balance" from a hub that
// sends "credits", and as internal/hubapi missing home_hub: two sides of
// one wire, each internally consistent, drifting apart in silence. The
// only thing that ever catches it is a test that reads both.
//
// It lives on the Go side because the Go side owns the wire. A TypeScript
// test could not read the Go struct, and a hand-maintained list in a
// third place would be a third thing to forget.
func TestTheWebUIDeclaresTheFieldsThisPackageSends(t *testing.T) {
	const apiTS = "../../webui/src/lib/api.ts"
	src, err := os.ReadFile(apiTS)
	if err != nil {
		t.Skipf("webui not checked out here: %v", err)
	}
	for _, tc := range []struct {
		iface string
		value any
	}{
		{"AgentView", aghub.AgentView{}},
		{"ReviewView", aghub.ReviewView{}},
		{"Stats", aghub.HubStats{}},
	} {
		t.Run(tc.iface, func(t *testing.T) {
			want := goJSONFields(t, tc.value)
			got := tsInterfaceFields(t, string(src), tc.iface)
			if got == nil {
				t.Fatalf("the web UI declares no %s — it cannot render what it cannot describe", tc.iface)
			}
			if missing := notIn(want, got); len(missing) > 0 {
				t.Errorf("the web UI is missing %v\n"+
					"these arrive on the wire and are silently discarded at the boundary — "+
					"add them to %s", missing, apiTS)
			}
			if extra := notIn(got, want); len(extra) > 0 {
				t.Errorf("the web UI expects %v, which this hub never sends\n"+
					"a field that is always undefined renders as a blank the reader "+
					"cannot distinguish from a real empty value", extra)
			}
		})
	}
}

// goJSONFields is what the type actually puts on the wire, including the
// omitempty ones — those are part of the contract, just not of every
// message.
func goJSONFields(t *testing.T, v any) []string {
	t.Helper()
	rt := reflect.TypeOf(v)
	var out []string
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// tsInterfaceFields reads the field names out of a TypeScript interface.
//
// A regex over the source rather than a parse, because the alternative is
// a TypeScript toolchain in a Go test. It is deliberately strict about
// the shape it accepts: a declaration this cannot read is reported as a
// missing interface rather than silently matching nothing, so the test
// fails loudly instead of passing for the wrong reason.
func tsInterfaceFields(t *testing.T, src, iface string) []string {
	t.Helper()
	block := regexp.MustCompile(`(?s)export interface ` + iface + ` \{(.*?)\n\}`)
	m := block.FindStringSubmatch(src)
	if m == nil {
		return nil
	}
	field := regexp.MustCompile(`(?m)^\s{2}([a-z_][a-z0-9_]*)\??:`)
	var out []string
	for _, f := range field.FindAllStringSubmatch(m[1], -1) {
		out = append(out, f[1])
	}
	sort.Strings(out)
	return out
}

func notIn(a, b []string) []string {
	have := map[string]bool{}
	for _, x := range b {
		have[x] = true
	}
	var out []string
	for _, x := range a {
		if !have[x] {
			out = append(out, x)
		}
	}
	return out
}

// A quiet agent must survive the trip to the page as a quiet agent.
//
// The field being declared is not the same as it arriving: omitempty
// means quiet:false is absent from the JSON, and a reader that treated
// absent as "unknown" rather than "not quiet" would flag every healthy
// agent.
func TestQuietSurvivesEncoding(t *testing.T) {
	quiet, err := json.Marshal(aghub.AgentView{AID: "a", Quiet: true, LastSeen: "2026-08-23T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(quiet), `"quiet":true`) {
		t.Errorf("a quiet agent does not say so on the wire: %s", quiet)
	}
	live, err := json.Marshal(aghub.AgentView{AID: "a", LastSeen: "2026-08-23T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(live), `"quiet"`) {
		t.Errorf("a live agent carries a quiet field: %s", live)
	}
	// last_seen present without quiet is the healthy shape, and the page
	// needs both halves: without last_seen it cannot say how long.
	if !strings.Contains(string(live), `"last_seen"`) {
		t.Errorf("a live agent does not report when it was last seen: %s", live)
	}
}

// healthz must say which build is answering.
//
// A bare {"status":"ok"} cannot answer "is the binary running in
// production the one I just deployed", which is the question that comes
// up — and the one that had a stale check on cmax reporting failures for
// three hours against a hub that was fine.
func TestHealthzReportsTheBuild(t *testing.T) {
	srv := newHub(t)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"status", "version", "commit", "built_at"} {
		if out[k] == "" {
			t.Errorf("healthz does not report %q: %v", k, out)
		}
	}
	if out["status"] != "ok" {
		t.Errorf("status = %q", out["status"])
	}
	// An unstamped build says so rather than inventing something
	// plausible. A wrong commit is worse than an absent one: a check
	// comparing versions would pass while comparing two fabrications.
	if out["commit"] != version.Commit {
		t.Errorf("commit = %q, want %q", out["commit"], version.Commit)
	}
}

// Every AID an edge names must have a node.
//
// nodes came from the browsable listing and edges from every stored
// review, and the two disagree by construction: an agent that left, or
// went quiet for a month, drops out of the listing while its reviews
// stay — because leaving removes routing and keeps evidence. Production
// served one node and fifteen edges, and a renderer given that either
// drops the edges silently or fails.
func TestTheGraphHasANodeForEveryEdge(t *testing.T) {
	srv, _ := newHubWithStore(t)
	provider, requester := twoAgents(t)
	register(t, srv, provider, "Provider", []string{"work.do"})
	register(t, srv, requester, "Requester", nil)
	uploadInterlockedReview(t, srv, provider, requester, 5, "good")

	// The provider leaves. Its reviews stay, which is the design.
	ts := uint64(time.Now().UnixMilli())
	sig, seq := provider.Sign(relayauth.Preimage(relayauth.ActionProfile, provider.AID(), ts))
	if code, b := post(t, srv.URL+"/agents/"+provider.AID()+"/deregister", map[string]any{
		"ts": ts, "key_state_seq": seq, "sig": base64.StdEncoding.EncodeToString(sig)}); code != 200 {
		t.Fatalf("deregister: %d %s", code, b)
	}

	g := graphOf(t, srv)
	if len(g.Edges) == 0 {
		t.Fatal("the review edge vanished with the agent — evidence was deleted, not just routing")
	}
	nodes := map[string]aghub.AgentView{}
	for _, n := range g.Nodes {
		nodes[n.AID] = n
	}
	for _, e := range g.Edges {
		for _, aid := range []string{e.Source, e.Target} {
			if _, ok := nodes[aid]; !ok {
				t.Errorf("edge names %s, which has no node", aid[:12])
			}
		}
	}
	// And the one that left is marked, so a reader can tell it apart from
	// an agent still being routed to.
	if n, ok := nodes[provider.AID()]; !ok {
		t.Error("the departed provider has no node at all")
	} else if n.Registered {
		t.Error("a departed agent is marked as still registered")
	}
	// The requester never left and must still read as registered.
	if n, ok := nodes[requester.AID()]; ok && !n.Registered {
		t.Error("an agent that is still here is marked as gone")
	}
}

func graphOf(t *testing.T, srv *httptest.Server) struct {
	Nodes []aghub.AgentView `json:"nodes"`
	Edges []aghub.Edge      `json:"edges"`
} {
	t.Helper()
	var out struct {
		Nodes []aghub.AgentView `json:"nodes"`
		Edges []aghub.Edge      `json:"edges"`
	}
	resp, err := http.Get(srv.URL + "/graph")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
