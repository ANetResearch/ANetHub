package aghub_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/ANetResearch/ANetCore/identity"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
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
	if code, b := leave(t, srv, provider); code != 200 {
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

// The ledger endpoint must say how much it did not return.
//
// It served the newest hundred entries with nothing marking the cap, and
// `anet reconcile` summed that page against the full balance. Every
// account with more history than one page reported a discrepancy that
// came from the cap rather than the ledger.
func TestLedgerReportsTheWholeAccountNotJustThePage(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Spender", []string{"work.do"})
	for i := 0; i < 7; i++ {
		if err := store.GrantCredit(agent.AID(), 10, "test grant"); err != nil {
			t.Fatal(err)
		}
	}
	code, body := ownerGet(t, srv, agent, relayauth.ActionLedger, "/agents/"+agent.AID()+"/ledger?limit=3")
	if code != 200 {
		t.Fatalf("ledger returned %d: %s", code, body)
	}
	var got struct {
		Entries   []map[string]any `json:"entries"`
		Total     int              `json:"total"`
		Returned  int              `json:"returned"`
		Sum       int64            `json:"sum"`
		Truncated bool             `json:"truncated"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Returned != 3 || len(got.Entries) != 3 {
		t.Fatalf("returned %d entries, want 3: %s", len(got.Entries), body)
	}
	if got.Total < 7 {
		t.Errorf("total = %d, want at least the 7 written", got.Total)
	}
	if !got.Truncated {
		t.Error("a truncated page was not marked truncated")
	}
	// The sum covers the account, so it must exceed what the page holds.
	if got.Sum < 70 {
		t.Errorf("sum = %d, want at least 70 — it summed the page, not the account", got.Sum)
	}
}

// The commands the join page tells a newcomer to run must be commands
// that exist.
//
// JoinSection publishes copy-paste instructions naming `anet install
// --agent <id>` and `anet autoreply set --backend exec --agent <id>` for
// five agent ids. Those names live in the ANet repository, and nothing
// checked that this page still agrees with them — the failure mode is a
// newcomer running the first command, being told there is no such agent,
// and having no way to tell whether the page or their typing was wrong.
//
// Pinned here rather than in the webui suite because the drift is
// cross-repository: the page is only wrong when ANet changes, and a test
// that reads the page alone cannot see that.
func TestTheJoinPageNamesAgentsThatExist(t *testing.T) {
	raw, err := os.ReadFile("../../webui/src/components/JoinSection.tsx")
	if err != nil {
		t.Skipf("join page not present: %v", err)
	}
	page := string(raw)

	// The agent ids ANet accepts for --agent. Kept as a literal list
	// rather than imported: ANetHub does not depend on ANet, and this is
	// exactly the boundary the check is about. When ANet adds one, this
	// list and the page are updated together or this fails.
	for _, agent := range []string{"cursor", "claude", "codex", "openclaw", "hermes"} {
		if !strings.Contains(page, "anet install --agent ${agent}") &&
			!strings.Contains(page, `"`+agent+`"`) {
			t.Errorf("the join page does not offer %q", agent)
		}
	}
	// And the two command names themselves.
	for _, cmd := range []string{
		"anet install --agent",
		"anet autoreply set --backend exec --agent",
		"anet autoreply set --backend openai",
		"anet autoreply test",
		"anet autoreply off",
	} {
		if !strings.Contains(page, cmd) {
			t.Errorf("the join page no longer names %q — if the CLI changed, "+
				"the page has to change with it", cmd)
		}
	}
}

// Wire 2 field names, pinned (A2A-DESIGN §3.7, §3.9).
//
// The daemon in ANet declares the same shapes in internal/hubapi and pins
// them there. Neither build fails when one side renames a field: the JSON
// still parses and the field arrives as its zero value. A rename is
// therefore a deliberate edit of both lists.
func TestTheWire2FieldNamesArePinned(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		want  []string
	}{
		{"RelaySendRequest", aghub.RelaySendRequest{}, []string{"envelope", "to_aid"}},
		{"RelaySendResponse", aghub.RelaySendResponse{}, []string{"id", "recipient_quiet", "status", "via_hub", "warning"}},
		{"RelayPollRequest", aghub.RelayPollRequest{}, []string{"limit"}},
		{"RelayPollResponse", aghub.RelayPollResponse{}, []string{"messages"}},
		{"RelayEnvelopeView", aghub.RelayEnvelopeView{}, []string{"envelope", "id"}},
		{"RelayAckRequest", aghub.RelayAckRequest{}, []string{"ids"}},
		{"RelayAckResponse", aghub.RelayAckResponse{}, []string{"acked"}},
		{"RegisterRequest", aghub.RegisterRequest{}, []string{
			"a2a_card", "aid", "caps", "card", "enc_keys", "invite", "kel", "name", "pricing", "readme", "summary"}},
		{"RegisterResponse", aghub.RegisterResponse{}, []string{
			"aid", "card_error", "card_status", "keys_error", "keys_status", "status"}},
		{"ProfileRequest", aghub.ProfileRequest{}, []string{"aid", "pricing", "readme", "summary"}},
		{"KeysView", aghub.KeysView{}, []string{"aid", "kel", "keyset"}},
		{"KeysPublishRequest", aghub.KeysPublishRequest{}, []string{"keyset"}},
		{"KeysPublishResponse", aghub.KeysPublishResponse{}, []string{"aid", "keys_status"}},
		{"FedCard", aghub.FedCard{}, []string{"card", "fed_seq", "home", "kel", "keys"}},
		// The A2A registry (A2A-DESIGN §10.5), read by the daemon's
		// list_agents (ANet internal/hubapi pins the same names).
		{"A2AAgentEntry", aghub.A2AAgentEntry{}, []string{
			"aid", "avgRating", "card", "cardVerification", "homeHub", "lastSeen", "quiet", "reviewCount", "verifiedAt"}},
		{"A2AAgentList", aghub.A2AAgentList{}, []string{"agents", "nextCursor"}},
		{"federation.Envelope", federation.Envelope{}, []string{
			"dest_aid", "hop", "key_state_seq", "origin_hub_aid", "payload", "payload_cid", "seen_hubs", "sig", "ts", "v"}},
		{"federation.KeysAnswer", federation.KeysAnswer{}, []string{"kel", "keyset"}},
		// GET /fed/v2/cards (A2A-DESIGN §10.6), read by peer hubs.
		{"federation.FedA2ACardEntry", federation.FedA2ACardEntry{}, []string{
			"card", "fed_seq", "format", "home", "kel", "keys"}},
		{"federation.FedA2ACardPage", federation.FedA2ACardPage{}, []string{"cards", "cursor"}},
	} {
		got := goJSONFields(t, tc.value)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s fields = %v, want %v", tc.name, got, tc.want)
		}
	}
	// The per-field status values a daemon branches on.
	for _, pair := range [][2]string{
		{aghub.KeysStatusOK, "ok"}, {aghub.KeysStatusUnchanged, "unchanged"}, {aghub.KeysStatusAbsent, "absent"},
		{aghub.KeysStatusInvalid, "invalid"}, {aghub.KeysStatusConflict, "conflict"},
		{aghub.CardStatusOK, "ok"}, {aghub.CardStatusUnchanged, "unchanged"}, {aghub.CardStatusAbsent, "absent"},
		{aghub.CardStatusInvalid, "invalid"}, {aghub.CardStatusConflict, "conflict"},
		{aghub.CardStatusWithdrawn, "withdrawn"},
		{aghub.CardVerificationOK, "ok"},
		// The /fed/v2/cards entry formats a peer hub dispatches on.
		{federation.FormatA2ACard, "a2a-card/1"}, {federation.FormatWithdrawal, "withdrawal/1"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("status value %q, want %q", pair[0], pair[1])
		}
	}
}

// The version numbers and the authentication header names are part of the
// contract too: the daemon sends these exact strings.
func TestTheWire2VersionsAndHeadersArePinned(t *testing.T) {
	if aghub.WireVersion != 2 {
		t.Errorf("hub wire version %d, want 2", aghub.WireVersion)
	}
	if federation.ForwardVersion != 2 {
		t.Errorf("federation forward version %d, want 2", federation.ForwardVersion)
	}
	for _, pair := range [][2]string{
		{relayauth.HeaderAID, "X-ANet-AID"}, {relayauth.HeaderTS, "X-ANet-TS"},
		{relayauth.HeaderSeq, "X-ANet-Seq"}, {relayauth.HeaderSig, "X-ANet-Sig"},
		{relayauth.ActionSend, "send"}, {relayauth.ActionPoll, "poll"}, {relayauth.ActionAck, "ack"},
		{relayauth.ActionRegister, "register"}, {relayauth.ActionProfile, "profile"},
		{relayauth.ActionVisibility, "visibility"}, {relayauth.ActionDeregister, "deregister"},
		{relayauth.ActionP2P, "p2p"}, {relayauth.ActionKeys, "keys"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%q, want %q", pair[0], pair[1])
		}
	}
}

// Every wire-2 route is served, and each signed one answers an unsigned
// request from its own authentication step (401 with the header names),
// not from the mux (404/405).
func TestTheWire2RoutesAreServed(t *testing.T) {
	srv := newHub(t)
	c, _ := twoAgents(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/relay/send"}, {http.MethodPost, "/relay/poll"}, {http.MethodPost, "/relay/ack"},
		{http.MethodPost, "/register"}, {http.MethodPost, "/profile"},
		{http.MethodPost, "/agents/" + c.AID() + "/keys"},
	} {
		req := newRequest(t, srv, tc.method, tc.path, []byte(`{}`))
		code, body, _ := send(t, req)
		if code != http.StatusUnauthorized || !strings.Contains(string(body), relayauth.HeaderSig) {
			t.Errorf("%s %s unsigned: %d %s, want 401 naming the auth headers", tc.method, tc.path, code, body)
		}
	}
	code, body := getJSON(t, srv.URL+"/agents/"+c.AID()+"/keys")
	var out map[string]string
	if code != http.StatusNotFound || json.Unmarshal(body, &out) != nil || out["error"] == "" {
		t.Errorf("GET keys of an unknown AID: %d %s, want the handler's JSON 404", code, body)
	}
}

// The facilitator contract (A2A-DESIGN §8.5, §17 契约 row).
//
// /x402/verify and /x402/settle take x402 v2's {x402Version,
// paymentPayload, paymentRequirements}, and paymentRequirements is
// required. Two bodies carry it: daemon → hub (ANet module/x402, pinned
// on that side in internal/hubapi) and entry hub → ledger hub
// (cmd/anet-hub/wire_federation.go, whose forwarded bytes are checked in
// cmd/anet-hub TestACrossHubPaymentIsCheckedAtBothHubsAndCreditedOnce).
// Both build payment.FacilitatorRequest, so its field names are pinned
// here, and the hub is driven with a literal body so that a rename on the
// hub side fails even if the Go struct were renamed in step.
func TestTheFacilitatorContractIsPinned(t *testing.T) {
	if got := goJSONFields(t, payment.FacilitatorRequest{}); strings.Join(got, ",") !=
		"paymentPayload,paymentRequirements,x402Version" {
		t.Errorf("FacilitatorRequest fields = %v", got)
	}
	if got := goJSONFields(t, payment.Supported{}); strings.Join(got, ",") !=
		"anet.signer_kel,extensions,kinds,signers" {
		t.Errorf("Supported fields = %v", got)
	}

	srv := newHub(t)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	hubAID := hubAIDOf(t, srv)
	payload := creditPayload(t, signedAuth(t, payer, payee.AID(), 12, hubAID, "contract-1"),
		payee.AID(), payment.CreditNetwork(hubAID))
	literal := map[string]any{
		"x402Version":    2,
		"paymentPayload": payload,
	}
	// Without paymentRequirements: 400 and the x402 reason for it.
	code, body := post(t, srv.URL+"/x402/settle", literal)
	if code != http.StatusBadRequest || !strings.Contains(string(body), `"errorReason":"invalid_payment_requirements"`) {
		t.Errorf("settle without paymentRequirements: %d %s", code, body)
	}
	// With it, spelled as the daemon spells it.
	literal["paymentRequirements"] = map[string]any{
		"scheme": "anet-credit", "network": "hub:" + hubAID, "amount": "12",
		"asset": "credit", "payTo": payee.AID(),
	}
	code, body = post(t, srv.URL+"/x402/settle", literal)
	if code != http.StatusOK || !strings.Contains(string(body), `"success":true`) {
		t.Errorf("settle with paymentRequirements: %d %s", code, body)
	}

	// The relayauth v2 actions of the three account reads (§3.7).
	for _, pair := range [][2]string{
		{relayauth.ActionBalance, "balance"}, {relayauth.ActionLedger, "ledger"},
		{relayauth.ActionRedemptions, "redemptions"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%q, want %q", pair[0], pair[1])
		}
	}
}

// Review and stats field names, pinned (A2A-DESIGN §9 rows 评价 and
// completed_task, §17 contract row "评价无内容字段").
//
// The daemon in ANet declares ReviewView and the upload body in
// internal/hubapi and pins them in hubapi_test.go; that list has to change
// with this one (ANet task C2): goal and deliverable removed,
// content_binding added, and guest_quota removed from AgentView. No
// content field may appear in any of these: the hub does not receive
// interaction content, so a field that could carry it is a field some
// client would fill.
func TestTheReviewFieldNamesArePinned(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		want  []string
	}{
		{"UploadReviewRequest", aghub.UploadReviewRequest{}, []string{"receipt", "review"}},
		{"ReviewView", aghub.ReviewView{}, []string{
			"comment", "completed_at", "content_binding", "created_at", "interaction_id", "rating",
			"receipt_cid", "request_cid", "result_cid", "reviewer_aid", "subject_aid"}},
		{"FedReview", aghub.FedReview{}, []string{"fed_seq", "provider_kel", "receipt", "review", "reviewer_kel"}},
		{"HubStats", aghub.HubStats{}, []string{
			"agents", "avg_rating", "federated_agents", "modules", "reviews", "tasks_completed"}},
	} {
		got := goJSONFields(t, tc.value)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s fields = %v, want %v", tc.name, got, tc.want)
		}
		for _, f := range got {
			switch f {
			case "goal", "deliverable", "request_doc", "transcript", "body":
				t.Errorf("%s carries %q, a content field", tc.name, f)
			}
		}
	}
	for _, f := range goJSONFields(t, aghub.AgentView{}) {
		if f == "guest_quota" {
			t.Error("AgentView still carries guest_quota; guest mode is removed")
		}
	}
	if aghub.ContentBindingUnverified != "UNVERIFIED" {
		t.Errorf("content binding state %q, want %q", aghub.ContentBindingUnverified, "UNVERIFIED")
	}
	if aghub.MaxReviewCommentRunes != 280 {
		t.Errorf("review comment bound %d, want 280", aghub.MaxReviewCommentRunes)
	}
}
