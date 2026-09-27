package aghub_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// A2A card admission and the A2A registry (A2A-DESIGN §3.7, §10.3, §10.5).

// a2aCardFor is a minimal anet network card for c in publish form, as a
// JSON tree the edits can change before signing. It follows baseCard in
// ANetCore a2acard/helpers_test.go, which is not exported.
func a2aCardFor(c *identity.Controller, seq uint64, edits ...func(map[string]any)) map[string]any {
	now := uint64(time.Now().UnixMilli())
	dec := func(n uint64) string { return strconv.FormatUint(n, 10) }
	card := map[string]any{
		"name":        "Test Agent",
		"description": "An agent used by the hub registry tests.",
		"version":     "1.0.0",
		"supportedInterfaces": []any{map[string]any{
			"url":             "https://hub.example.org/relay",
			"protocolBinding": a2acard.BindingRelayURI,
			"protocolVersion": "1.0",
			"tenant":          c.AID(),
		}},
		"capabilities": map[string]any{
			"streaming":         false,
			"pushNotifications": false,
			"extensions": []any{map[string]any{
				"uri": a2acard.ExtCardURI,
				"params": map[string]any{
					"aid": c.AID(), "seq": dec(seq), "issuedAt": dec(now), "notBefore": dec(now - 60_000),
				},
			}},
		},
		"defaultInputModes":  []any{"text/plain"},
		"defaultOutputModes": []any{"text/plain"},
		"skills": []any{map[string]any{
			"id": "echo", "name": "Echo", "description": "Returns the input text.",
			"tags": []any{"text", "echo"},
		}},
	}
	for _, e := range edits {
		e(card)
	}
	return card
}

// withSkills replaces the card's skills: each is {id, name, tags...}.
func withSkills(skills ...[]string) func(map[string]any) {
	return func(card map[string]any) {
		var out []any
		for _, s := range skills {
			tags := []any{}
			for _, t := range s[2:] {
				tags = append(tags, t)
			}
			out = append(out, map[string]any{"id": s[0], "name": s[1], "description": "Skill " + s[0] + ".", "tags": tags})
		}
		card["skills"] = out
	}
}

func cardParams(card map[string]any) map[string]any {
	ext := card["capabilities"].(map[string]any)["extensions"].([]any)[0].(map[string]any)
	return ext["params"].(map[string]any)
}

// signA2A signs card under signer's current key state, with the jku a
// daemon writes.
func signA2A(t *testing.T, signer *identity.Controller, card map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	out, err := a2acard.SignWithController(b, signer, "https://hub.example.org/agents/"+signer.AID()+"/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// editSigned changes a signed card without re-signing it.
func editSigned(t *testing.T, signed json.RawMessage, edit func(map[string]any)) json.RawMessage {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(signed, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// registerA2A registers c with card in a2a_card (nil: no field) and
// returns the answer; the registration itself must succeed.
func registerA2A(t *testing.T, srv *httptest.Server, c *identity.Controller, name string, caps []string, card json.RawMessage) aghub.RegisterResponse {
	t.Helper()
	body := registerBody(t, c, name, caps)
	if card != nil {
		body["a2a_card"] = card
	}
	code, b := signedDo(t, srv, c, relayauth.ActionRegister, http.MethodPost, "/register", body)
	if code != http.StatusOK {
		t.Fatalf("register %s: %d %s", name, code, b)
	}
	var out aghub.RegisterResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// registry fetches one page of GET /a2a/v1/agents.
func registry(t *testing.T, srv *httptest.Server, query string) aghub.A2AAgentList {
	t.Helper()
	code, b := getJSON(t, srv.URL+"/a2a/v1/agents"+query)
	if code != http.StatusOK {
		t.Fatalf("GET /a2a/v1/agents%s: %d %s", query, code, b)
	}
	var out aghub.A2AAgentList
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("registry body: %v: %s", err, b)
	}
	return out
}

func registryAIDs(l aghub.A2AAgentList) []string {
	out := []string{}
	for _, e := range l.Agents {
		out = append(out, e.AID)
	}
	return out
}

// directoryEntry is c's entry in GET /agents?cap=capID, or nil.
func directoryEntry(t *testing.T, srv *httptest.Server, capID, aid string) *aghub.AgentView {
	t.Helper()
	_, b := getJSON(t, srv.URL+"/agents?cap="+capID)
	var out struct {
		Agents []aghub.AgentView `json:"agents"`
	}
	_ = json.Unmarshal(b, &out)
	for i := range out.Agents {
		if out.Agents[i].AID == aid {
			return &out.Agents[i]
		}
	}
	return nil
}

// A card that verifies is stored as its bytes, listed with the hub's
// statements around it, and becomes the source of the agent's directory
// name and capability ids. The same card again is "unchanged", and a
// registration without the field keeps it.
func TestAnA2ACardIsAdmittedListedAndNamesTheAgent(t *testing.T) {
	srv := newHub(t)
	c, _ := twoAgents(t)
	card := signA2A(t, c, a2aCardFor(c, 10))
	out := registerA2A(t, srv, c, "Declared Name", []string{"declared.cap"}, card)
	if out.CardStatus != aghub.CardStatusOK || out.CardError != "" {
		t.Fatalf("first card: %+v", out)
	}
	l := registry(t, srv, "")
	if len(l.Agents) != 1 || l.NextCursor != "" {
		t.Fatalf("registry: %+v", l)
	}
	e := l.Agents[0]
	if e.AID != c.AID() || !bytes.Equal(e.Card, card) || e.CardVerification != aghub.CardVerificationOK ||
		e.VerifiedAt == "" || e.HomeHub != srv.URL || e.ReviewCount != 0 {
		t.Errorf("entry: %+v\ncard sent: %s", e, card)
	}
	// /agents keeps its shape, and its name and capability ids now come
	// from the card (§10.5).
	if d := directoryEntry(t, srv, "echo", c.AID()); d == nil || d.Name != "Test Agent" ||
		strings.Join(d.Caps, ",") != "echo" {
		t.Errorf("directory entry from the card: %+v", d)
	}
	if d := directoryEntry(t, srv, "declared.cap", c.AID()); d != nil {
		t.Errorf("the declared capability outlived the card that replaced it: %+v", d)
	}
	if out = registerA2A(t, srv, c, "Declared Name", []string{"declared.cap"}, card); out.CardStatus != aghub.CardStatusUnchanged {
		t.Errorf("the same card again: %+v", out)
	}
	if out = registerA2A(t, srv, c, "Declared Name", []string{"declared.cap"}, nil); out.CardStatus != aghub.CardStatusAbsent {
		t.Errorf("no card: %+v", out)
	}
	if got := registryAIDs(registry(t, srv, "")); len(got) != 1 {
		t.Errorf("a registration without a card dropped the stored one: %v", got)
	}
	if d := directoryEntry(t, srv, "echo", c.AID()); d == nil || d.Name != "Test Agent" {
		t.Errorf("a registration without a card took the name back from it: %+v", d)
	}
}

// Every rejection is reported per field, names the a2acard code, stores
// nothing, and leaves an admitted card in place.
func TestA2ACardRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		// prior, when set, is admitted first (seq 10).
		prior  bool
		card   func(t *testing.T, c, other *identity.Controller) json.RawMessage
		status string
		code   a2acard.Code
		detail string
	}{
		{name: "empty signatures", status: aghub.CardStatusInvalid, code: a2acard.CodeUnsigned,
			card: func(t *testing.T, c, _ *identity.Controller) json.RawMessage {
				return editSigned(t, signA2A(t, c, a2aCardFor(c, 1)), func(m map[string]any) { m["signatures"] = []any{} })
			}},
		{name: "kid names another AID", status: aghub.CardStatusInvalid, code: a2acard.CodeBindingMismatch,
			card: func(t *testing.T, c, other *identity.Controller) json.RawMessage {
				return signA2A(t, other, a2aCardFor(c, 1))
			}},
		{name: "card for another AID", status: aghub.CardStatusInvalid, code: a2acard.CodeKELUnavailable,
			detail: "not for the registrant",
			card: func(t *testing.T, _, other *identity.Controller) json.RawMessage {
				return signA2A(t, other, a2aCardFor(other, 1))
			}},
		{name: "relay tenant is another AID", status: aghub.CardStatusInvalid, code: a2acard.CodeBindingMismatch,
			card: func(t *testing.T, c, other *identity.Controller) json.RawMessage {
				return signA2A(t, c, a2aCardFor(c, 1, func(m map[string]any) {
					m["supportedInterfaces"].([]any)[0].(map[string]any)["tenant"] = other.AID()
				}))
			}},
		{name: "key retired by a rotation", status: aghub.CardStatusInvalid, code: a2acard.CodeKeyNotCurrent,
			card: func(t *testing.T, c, _ *identity.Controller) json.RawMessage {
				card := signA2A(t, c, a2aCardFor(c, 1))
				if err := c.Rotate(uint64(time.Now().UnixMilli())); err != nil {
					t.Fatal(err)
				}
				return card // registered with the rotated KEL
			}},
		{name: "notBefore more than 300 s ahead", status: aghub.CardStatusInvalid, code: a2acard.CodeNotYetValid,
			card: func(t *testing.T, c, _ *identity.Controller) json.RawMessage {
				return signA2A(t, c, a2aCardFor(c, 1, func(m map[string]any) {
					cardParams(m)["notBefore"] = strconv.FormatInt(time.Now().Add(10*time.Minute).UnixMilli(), 10)
				}))
			}},
		{name: "over 64 KiB", status: aghub.CardStatusInvalid, code: a2acard.CodeTooLarge,
			card: func(t *testing.T, c, _ *identity.Controller) json.RawMessage {
				return editSigned(t, signA2A(t, c, a2aCardFor(c, 1)), func(m map[string]any) {
					m["documentationUrl"] = "https://example.org/" + strings.Repeat("a", 64<<10)
				})
			}},
		{name: "REQUIRED member missing", status: aghub.CardStatusInvalid, code: a2acard.CodeInvalidCard,
			detail: "version is missing",
			card: func(t *testing.T, c, _ *identity.Controller) json.RawMessage {
				return editSigned(t, signA2A(t, c, a2aCardFor(c, 1)), func(m map[string]any) { delete(m, "version") })
			}},
		{name: "signature over other content", status: aghub.CardStatusInvalid, code: a2acard.CodeInvalidSignature,
			card: func(t *testing.T, c, _ *identity.Controller) json.RawMessage {
				return editSigned(t, signA2A(t, c, a2aCardFor(c, 1)), func(m map[string]any) { m["name"] = "Someone Else" })
			}},
		{name: "seq below the stored one", prior: true, status: aghub.CardStatusConflict, code: a2acard.CodeSeqRollback,
			card: func(t *testing.T, c, _ *identity.Controller) json.RawMessage {
				return signA2A(t, c, a2aCardFor(c, 9))
			}},
		{name: "stored seq with another payload", prior: true, status: aghub.CardStatusConflict, code: a2acard.CodeSeqFork,
			card: func(t *testing.T, c, _ *identity.Controller) json.RawMessage {
				return signA2A(t, c, a2aCardFor(c, 10, func(m map[string]any) { m["description"] = "Something else." }))
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newHub(t)
			c, other := twoAgents(t)
			var prior json.RawMessage
			if tc.prior {
				prior = signA2A(t, c, a2aCardFor(c, 10))
				if out := registerA2A(t, srv, c, "Agent", nil, prior); out.CardStatus != aghub.CardStatusOK {
					t.Fatalf("prior card: %+v", out)
				}
			}
			card := tc.card(t, c, other)
			out := registerA2A(t, srv, c, "Agent", nil, card)
			if out.CardStatus != tc.status || !strings.HasPrefix(out.CardError, string(tc.code)) ||
				!strings.Contains(out.CardError, tc.detail) {
				t.Fatalf("card_status %q card_error %q, want %q led by %s (containing %q)",
					out.CardStatus, out.CardError, tc.status, tc.code, tc.detail)
			}
			l := registry(t, srv, "")
			switch {
			case prior == nil && len(l.Agents) != 0:
				t.Errorf("a refused card is listed: %+v", l)
			case prior != nil && (len(l.Agents) != 1 || !bytes.Equal(l.Agents[0].Card, prior)):
				t.Errorf("the refused card displaced the admitted one: %+v", l)
			}
		})
	}
	t.Run("not a JSON object", func(t *testing.T) {
		srv := newHub(t)
		c, _ := twoAgents(t)
		if out := registerA2A(t, srv, c, "Agent", nil, json.RawMessage(`"card"`)); out.CardStatus != aghub.CardStatusInvalid ||
			!strings.Contains(out.CardError, "JSON object") {
			t.Errorf("%+v", out)
		}
	})
}

// skill and tag select through the indexes, q matches name, description
// and skill names ignoring case (beyond ASCII), and pages follow the
// cursor without gaps or repeats.
func TestTheRegistryFiltersAndPages(t *testing.T) {
	srv := newHub(t)
	var agents []*identity.Controller
	for i, card := range []func(map[string]any){
		withSkills([]string{"echo", "Echo", "text", "echo"}),
		withSkills([]string{"translate", "Translate", "text", "translation"}),
		func(m map[string]any) {
			m["name"] = "Ärger Agent"
			m["description"] = "Handles Complaints."
			withSkills([]string{"summarize", "Summarize", "ml"})(m)
		},
	} {
		c, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		if out := registerA2A(t, srv, c, "Agent", nil, signA2A(t, c, a2aCardFor(c, uint64(i+1), card))); out.CardStatus != aghub.CardStatusOK {
			t.Fatalf("agent %d: %+v", i, out)
		}
		agents = append(agents, c)
	}
	echo, translate, summarize := agents[0].AID(), agents[1].AID(), agents[2].AID()
	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"?skill=echo", []string{echo}},
		{"?skill=ech", nil}, // exact, not a prefix
		{"?tag=text", []string{echo, translate}},
		{"?tag=text&skill=translate", []string{translate}},
		{"?tag=ml", []string{summarize}},
		{"?q=TRANSLATE", []string{translate}},  // skill name
		{"?q=complaints", []string{summarize}}, // description
		{"?q=%C3%A4rger", []string{summarize}}, // name, "ärger" against "Ärger"
		{"?q=nothing-matches-this", nil},
	} {
		got := registryAIDs(registry(t, srv, tc.query))
		if !sameSet(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.query, got, tc.want)
		}
	}
	// Pages of two: two, then one, in AID order, covering everyone once.
	first := registry(t, srv, "?limit=2")
	if len(first.Agents) != 2 || first.NextCursor == "" {
		t.Fatalf("first page: %+v", first)
	}
	second := registry(t, srv, "?limit=2&cursor="+first.NextCursor)
	if len(second.Agents) != 1 || second.NextCursor != "" {
		t.Fatalf("second page: %+v", second)
	}
	all := append(registryAIDs(first), registryAIDs(second)...)
	if !sameSet(all, []string{echo, translate, summarize}) || !(all[0] < all[1] && all[1] < all[2]) {
		t.Errorf("pages: %v", all)
	}
	for _, q := range []string{"?limit=0", "?limit=x", "?cursor=***", "?skill=", "?tag=%20"} {
		if code, b := getJSON(t, srv.URL+"/a2a/v1/agents"+q); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", q, code, b)
		}
	}
	if l := registry(t, srv, "?limit=100000"); len(l.Agents) != 3 {
		t.Errorf("a limit over the maximum: %+v", l)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		if seen[s] == 0 {
			return false
		}
		seen[s]--
	}
	return true
}

// The card endpoint serves the agent's bytes with a strong ETag over
// them, a five-minute max-age, and 304 for a matching If-None-Match.
func TestTheCardEndpointServesTheAgentsBytes(t *testing.T) {
	srv := newHub(t)
	c, bare := twoAgents(t)
	card := signA2A(t, c, a2aCardFor(c, 1))
	registerA2A(t, srv, c, "Agent", nil, card)
	registerA2A(t, srv, bare, "Bare", nil, nil)
	url := srv.URL + "/a2a/v1/agents/" + c.AID() + "/card"
	sum := sha256.Sum256(card)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	code, body, hdr := send(t, newGet(t, url, ""))
	if code != http.StatusOK || !bytes.Equal(body, card) || hdr.Get("ETag") != etag ||
		hdr.Get("Cache-Control") != "max-age=300" || hdr.Get("Content-Type") != "application/json" {
		t.Fatalf("card: %d %v\n%s", code, hdr, body)
	}
	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		if code, body, _ := send(t, newGet(t, url, inm)); code != http.StatusNotModified || len(body) != 0 {
			t.Errorf("If-None-Match %s: %d %s, want 304", inm, code, body)
		}
	}
	if code, _, _ := send(t, newGet(t, url, `"other"`)); code != http.StatusOK {
		t.Errorf("a stale If-None-Match: %d, want 200", code)
	}
	for _, aid := range []string{bare.AID(), "bafyunknown"} {
		if code, _, _ := send(t, newGet(t, srv.URL+"/a2a/v1/agents/"+aid+"/card", "")); code != http.StatusNotFound {
			t.Errorf("card of %s: %d, want 404", aid, code)
		}
	}
}

// newGet is a plain GET, as an external A2A client sends it: no wire
// header, optionally conditional.
func newGet(t *testing.T, url, ifNoneMatch string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	return req
}

// ANetCore's a2acard vectors hold for a hub: the suite identity's card
// is admitted, and its JWKS is the golden one byte for byte.
func TestTheHubAgreesWithTheA2ACardGoldenVectors(t *testing.T) {
	dir := a2acardTestdata(t)
	card, err := os.ReadFile(filepath.Join(dir, "golden-card.json"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(dir, "golden-jwks.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := newHub(t)
	suite := identity.SuiteController()
	if out := registerA2A(t, srv, suite, "Suite", nil, bytes.TrimSpace(card)); out.CardStatus != aghub.CardStatusOK {
		t.Fatalf("golden card: %+v", out)
	}
	code, got, hdr := send(t, newGet(t, srv.URL+"/agents/"+suite.AID()+"/jwks.json", ""))
	if code != http.StatusOK || !bytes.Equal(got, bytes.TrimSpace(want)) || hdr.Get("ETag") == "" {
		t.Errorf("jwks: %d %v\n got %s\nwant %s", code, hdr, got, want)
	}
}

// a2acardTestdata locates ANetCore's a2acard/testdata through the go
// command, so the test reads the vectors of the ANetCore it builds with.
func a2acardTestdata(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", "github.com/ANetResearch/ANetCore/a2acard").Output()
	if err != nil {
		t.Skipf("cannot locate ANetCore a2acard: %v", err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "testdata")
}

// The JWKS lists the key states a card may be signed under and nothing
// else: after a rotation the retired kid is gone.
func TestTheJWKSListsOnlyTheActiveKeyStates(t *testing.T) {
	srv := newHub(t)
	c, _ := twoAgents(t)
	registerA2A(t, srv, c, "Agent", nil, nil)
	kids := func() []string {
		t.Helper()
		code, b, _ := send(t, newGet(t, srv.URL+"/agents/"+c.AID()+"/jwks.json", ""))
		if code != http.StatusOK {
			t.Fatalf("jwks: %d %s", code, b)
		}
		var set struct {
			Keys []struct {
				Kid string `json:"kid"`
				X   string `json:"x"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(b, &set); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, k := range set.Keys {
			out = append(out, k.Kid)
		}
		return out
	}
	if got := kids(); strings.Join(got, ",") != a2acard.KID(c.AID(), 0) {
		t.Fatalf("before rotation: %v", got)
	}
	if err := c.Rotate(uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	registerA2A(t, srv, c, "Agent", nil, nil)
	if got := kids(); strings.Join(got, ",") != a2acard.KID(c.AID(), 1) {
		t.Errorf("after rotation: %v, want only %s", got, a2acard.KID(c.AID(), 1))
	}
	if code, _, _ := send(t, newGet(t, srv.URL+"/agents/bafyunknown/jwks.json", "")); code != http.StatusNotFound {
		t.Errorf("jwks of an unknown AID: %d, want 404", code)
	}
}

// A card is listed only while it verifies and its agent is registered and
// browsable: a rotation that retires the signing key delists it until it
// is re-signed, an abandoned agent drops out, and so does an agent whose
// row an operator deleted.
func TestOnlyVerifiedCardsAreListed(t *testing.T) {
	dir := t.TempDir()
	srv, store, _ := newHubAt(t, dir)
	c, other := twoAgents(t)
	body := a2aCardFor(c, 5)
	if out := registerA2A(t, srv, c, "Declared", []string{"declared.cap"}, signA2A(t, c, body)); out.CardStatus != aghub.CardStatusOK {
		t.Fatalf("card: %+v", out)
	}
	if err := c.Rotate(uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if out := registerA2A(t, srv, c, "Declared", []string{"declared.cap"}, nil); out.CardStatus != aghub.CardStatusAbsent {
		t.Fatalf("re-registration after the rotation: %+v", out)
	}
	if l := registry(t, srv, "?skill=echo"); len(l.Agents) != 0 {
		t.Errorf("a card signed by a retired key is listed: %+v", l)
	}
	if code, _ := getJSON(t, srv.URL+"/a2a/v1/agents/"+c.AID()+"/card"); code != http.StatusNotFound {
		t.Errorf("card signed by a retired key: %d, want 404", code)
	}
	if d := directoryEntry(t, srv, "declared.cap", c.AID()); d == nil || d.Name != "Declared" {
		t.Errorf("with the card delisted the registration's own name and capabilities stand: %+v", d)
	}
	// The same statement re-signed under the new key is the same card.
	resigned := signA2A(t, c, body)
	if out := registerA2A(t, srv, c, "Declared", nil, resigned); out.CardStatus != aghub.CardStatusUnchanged {
		t.Fatalf("re-signed card: %+v", out)
	}
	if l := registry(t, srv, ""); len(l.Agents) != 1 || !bytes.Equal(l.Agents[0].Card, resigned) {
		t.Fatalf("the re-signed card is not what is listed: %+v", l)
	}
	// Abandoned: out of the registry, as out of /agents.
	if err := store.SetLastSeenForTest(c.AID(), time.Now().Add(-40*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if l := registry(t, srv, ""); len(l.Agents) != 0 {
		t.Errorf("an abandoned agent is listed: %+v", l)
	}
	// An operator deleting the agent row (admin DeleteAgent) takes the
	// card off every registry answer, even with other rows left behind.
	registerA2A(t, srv, other, "Other", nil, signA2A(t, other, a2aCardFor(other, 1)))
	if l := registry(t, srv, ""); len(l.Agents) != 1 {
		t.Fatalf("precondition, the other agent is listed: %+v", l)
	}
	if _, err := openDB(t, dir).Exec(`DELETE FROM agent WHERE aid=?`, other.AID()); err != nil {
		t.Fatal(err)
	}
	if l := registry(t, srv, ""); len(l.Agents) != 0 {
		t.Errorf("a card without its agent row is listed: %+v", l)
	}
	if code, _ := getJSON(t, srv.URL+"/a2a/v1/agents/"+other.AID()+"/card"); code != http.StatusNotFound {
		t.Errorf("card without its agent row: %d, want 404", code)
	}
}

// A card stored before admission existed is verified when the hub opens
// its database: kept (and indexed) if it verifies, deleted otherwise.
func TestCardsStoredBeforeAdmissionAreVerifiedOnUpgrade(t *testing.T) {
	dir := t.TempDir()
	srv, store, _ := newHubAt(t, dir)
	good, bad := twoAgents(t)
	registerA2A(t, srv, good, "Good", nil, nil)
	registerA2A(t, srv, bad, "Bad", nil, nil)
	db := openDB(t, dir)
	goodCard := signA2A(t, good, a2aCardFor(good, 1))
	badCard := editSigned(t, signA2A(t, bad, a2aCardFor(bad, 1)), func(m map[string]any) { m["name"] = "Forged" })
	for aid, card := range map[string][]byte{good.AID(): goodCard, bad.AID(): badCard} {
		// What the pre-admission hub wrote: bytes, no mark.
		if _, err := db.Exec(`INSERT INTO agent_a2a_card(aid, card, stored_at) VALUES(?,?,?)`,
			aid, card, time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	srv.Close()
	store.Close()
	srv2, _, _ := newHubAt(t, dir)
	l := registry(t, srv2, "")
	if len(l.Agents) != 1 || l.Agents[0].AID != good.AID() || !bytes.Equal(l.Agents[0].Card, goodCard) {
		t.Errorf("after the upgrade: %+v", l)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM agent_a2a_card WHERE aid=?`, bad.AID()).Scan(&n)
	if n != 0 {
		t.Error("a stored card that does not verify survived the upgrade")
	}
	if got := registryAIDs(registry(t, srv2, "?skill=echo")); len(got) != 1 {
		t.Errorf("the readmitted card is not indexed: %v", got)
	}
}

// The registry's cursor is opaque base64url; decoding it is the hub's
// business, but a caller passing it back must get the next page.
func TestTheRegistryCursorRoundTrips(t *testing.T) {
	srv := newHub(t)
	c, _ := twoAgents(t)
	registerA2A(t, srv, c, "Agent", nil, signA2A(t, c, a2aCardFor(c, 1)))
	cursor := base64.RawURLEncoding.EncodeToString([]byte(c.AID()))
	if l := registry(t, srv, "?cursor="+cursor); len(l.Agents) != 0 {
		t.Errorf("a cursor at the last AID: %+v", l)
	}
}
