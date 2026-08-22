package aghub_test

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"

	_ "modernc.org/sqlite"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

func newHub(t *testing.T) *httptest.Server {
	srv, _ := newHubWithStore(t)
	return srv
}

// newHubWithStore also hands back the store, for the things a hub
// operator does directly rather than over HTTP.
func newHubWithStore(t *testing.T) (*httptest.Server, *aghub.Store) {
	t.Helper()
	store, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The signing key too, as main.go does. Without it signSettlement is
	// a silent no-op and every test here would be exercising a hub that
	// signs nothing — which is precisely the shape of harness that lets an
	// unsigned production path pass a full green suite.
	store.SetHubKey(id.Ctrl)
	s := aghub.NewServer(store)
	s.SetHubAID(id.AID)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); store.Close() })
	testHubAID.Store(srv.URL, id.AID)
	testHubStores.Store(srv.URL, store)
	testHubCtrl.Store(srv.URL, id.Ctrl)
	return srv, store
}

var testHubAID sync.Map

// testHubCtrl is the hub identity behind a test server, for checking
// signatures the hub produced.
var testHubCtrl sync.Map

// fundAgent credits an account.
//
// Deliberately not an HTTP endpoint. Who may create credit is a policy
// question — an operator's billing system, a faucet, a grant — and this
// round answers the protocol, not that. Until it is answered, funding is
// something the operator does to their own store.
func fundAgent(t *testing.T, srv *httptest.Server, aid string, amount int64) {
	t.Helper()
	v, ok := testHubStores.Load(srv.URL)
	if !ok {
		t.Fatal("no store for this hub")
	}
	if err := v.(*aghub.Store).Credit(aid, amount, "test grant"); err != nil {
		t.Fatal(err)
	}
}

var testHubStores sync.Map

func post(t *testing.T, url string, body any) (int, []byte) {
	t.Helper()
	buf, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// register does what the daemon does: signs the challenge AND publishes a
// card, so the claims are attributable to the agent rather than to the
// hub storing them.
func register(t *testing.T, srv *httptest.Server, c *identity.Controller, name string, caps []string) {
	t.Helper()
	code, b := registerWithCard(t, srv, c, name, caps, mintCard(t, c, name, caps))
	if code != 200 {
		t.Fatalf("register %s: %d %s", name, code, b)
	}
}

// registerLegacy is a node that predates cards. It must still register.
func registerLegacy(t *testing.T, srv *httptest.Server, c *identity.Controller, name string, caps []string) {
	t.Helper()
	code, b := registerWithCard(t, srv, c, name, caps, nil)
	if code != 200 {
		t.Fatalf("register %s: %d %s", name, code, b)
	}
}

func registerWithCard(t *testing.T, srv *httptest.Server, c *identity.Controller,
	name string, caps []string, card json.RawMessage) (int, []byte) {
	t.Helper()
	kelB, _ := identity.MarshalKEL(c.KEL())
	ts := uint64(time.Now().UnixMilli())
	sig, seq := c.Sign(relayauth.Preimage(relayauth.ActionRegister, c.AID(), ts))
	body := map[string]any{
		"aid": c.AID(), "name": name, "caps": caps,
		"kel": base64.StdEncoding.EncodeToString(kelB),
		"ts":  ts, "key_state_seq": seq, "sig": base64.StdEncoding.EncodeToString(sig),
	}
	if len(card) > 0 {
		body["card"] = card
	}
	return post(t, srv.URL+"/register", body)
}

func mintCard(t *testing.T, c *identity.Controller, name string, caps []string) json.RawMessage {
	t.Helper()
	if caps == nil {
		caps = []string{}
	}
	now := time.Now()
	card := &adp.AgentCard{
		SubjectDID: c.AID(), CardSchema: adp.CardSchema{Major: 1},
		Seq: uint64(now.UnixNano()), IssuedAt: now.Unix(),
		NotBefore:    now.Add(-time.Minute).Unix(),
		Capabilities: caps, CriticalExtensions: []string{}, Name: name,
	}
	if err := card.Sign(c); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// interactionContent is the raw request + deliverable bytes an upload must carry; the Hub re-hashes them
// against the receipt's anchors. These stand in for the signed TaskDoc + deliverable.
var (
	testRequestDoc  = []byte("the request: bake sourdough")
	testDeliverable = []byte("the deliverable: a crusty loaf recipe")
)

// makeEvidence builds an interlocking provider-signed receipt + requester-signed review for one
// interaction, with the receipt's content anchors set to the real hashes of testRequestDoc /
// testDeliverable. Returns everything base64-encoded, ready to POST to /reviews.
func makeEvidence(t *testing.T, prov, req *identity.Controller, ixID string, rating int, subjectOverride string) map[string]string {
	t.Helper()
	reqCID, _ := anetcid.Sum(testRequestDoc)
	resCID, _ := anetcid.Sum(testDeliverable)
	rc := &evidence.Receipt{InteractionID: ixID, RequesterAID: req.AID(), ProviderAID: prov.AID(), RequestCID: reqCID, ResultCID: resCID, CompletedAt: 1000}
	if err := rc.Sign(prov); err != nil {
		t.Fatal(err)
	}
	rcid, _ := rc.CID()
	subject := prov.AID()
	if subjectOverride != "" {
		subject = subjectOverride
	}
	rv := &evidence.Review{InteractionID: ixID, SubjectAID: subject, ReviewerAID: req.AID(), Rating: rating, ReceiptCID: rcid, CreatedAt: 2000}
	if err := rv.Sign(req); err != nil {
		t.Fatal(err)
	}
	rcB, _ := rc.Marshal()
	rvB, _ := rv.Marshal()
	return map[string]string{
		"receipt":     base64.StdEncoding.EncodeToString(rcB),
		"review":      base64.StdEncoding.EncodeToString(rvB),
		"request_doc": base64.StdEncoding.EncodeToString(testRequestDoc),
		"deliverable": base64.StdEncoding.EncodeToString(testDeliverable),
	}
}

// The happy path: two registered agents, one real interaction → the review is verified, stored, and
// aggregated into the provider's average.
func TestUploadReviewHappyPath(t *testing.T) {
	srv := newHub(t)
	prov, _ := identity.Incept()
	req, _ := identity.Incept()
	register(t, srv, prov, "Provider", []string{"bakery"})
	register(t, srv, req, "Requester", nil)

	if code, b := post(t, srv.URL+"/reviews", makeEvidence(t, prov, req, "ix_1", 5, "")); code != 200 {
		t.Fatalf("upload: %d %s", code, b)
	}

	resp, err := http.Get(srv.URL + "/agents/" + prov.AID())
	if err != nil {
		t.Fatalf("get agent: %v", err)
	}
	defer resp.Body.Close()
	var got struct {
		Agent   aghub.AgentView    `json:"agent"`
		Reviews []aghub.ReviewView `json:"reviews"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.Agent.ReviewCount != 1 || got.Agent.AvgRating != 5 {
		t.Fatalf("aggregate = count %d avg %v, want 1/5", got.Agent.ReviewCount, got.Agent.AvgRating)
	}
	if len(got.Reviews) != 1 || got.Reviews[0].Rating != 5 {
		t.Fatalf("reviews = %+v", got.Reviews)
	}
	// The stored review must carry the verified interaction content, not just the rating.
	if got.Reviews[0].Deliverable != string(testDeliverable) {
		t.Fatalf("review deliverable = %q, want %q", got.Reviews[0].Deliverable, testDeliverable)
	}
	if got.Reviews[0].ResultCID == "" || got.Reviews[0].RequestCID == "" {
		t.Fatalf("review missing content anchors: %+v", got.Reviews[0])
	}
}

// A review whose uploaded deliverable does not hash to the receipt's result_cid is rejected — the
// displayed content is always bound to what the provider signed.
func TestUploadReviewTamperedContentRejected(t *testing.T) {
	srv := newHub(t)
	prov, _ := identity.Incept()
	req, _ := identity.Incept()
	register(t, srv, prov, "P", nil)
	register(t, srv, req, "R", nil)
	body := makeEvidence(t, prov, req, "ix_tamper", 5, "")
	body["deliverable"] = base64.StdEncoding.EncodeToString([]byte("a forged, better-sounding deliverable"))
	if code, b := post(t, srv.URL+"/reviews", body); code == 200 {
		t.Fatalf("tampered deliverable must be rejected, got %d %s", code, b)
	}
}

// A review upload missing its interaction content is rejected (content is mandatory in v0.1).
func TestUploadReviewMissingContentRejected(t *testing.T) {
	srv := newHub(t)
	prov, _ := identity.Incept()
	req, _ := identity.Incept()
	register(t, srv, prov, "P", nil)
	register(t, srv, req, "R", nil)
	body := makeEvidence(t, prov, req, "ix_nocontent", 5, "")
	delete(body, "deliverable")
	delete(body, "request_doc")
	if code, b := post(t, srv.URL+"/reviews", body); code == 200 {
		t.Fatalf("missing content must be rejected, got %d %s", code, b)
	}
}

// The same interaction cannot be reviewed twice (interaction_id is the uniqueness key).
func TestUploadReviewDuplicateRejected(t *testing.T) {
	srv := newHub(t)
	prov, _ := identity.Incept()
	req, _ := identity.Incept()
	register(t, srv, prov, "P", nil)
	register(t, srv, req, "R", nil)
	body := makeEvidence(t, prov, req, "ix_dup", 4, "")
	if code, _ := post(t, srv.URL+"/reviews", body); code != 200 {
		t.Fatal("first upload should succeed")
	}
	if code, _ := post(t, srv.URL+"/reviews", body); code == 200 {
		t.Fatal("duplicate interaction must be rejected")
	}
}

// A review whose subject does not match the receipt's provider is rejected (interlock check).
func TestUploadReviewSubjectMismatchRejected(t *testing.T) {
	srv := newHub(t)
	prov, _ := identity.Incept()
	req, _ := identity.Incept()
	register(t, srv, prov, "P", nil)
	register(t, srv, req, "R", nil)
	if code, b := post(t, srv.URL+"/reviews", makeEvidence(t, prov, req, "ix_bad", 5, "did:anet:someone-else")); code == 200 {
		t.Fatalf("subject mismatch must be rejected, got %d %s", code, b)
	}
}

// Evidence for an unregistered provider is rejected (the Hub has no KEL to verify the receipt against).
func TestUploadReviewUnregisteredProviderRejected(t *testing.T) {
	srv := newHub(t)
	prov, _ := identity.Incept()
	req, _ := identity.Incept()
	register(t, srv, req, "R", nil) // only the requester registers
	if code, _ := post(t, srv.URL+"/reviews", makeEvidence(t, prov, req, "ix_np", 5, "")); code == 200 {
		t.Fatal("unregistered provider must be rejected")
	}
}

// The relay broker: a message sent to a registered recipient is queued, pulled by the KEL-signed owner,
// and acked; a poll signed by the WRONG identity is rejected.
func TestRelayBrokerSendPollAck(t *testing.T) {
	srv := newHub(t)
	recip, _ := identity.Incept()
	sender, _ := identity.Incept()
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)

	// send is open, but the recipient must be registered.
	payload := base64.StdEncoding.EncodeToString([]byte("hello mailbox"))
	if code, b := post(t, srv.URL+"/relay/send", map[string]any{
		"to_aid": recip.AID(), "from_aid": sender.AID(), "kind": aghub.RelayKindDelegate,
		"interaction_id": "ix_relay", "payload": payload,
	}); code != 200 {
		t.Fatalf("relay send: %d %s", code, b)
	}

	// a poll that CLAIMS the recipient's AID but is signed by another key must be rejected — you can
	// only read a mailbox you provably control.
	forged := signedRelay(t, "poll", sender)
	forged["aid"] = recip.AID()
	if code, _ := post(t, srv.URL+"/relay/poll", forged); code == 200 {
		t.Fatal("forged poll (recipient AID, wrong key) must be rejected")
	}

	// the recipient polls its mailbox and gets the message.
	code, b := post(t, srv.URL+"/relay/poll", signedRelay(t, "poll", recip))
	if code != 200 {
		t.Fatalf("relay poll: %d %s", code, b)
	}
	var polled struct {
		Messages []struct {
			ID      int64  `json:"id"`
			Kind    string `json:"kind"`
			Payload string `json:"payload"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(b, &polled)
	if len(polled.Messages) != 1 || polled.Messages[0].Kind != aghub.RelayKindDelegate {
		t.Fatalf("polled = %+v, want 1 delegate message", polled.Messages)
	}

	// ack it, then a re-poll returns nothing.
	ack := signedRelay(t, "ack", recip)
	ack["ids"] = []int64{polled.Messages[0].ID}
	if code, b := post(t, srv.URL+"/relay/ack", ack); code != 200 {
		t.Fatalf("relay ack: %d %s", code, b)
	}
	_, b = post(t, srv.URL+"/relay/poll", signedRelay(t, "poll", recip))
	_ = json.Unmarshal(b, &polled)
	if len(polled.Messages) != 0 {
		t.Fatalf("after ack, mailbox should be empty, got %d", len(polled.Messages))
	}
}

// signedRelay builds a KEL-signed relay auth body for the given action + identity.
func signedRelay(t *testing.T, action string, c *identity.Controller) map[string]any {
	t.Helper()
	ts := uint64(time.Now().UnixMilli())
	sig, seq := c.Sign(relayauth.Preimage(action, c.AID(), ts))
	return map[string]any{
		"aid": c.AID(), "ts": ts, "key_state_seq": seq,
		"sig": base64.StdEncoding.EncodeToString(sig),
	}
}

// A registration without a valid signed challenge is rejected — merely knowing a public KEL must not let
// a stranger register/overwrite that AID.
func TestRegisterRequiresSignature(t *testing.T) {
	srv := newHub(t)
	c, _ := identity.Incept()
	kelB, _ := identity.MarshalKEL(c.KEL())
	// no ts/sig
	if code, _ := post(t, srv.URL+"/register", map[string]any{
		"aid": c.AID(), "name": "NoSig", "kel": base64.StdEncoding.EncodeToString(kelB),
	}); code == 200 {
		t.Fatal("register without a signed challenge must be rejected")
	}
}

// A pure requester (registered, no caps/profile) is NOT listed; once its agent publishes a profile it
// becomes listed and its readme/pricing are shown. A forged profile update (wrong key) is rejected.
func TestProfileListingAndAuth(t *testing.T) {
	srv := newHub(t)
	c, _ := identity.Incept()
	other, _ := identity.Incept()
	register(t, srv, c, "Solo", nil) // no caps
	register(t, srv, other, "Other", nil)

	// Not listed yet: absent from /agents.
	if listedContains(t, srv, c.AID()) {
		t.Fatal("agent with no caps/profile must not be listed")
	}

	// A forged profile update (claims c's AID, signed by other's key) must be rejected.
	forged := signedProfile(t, other, "hi", "readme", "free")
	forged["aid"] = c.AID()
	if code, _ := post(t, srv.URL+"/profile", forged); code == 200 {
		t.Fatal("forged profile update must be rejected")
	}

	// The owner publishes a profile → now listed, with content shown.
	body := signedProfile(t, c, "does translations", "# Bob\nFast + accurate", "¥1 per line")
	if code, b := post(t, srv.URL+"/profile", body); code != 200 {
		t.Fatalf("profile update: %d %s", code, b)
	}
	if !listedContains(t, srv, c.AID()) {
		t.Fatal("agent with a profile must be listed")
	}
	resp, err := http.Get(srv.URL + "/agents/" + c.AID())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Agent aghub.AgentView `json:"agent"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.Agent.Readme == "" || got.Agent.Pricing == "" || got.Agent.Summary == "" {
		t.Fatalf("profile not stored/returned: %+v", got.Agent)
	}
	if !got.Agent.Listed {
		t.Fatalf("agent should be listed: %+v", got.Agent)
	}
}

// signedProfile builds a KEL-signed /profile body for c.
func signedProfile(t *testing.T, c *identity.Controller, summary, readme, pricing string) map[string]any {
	t.Helper()
	ts := uint64(time.Now().UnixMilli())
	sig, seq := c.Sign(relayauth.Preimage(relayauth.ActionProfile, c.AID(), ts))
	return map[string]any{
		"aid": c.AID(), "summary": summary, "readme": readme, "pricing": pricing,
		"ts": ts, "key_state_seq": seq, "sig": base64.StdEncoding.EncodeToString(sig),
	}
}

// listedContains reports whether aid appears in the public /agents listing.
func listedContains(t *testing.T, srv *httptest.Server, aid string) bool {
	t.Helper()
	resp, err := http.Get(srv.URL + "/agents")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Agents []aghub.AgentView `json:"agents"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	for _, a := range out.Agents {
		if a.AID == aid {
			return true
		}
	}
	return false
}

// A registration whose KEL does not derive the claimed AID is rejected.
func TestRegisterAidKelMismatchRejected(t *testing.T) {
	srv := newHub(t)
	a, _ := identity.Incept()
	b, _ := identity.Incept()
	kelB, _ := identity.MarshalKEL(b.KEL()) // b's KEL under a's claimed AID
	if code, _ := post(t, srv.URL+"/register", map[string]any{
		"aid": a.AID(), "kel": base64.StdEncoding.EncodeToString(kelB),
	}); code == 200 {
		t.Fatal("aid/kel mismatch must be rejected")
	}
}

// C2 states its version on the wire.
//
// Three repos had drifted onto three different kernel versions at once and
// nothing on the wire could have told anybody. A contract that cannot say
// which contract it is has no way to catch that.
func TestWireContractVersionIsStated(t *testing.T) {
	srv := newHub(t)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-ANet-Wire"); got != "1" {
		t.Fatalf("every response must state the contract version, got %q", got)
	}
}

// A caller from the future is refused with both numbers named, because the
// alternative is a delegation that half-arrives.
func TestWireContractRefusesANewerCaller(t *testing.T) {
	srv := newHub(t)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/agents", nil)
	req.Header.Set("X-ANet-Wire", "99")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a newer caller must be refused, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "upgrade the hub") {
		t.Errorf("the refusal must say what to do: %s", b)
	}
}

// Everything built before the header existed keeps working.
func TestWireContractAcceptsALegacyCaller(t *testing.T) {
	srv := newHub(t)

	resp, err := http.Get(srv.URL + "/agents") // no version header at all
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a daemon predating the header must still be served, got %d", resp.StatusCode)
	}
}

// A receipt names the AID that signed it, and checking that signature
// needs that AID's key history. The Hub has stored every KEL since v0.1
// and published none — so the only way to obtain one was to ask a
// participant, which made "anyone can verify a receipt" true exactly when
// someone chose to cooperate. That is the property the whole scheme
// exists to remove.
func TestTheHubPublishesKeyHistories(t *testing.T) {
	srv := newHub(t)
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, c, "Provider", []string{"translate"})

	resp, err := http.Get(srv.URL + "/agents/" + c.AID() + "/kel")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("kel endpoint = %d, want 200", resp.StatusCode)
	}
	var out struct {
		AID string `json:"aid"`
		KEL string `json:"kel"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.KEL == "" {
		t.Fatal("no kel published — a third party cannot check this agent's signatures")
	}
	raw, err := base64.StdEncoding.DecodeString(out.KEL)
	if err != nil {
		t.Fatalf("kel is not base64: %v", err)
	}
	kel, err := identity.UnmarshalKEL(raw)
	if err != nil {
		t.Fatalf("published kel does not decode: %v", err)
	}
	// Usable, not merely present: replaying it must yield the AID it was
	// served under, or the endpoint is handing out somebody else's keys.
	states, err := identity.Replay(kel)
	if err != nil {
		t.Fatalf("published kel does not replay: %v", err)
	}
	if got := states[len(states)-1].AID; got != c.AID() {
		t.Errorf("published kel belongs to %s, served under %s", got, c.AID())
	}
}

// The published KEL is enough to verify a real receipt, which is the
// whole point of publishing it. This is the third party's path end to
// end: fetch the key history from the Hub, check the provider's
// signature, and never ask either participant for anything.
func TestAPublishedKELVerifiesARealReceipt(t *testing.T) {
	srv := newHub(t)
	prov, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, prov, "Provider", []string{"translate"})

	rc := &evidence.Receipt{
		InteractionID: "ix-1", RequesterAID: "did:anet:someone",
		ProviderAID: prov.AID(), RequestCID: "bafyreq", ResultCID: "bafyres",
		CompletedAt: uint64(time.Now().UnixMilli()),
	}
	if err := rc.Sign(prov); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(srv.URL + "/agents/" + rc.ProviderAID + "/kel")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		KEL string `json:"kel"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(out.KEL)
	kel, err := identity.UnmarshalKEL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Verify(kel, rc.CompletedAt); err != nil {
		t.Fatalf("a stranger with the published KEL must be able to verify: %v", err)
	}
}

func TestAnUnknownAgentHasNoKEL(t *testing.T) {
	srv := newHub(t)
	resp, err := http.Get(srv.URL + "/agents/did:anet:nobody/kel")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown agent kel = %d, want 404", resp.StatusCode)
	}
}

// A capability id is precise, structured and machine-resolvable. Discovery
// could only match it as a substring inside a JSON blob, alongside the
// agent's prose — so "who serves cas.put" was a question the network
// could not be asked, though C1 had been answering it on every single
// invocation.
func TestFindByCapability(t *testing.T) {
	srv := newHub(t)
	store, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	cam, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	prose, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, store, "StoreNode", []string{"cas.put", "cas.get"})
	register(t, srv, cam, "CameraNode", []string{"ptz.absolute@onvif/camera-006", "ptz.home@onvif/camera-006"})
	// An agent that merely talks about capabilities must not answer for
	// them. This is the substring search's failure mode, written down.
	register(t, srv, prose, "Blogger", []string{"writing"})

	names := func(q string) []string {
		resp, err := http.Get(srv.URL + "/agents?cap=" + url.QueryEscape(q))
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
		var ns []string
		for _, a := range out.Agents {
			ns = append(ns, a.Name)
		}
		sort.Strings(ns)
		return ns
	}

	if got := names("cas.put"); len(got) != 1 || got[0] != "StoreNode" {
		t.Errorf("cap=cas.put returned %v, want only StoreNode", got)
	}
	// The prefix form is a real question — "who can move a camera" — not a
	// convenience. The alternative is asking for prose and hoping the
	// provider described itself the way the caller thought to search.
	if got := names("ptz.*"); len(got) != 1 || got[0] != "CameraNode" {
		t.Errorf("cap=ptz.* returned %v, want only CameraNode", got)
	}
	if got := names("cas.*"); len(got) != 1 || got[0] != "StoreNode" {
		t.Errorf("cap=cas.* returned %v, want only StoreNode", got)
	}
	// Comma still means OR, as the category directories rely on.
	if got := names("cas.put,writing"); len(got) != 2 {
		t.Errorf("cap=cas.put,writing returned %v, want two", got)
	}
	// Nothing matches means nothing — never a fallback to prose search.
	if got := names("nobody.serves.this"); len(got) != 0 {
		t.Errorf("an unserved capability returned %v", got)
	}
	// A LIKE wildcard inside the id must not widen the query.
	if got := names("cas.%"); len(got) != 0 {
		t.Errorf("cap=cas.%% must be literal, returned %v", got)
	}
}

// An upgraded hub already holds agents whose capabilities were only ever a
// JSON blob. A directory that silently forgets its contents on upgrade is
// worse than one that never had an index.
func TestCapabilitiesAreIndexedForAgentsRegisteredBeforeTheIndex(t *testing.T) {
	dir := t.TempDir()
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	s, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutAgent(c.AID(), "Old", []string{"cas.put"}, 5, kel); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// The pre-index state: the agent row exists, the index does not. Done
	// with raw SQL rather than a production method that exists only for a
	// test — the point is what an old database looks like, and an old
	// database has no such method either.
	raw, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DROP TABLE agent_cap`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	reopened, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.FindByCapability("cas.put")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "Old" {
		t.Errorf("an agent registered before the index is invisible to it: %v", got)
	}
}

// Re-registering replaces the capability set. A node that dropped a
// capability has stopped offering it, and a directory that kept answering
// yes would send work to a provider that will refuse it.
func TestDroppingACapabilityRemovesItFromTheIndex(t *testing.T) {
	srv := newHub(t)
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, c, "Node", []string{"cas.put", "cas.get"})
	register(t, srv, c, "Node", []string{"cas.get"})

	resp, err := http.Get(srv.URL + "/agents?cap=cas.put")
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
	if len(out.Agents) != 0 {
		t.Errorf("a withdrawn capability still answers: %v", out.Agents)
	}
}

// A registration says what an agent offers, and nothing made that
// attributable to the agent saying it.
//
// The register challenge signs an action, an AID and a timestamp. It
// proves who is calling and covers none of what they said, so this hub
// could change an agent's name or capability list and no party could tell
// — including the agent. Tolerable for a hub someone chose to trust;
// untenable the moment a directory is federated, where the property being
// relied on is that a peer can hide a card and never invent one.
func TestASignedCardMakesTheRegistrationAttributable(t *testing.T) {
	srv := newHub(t)
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, c, "Honest", []string{"cas.put"})

	resp, err := http.Get(srv.URL + "/agents/" + c.AID() + "/card")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("card endpoint = %d, want 200", resp.StatusCode)
	}
	var card adp.AgentCard
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		t.Fatal(err)
	}
	if card.SubjectDID != c.AID() {
		t.Errorf("card subject = %s, want %s", card.SubjectDID, c.AID())
	}
	// The claims are inside the signature, which is the whole point.
	if len(card.Capabilities) != 1 || card.Capabilities[0] != "cas.put" {
		t.Errorf("capabilities not in the card: %v", card.Capabilities)
	}
	if _, err := adp.AdmitCard(&card, time.Now(), 0, c.KEL(),
		map[uint16]bool{1: true}, nil); err != nil {
		t.Errorf("the published card does not verify against the agent's own KEL: %v", err)
	}
}

// A card may only speak for the agent registering it. Otherwise any
// registrant could publish claims in someone else's name — the exact
// forgery a card exists to prevent.
func TestACardForSomebodyElseIsRefused(t *testing.T) {
	srv := newHub(t)
	mallory, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	victim, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	card := &adp.AgentCard{
		SubjectDID: victim.AID(), CardSchema: adp.CardSchema{Major: 1},
		Seq: uint64(time.Now().Unix()), IssuedAt: time.Now().Unix(),
		NotBefore:    time.Now().Add(-time.Minute).Unix(),
		Capabilities: []string{"anything.at.all"}, CriticalExtensions: []string{},
	}
	if err := card.Sign(mallory); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	code, body := registerWithCard(t, srv, mallory, "Mallory", []string{"x"}, raw)
	if code == http.StatusOK {
		t.Fatalf("a card naming somebody else was accepted: %s", body)
	}
	if !strings.Contains(string(body), "not the registrant") {
		t.Errorf("refused for the wrong reason: %s", body)
	}
}

// A node running an older build sends no card and must still register.
// Refusing it would make upgrading this hub look like an outage to
// everyone who had not upgraded.
func TestRegistrationWithoutACardStillWorks(t *testing.T) {
	srv := newHub(t)
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	registerLegacy(t, srv, c, "Legacy", []string{"cas.get"})
	resp, err := http.Get(srv.URL + "/agents/" + c.AID() + "/card")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("no card should be 404, got %d", resp.StatusCode)
	}
	// …and the agent is registered regardless.
	if _, err := http.Get(srv.URL + "/agents/" + c.AID() + "/kel"); err != nil {
		t.Fatal(err)
	}
}

// A peer hub can hide a card. It must not be able to invent one, and
// these are the three ways it would try.
func TestAPeerCannotForgeADirectoryEntry(t *testing.T) {
	dir := t.TempDir()
	s, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	kelOf := func(c *identity.Controller) string {
		b, err := identity.MarshalKEL(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(b)
	}

	// Honest: signed by its subject, with that subject's key history.
	good := aghub.FedCard{
		Card: mintCard(t, agent, "Remote", []string{"cas.put"}),
		KEL:  kelOf(agent), Home: "https://hub-a.example",
	}
	if err := s.AdmitFedCard("did:anet:peer", good); err != nil {
		t.Fatalf("an honest federated card must be admitted: %v", err)
	}

	// Someone else's key history bolted onto a real card. Without binding
	// the KEL to the subject, a peer could pair any card with any keys and
	// both halves would "verify".
	swapped := good
	swapped.KEL = kelOf(mallory)
	if err := s.AdmitFedCard("did:anet:peer", swapped); err == nil {
		t.Error("a card paired with somebody else's key history was admitted")
	}

	// A card the peer signed itself, claiming to be the agent.
	forged := aghub.FedCard{
		Card: mintCard(t, mallory, "Remote", []string{"anything"}),
		KEL:  kelOf(mallory), Home: "https://hub-a.example",
	}
	// It verifies — mallory really did sign it — and it speaks only for
	// mallory, which is the whole protection: a signature cannot be
	// stretched over a name it does not own.
	if err := s.AdmitFedCard("did:anet:peer", forged); err != nil {
		t.Fatalf("mallory's own card should store under mallory: %v", err)
	}
	fed, err := s.FederatedAgents("cas.put")
	if err != nil {
		t.Fatal(err)
	}
	if len(fed) != 1 || fed[0].AID != agent.AID() {
		t.Errorf("cas.put answered with %v, want only the real agent", fed)
	}
}

// A peer must not be able to claim one of our own agents. Letting it
// would redirect that agent's work to the peer, by asserting it is home.
func TestAPeerCannotClaimAnAgentRegisteredHere(t *testing.T) {
	srv := newHub(t)
	local, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, local, "Ours", []string{"cas.put"})

	s, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Rebuild the same situation in a store we can reach directly.
	kelB, _ := identity.MarshalKEL(local.KEL())
	if err := s.PutAgent(local.AID(), "Ours", []string{"cas.put"}, 5, kelB); err != nil {
		t.Fatal(err)
	}
	err = s.AdmitFedCard("did:anet:peer", aghub.FedCard{
		Card: mintCard(t, local, "Stolen", []string{"cas.put"}),
		KEL:  base64.StdEncoding.EncodeToString(kelB), Home: "https://peer.example",
	})
	if err == nil {
		t.Fatal("a peer claimed an agent registered here")
	}
	if !strings.Contains(err.Error(), "registered here") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// The facilitator settles credit, once, for the payer who signed it.
func TestCreditSettlement(t *testing.T) {
	srv := newHub(t)
	payer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	payee, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", []string{"cas.put"})

	hubAID := hubAIDOf(t, srv)
	// Registering already granted each of them something, so the sums
	// below start from the grant rather than from zero.
	grant := int64(aghub.RegistrationGrant)
	fundAgent(t, srv, payer.AID(), 500)

	auth := signedAuth(t, payer, payee.AID(), 120, hubAID, "ix-1")
	payload := creditPayload(t, auth, payee.AID(), payment.CreditNetwork(hubAID))

	// Verify first: it must not move anything.
	var vr payment.VerifyResponse
	postJSON(t, srv.URL+"/x402/verify", map[string]any{
		"x402Version": payment.Version, "paymentPayload": payload}, &vr)
	if !vr.IsValid {
		t.Fatalf("a funded, signed authorization must verify: %s", vr.InvalidReason)
	}
	if got := balanceOf(t, srv, payer.AID()); got != grant+500 {
		t.Errorf("verify moved credit: balance is %d, want %d", got, grant+500)
	}

	var sr payment.SettlementResponse
	postJSON(t, srv.URL+"/x402/settle", map[string]any{
		"x402Version": payment.Version, "paymentPayload": payload}, &sr)
	if !sr.Success {
		t.Fatalf("settle failed: %s", sr.ErrorReason)
	}
	if balanceOf(t, srv, payer.AID()) != grant+380 || balanceOf(t, srv, payee.AID()) != grant+120 {
		t.Errorf("balances after settle: payer=%d payee=%d, want %d/%d",
			balanceOf(t, srv, payer.AID()), balanceOf(t, srv, payee.AID()), grant+380, grant+120)
	}

	// Settling again must not charge again. A lost reply is the ordinary
	// case, and the retry has to be indistinguishable from the call that
	// worked.
	var again payment.SettlementResponse
	postJSON(t, srv.URL+"/x402/settle", map[string]any{
		"x402Version": payment.Version, "paymentPayload": payload}, &again)
	if !again.Success {
		t.Errorf("a retried settle must succeed, got %s", again.ErrorReason)
	}
	if balanceOf(t, srv, payer.AID()) != grant+380 {
		t.Errorf("the authorization was spent twice: balance %d", balanceOf(t, srv, payer.AID()))
	}
	if again.Transaction != sr.Transaction {
		t.Errorf("a retry reported a different transaction: %s vs %s", again.Transaction, sr.Transaction)
	}
}

func TestPaymentRefusals(t *testing.T) {
	srv := newHub(t)
	payer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	payee, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	hubAID := hubAIDOf(t, srv)

	settle := func(p *payment.PaymentPayload) payment.SettlementResponse {
		var sr payment.SettlementResponse
		postJSON(t, srv.URL+"/x402/settle", map[string]any{
			"x402Version": payment.Version, "paymentPayload": p}, &sr)
		return sr
	}

	// More than the registration grant, and nothing else funded.
	over := uint64(aghub.RegistrationGrant + 1)
	broke := settle(creditPayload(t, signedAuth(t, payer, payee.AID(), over, hubAID, "ix-a"), payee.AID(), payment.CreditNetwork(hubAID)))
	if broke.Success || !strings.Contains(broke.ErrorReason, "insufficient") {
		t.Errorf("an unfunded payment settled: %+v", broke)
	}

	// Another hub's ledger. Settling it here would mint money.
	fundAgent(t, srv, payer.AID(), 500)
	foreign := signedAuth(t, payer, payee.AID(), 50, "did:anet:another-hub", "ix-b")
	fr := settle(creditPayload(t, foreign, payee.AID(), payment.CreditNetwork("did:anet:another-hub")))
	if fr.Success {
		t.Error("this hub settled another hub's credit")
	}

	// An unregistered payer has no key history here, so nothing can say
	// they authorised it.
	stranger, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	sr := settle(creditPayload(t, signedAuth(t, stranger, payee.AID(), 10, hubAID, "ix-c"), payee.AID(), payment.CreditNetwork(hubAID)))
	if sr.Success || !strings.Contains(sr.ErrorReason, "not registered") {
		t.Errorf("a stranger's payment settled: %+v", sr)
	}
}

// /supported is how a client learns what this facilitator will settle.
func TestFacilitatorAdvertisesItsRail(t *testing.T) {
	srv := newHub(t)
	resp, err := http.Get(srv.URL + "/x402/supported")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sup payment.Supported
	if err := json.NewDecoder(resp.Body).Decode(&sup); err != nil {
		t.Fatal(err)
	}
	if len(sup.Kinds) != 1 || sup.Kinds[0].Scheme != payment.SchemeCredit {
		t.Fatalf("supported = %+v", sup.Kinds)
	}
	if sup.Kinds[0].Network != payment.CreditNetwork(hubAIDOf(t, srv)) {
		t.Errorf("network = %s, want this hub's own ledger", sup.Kinds[0].Network)
	}
}

func hubAIDOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	v, ok := testHubAID.Load(srv.URL)
	if !ok {
		t.Fatal("no hub identity for this server")
	}
	return v.(string)
}

func signedAuth(t *testing.T, payer *identity.Controller, payTo string, amount uint64,
	hubAID, ix string) *payment.Authorization {
	t.Helper()
	now := time.Now().UnixMilli()
	a := &payment.Authorization{
		PayTo: payTo, Amount: amount, Network: payment.CreditNetwork(hubAID),
		Nonce: ix + "-nonce", IssuedAt: now - 1000, NotAfter: now + 60_000, InteractionID: ix,
	}
	if err := a.Sign(payer); err != nil {
		t.Fatal(err)
	}
	return a
}

func creditPayload(t *testing.T, a *payment.Authorization, payTo, network string) *payment.PaymentPayload {
	t.Helper()
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &payment.PaymentPayload{
		X402Version: payment.Version,
		Accepted: payment.PaymentOption{
			Scheme: payment.SchemeCredit, Network: network,
			Amount: payment.Amount(a.Amount), Asset: payment.AssetCredit, PayTo: payTo,
		},
		Payload: map[string]any{"authorization": base64.StdEncoding.EncodeToString(b)},
	}
}

func balanceOf(t *testing.T, srv *httptest.Server, aid string) int64 {
	t.Helper()
	resp, err := http.Get(srv.URL + "/agents/" + aid + "/balance")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b aghub.Balance
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return b.Credits
}

func postJSON(t *testing.T, url string, body any, out any) {
	t.Helper()
	code, b := post(t, url, body)
	if code != 200 {
		t.Fatalf("POST %s: %d %s", url, code, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("decode %s: %v (%s)", url, err, b)
	}
}

// A new node can try a paid capability before anyone has funded it. A
// network where nothing works until an operator notices you is a network
// nobody evaluates.
func TestRegistrationGrantsCreditOnce(t *testing.T) {
	srv := newHub(t)
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, c, "Newcomer", []string{"x"})
	if got := balanceOf(t, srv, c.AID()); got != aghub.RegistrationGrant {
		t.Fatalf("a new agent has %d credits, want %d", got, aghub.RegistrationGrant)
	}
	// Re-registering is the same agent, not a faucet.
	register(t, srv, c, "Newcomer", []string{"x", "y"})
	register(t, srv, c, "Newcomer", []string{"z"})
	if got := balanceOf(t, srv, c.AID()); got != aghub.RegistrationGrant {
		t.Errorf("re-registration paid out again: %d", got)
	}
}

// A balance must be explainable by its owner, not merely asserted by the
// hub keeping it.
func TestABalanceCanBeExplained(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, c, "Auditor", nil)
	if err := store.GrantCredit(c.AID(), 250, "topped up"); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(srv.URL + "/agents/" + c.AID() + "/ledger")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Entries []aghub.LedgerEntry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 2 {
		t.Fatalf("ledger has %d entries, want the grant and the top-up", len(out.Entries))
	}
	var total int64
	for _, e := range out.Entries {
		total += e.Delta
		if e.Reason == "" {
			t.Error("a movement with no reason explains nothing")
		}
	}
	if total != balanceOf(t, srv, c.AID()) {
		t.Errorf("the entries sum to %d but the balance is %d", total, balanceOf(t, srv, c.AID()))
	}
}

// A grant is the operator's doing and must be a positive amount: a
// negative "grant" is a confiscation wearing the wrong name.
func TestAGrantMustBePositive(t *testing.T) {
	_, store := newHubWithStore(t)
	for _, n := range []int64{0, -1, -1000} {
		if err := store.GrantCredit("did:anet:x", n, "test"); err == nil {
			t.Errorf("granting %d was allowed", n)
		}
	}
}

// One hub credits its own payee against another hub's signed settlement,
// and records what that hub now owes it. The trust introduced is real and
// bounded: we can show exactly what the peer told us.
func TestClearingAgainstAPeerHub(t *testing.T) {
	_, store := newHubWithStore(t)
	peer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	rec := &payment.Receipt{
		AuthID: "bafyauth-1", Payer: "did:anet:their-user", PayTo: "did:anet:our-provider",
		Amount: 300, Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli(),
	}
	if err := rec.Sign(peer); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearFromPeer(peer.AID(), peer.KEL(), rec); err != nil {
		t.Fatalf("clearing a genuine peer settlement: %v", err)
	}
	if got, _ := store.Balance("did:anet:our-provider"); got != 300 {
		t.Errorf("payee credited %d, want 300", got)
	}
	owed, _ := store.Owed(peer.AID())
	if owed != 300 {
		t.Errorf("peer owes %d, want 300 — a claim on another hub, tracked as one", owed)
	}

	// The same receipt again must not credit twice.
	if err := store.ClearFromPeer(peer.AID(), peer.KEL(), rec); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Balance("did:anet:our-provider"); got != 300 {
		t.Errorf("a repeated receipt credited again: %d", got)
	}

	// A receipt signed by somebody who is not the ledger's hub is refused
	// — otherwise any peer could issue itself credit here.
	impostor, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	forged := &payment.Receipt{
		AuthID: "bafyauth-2", Payer: "did:anet:x", PayTo: "did:anet:our-provider",
		Amount: 99999, Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli(),
	}
	if err := forged.Sign(impostor); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearFromPeer(peer.AID(), peer.KEL(), forged); err == nil {
		t.Error("a receipt signed by an impostor cleared")
	}
	if got, _ := store.Balance("did:anet:our-provider"); got != 300 {
		t.Errorf("the impostor moved credit: %d", got)
	}
}

// hubKELOf is the hub's own key history, for checking what it signed.
func hubKELOf(t *testing.T, url string) []identity.SignedEvent {
	t.Helper()
	v, ok := testHubCtrl.Load(url)
	if !ok {
		t.Fatal("no hub identity for " + url)
	}
	return v.(*identity.Controller).KEL()
}

// twoAgents mints a provider and a requester.
func twoAgents(t *testing.T) (*identity.Controller, *identity.Controller) {
	t.Helper()
	prov, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	req, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	return prov, req
}

// setVisibility opts an agent into (or out of) federation, signed as the
// agent, because that is a decision only the agent makes.
func setVisibility(t *testing.T, srv *httptest.Server, c *identity.Controller, v string) {
	t.Helper()
	ts := uint64(time.Now().UnixMilli())
	sig, seq := c.Sign(relayauth.Preimage(relayauth.ActionProfile, c.AID(), ts))
	code, b := post(t, srv.URL+"/agents/"+c.AID()+"/visibility", map[string]any{
		"visibility": v, "ts": ts, "key_state_seq": seq,
		"sig": base64.StdEncoding.EncodeToString(sig),
	})
	if code != 200 {
		t.Fatalf("visibility: %d %s", code, b)
	}
}

// uploadInterlockedReview posts one real, verified review.
func uploadInterlockedReview(t *testing.T, srv *httptest.Server, prov, req *identity.Controller,
	rating int, comment string) {
	t.Helper()
	body := makeEvidence(t, prov, req, "ix-"+comment+"-"+prov.AID()[:8], rating, "")
	if code, b := post(t, srv.URL+"/reviews", body); code != 200 {
		t.Fatalf("upload review: %d %s", code, b)
	}
}
