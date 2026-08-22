package aghub_test

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	_ "modernc.org/sqlite"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

func newHub(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(aghub.NewServer(store).Handler())
	t.Cleanup(func() { srv.Close(); store.Close() })
	return srv
}

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

func register(t *testing.T, srv *httptest.Server, c *identity.Controller, name string, caps []string) {
	t.Helper()
	kelB, _ := identity.MarshalKEL(c.KEL())
	ts := uint64(time.Now().UnixMilli())
	sig, seq := c.Sign(relayauth.Preimage(relayauth.ActionRegister, c.AID(), ts))
	code, b := post(t, srv.URL+"/register", map[string]any{
		"aid": c.AID(), "name": name, "caps": caps,
		"kel": base64.StdEncoding.EncodeToString(kelB),
		"ts":  ts, "key_state_seq": seq, "sig": base64.StdEncoding.EncodeToString(sig),
	})
	if code != 200 {
		t.Fatalf("register %s: %d %s", name, code, b)
	}
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
