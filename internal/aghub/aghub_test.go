package aghub_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/protocol/evidence"
	"github.com/ANetResearch/ANetHub/internal/protocol/relayauth"
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
