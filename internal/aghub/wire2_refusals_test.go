package aghub_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
)

// Refusal paths of the wire-2 endpoints that the positive tests do not
// reach: path-scoped authentication on visibility and p2p, the publisher
// rule for a re-signed or tampered key set, the consumer rule for key sets
// in the card stream, the poll budget and order, the atomic KEL check on
// registration, per-address limits for IPv6 callers and for federated key
// lookups, and the 507 a sender sees when the recipient's hub is full.

// signedPathRequest builds a request to path signed by signer for action,
// optionally claiming another AID in X-ANet-AID.
func signedPathRequest(t *testing.T, srvURL string, hubAID string, signer *identity.Controller,
	action, path string, body []byte, claim string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srvURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ANet-Wire", "2")
	if signer != nil {
		signV2(t, req, signer, action, hubAID, body, signingNow())
	}
	if claim != "" {
		req.Header.Set(relayauth.HeaderAID, claim)
	}
	return req
}

// Visibility decides whether other hubs learn an agent exists, so only the
// agent can change it: an unsigned request, another agent's signature
// (under its own AID or claiming the agent's), and the agent's signature
// for another action are all 401, and the stored visibility is unchanged.
func TestOnlyTheAgentCanChangeItsVisibility(t *testing.T) {
	dir := t.TempDir()
	srv, _, _ := newHubAt(t, dir)
	agent, other := twoAgents(t)
	register(t, srv, agent, "Agent", nil)
	register(t, srv, other, "Other", nil)
	hubAID := hubAIDOf(t, srv)
	path := "/agents/" + agent.AID() + "/visibility"
	body := rawBody(t, map[string]any{"visibility": aghub.VisibilityPublic})
	stored := func() string {
		var v string
		if err := openDB(t, dir).QueryRow(`SELECT visibility FROM agent WHERE aid=?`, agent.AID()).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, tc := range []struct {
		name   string
		signer *identity.Controller
		action string
		claim  string
	}{
		{"unsigned", nil, "", ""},
		{"another agent under its own AID", other, relayauth.ActionVisibility, ""},
		{"another agent claiming the agent", other, relayauth.ActionVisibility, agent.AID()},
		{"the agent, signing another action", agent, relayauth.ActionProfile, ""},
	} {
		req := signedPathRequest(t, srv.URL, hubAID, tc.signer, tc.action, path, body, tc.claim)
		if code, b, _ := send(t, req); code != http.StatusUnauthorized {
			t.Errorf("%s: %d %s, want 401", tc.name, code, b)
		}
	}
	if v := stored(); v != aghub.VisibilityHubLocal {
		t.Fatalf("a refused request changed the visibility to %q", v)
	}
	// The control: the agent itself.
	setVisibility(t, srv, agent, aghub.VisibilityPublic)
	if v := stored(); v != aghub.VisibilityPublic {
		t.Fatalf("the agent's own request did not take effect: %q", v)
	}
}

// A p2p address is a statement about oneself: another registered agent's
// valid signature does not publish an address for the agent in the path.
func TestAnotherAgentCannotPublishAnAgentsP2PAddress(t *testing.T) {
	srv := newHub(t)
	agent, other := twoAgents(t)
	register(t, srv, agent, "Agent", nil)
	register(t, srv, other, "Other", nil)
	hubAID := hubAIDOf(t, srv)
	path := "/agents/" + agent.AID() + "/p2p"
	body := rawBody(t, map[string]any{"addr": "tcp://198.51.100.7:4001"})
	for _, claim := range []string{"", agent.AID()} {
		req := signedPathRequest(t, srv.URL, hubAID, other, relayauth.ActionP2P, path, body, claim)
		if code, b, _ := send(t, req); code != http.StatusUnauthorized {
			t.Errorf("another agent's signature (claim %q): %d %s, want 401", claim, code, b)
		}
	}
	if code, b := getJSON(t, srv.URL+path); code == http.StatusOK {
		t.Fatalf("an address published by another agent is served: %s", b)
	}
	if code, b := publishAddr(t, srv, agent, "tcp://198.51.100.7:4001"); code != 200 {
		t.Fatalf("control: the agent's own address: %d %s", code, b)
	}
}

// signSet signs set as c and returns the SignedEncKeySet encoding.
func signSet(t *testing.T, c *identity.Controller, set *seal.EncKeySet) []byte {
	t.Helper()
	signed, err := seal.SignEncKeySet(set, c.Sign)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// tamperSig returns raw with one byte of its signature changed.
func tamperSig(t *testing.T, raw []byte) []byte {
	t.Helper()
	signed, err := seal.UnmarshalSignedEncKeySet(raw)
	if err != nil {
		t.Fatal(err)
	}
	signed.Sig = append([]byte(nil), signed.Sig...)
	signed.Sig[0] ^= 0x01
	out, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// storedKeys is the key set GET /agents/{aid}/keys serves.
func storedKeys(t *testing.T, srvURL, aid string) []byte {
	t.Helper()
	code, b := getJSON(t, srvURL+"/agents/"+aid+"/keys")
	if code != http.StatusOK {
		t.Fatalf("get keys: %d %s", code, b)
	}
	var view aghub.KeysView
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(view.KeySet)
	return raw
}

// "Same seq and same set bytes" is a no-op only for a set that verifies:
// the same set under a broken signature is refused and does not replace
// the stored signature, while the same set re-signed after a rotation is
// accepted as unchanged and its new signature is what the hub serves from
// then on. The pre-rotation signature is then refused, because a key set
// is verified against the key in force (§3.1 step 2).
func TestTheSameKeySetMustStillVerify(t *testing.T) {
	srv := newHub(t)
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, c, "Agent", nil)
	now := uint64(time.Now().UnixMilli())
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now+seal.KeyLifetimeMS)
	if err != nil {
		t.Fatal(err)
	}
	set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: c.AID(), Seq: 7, Keys: []seal.EncKey{kp.Public}, IssuedAt: now}
	before := signSet(t, c, set)
	if code, b := publishKeys(t, srv, c, before); code != 200 {
		t.Fatalf("first publish: %d %s", code, b)
	}

	broken := tamperSig(t, before)
	if code, b := publishKeys(t, srv, c, broken); code != http.StatusBadRequest {
		t.Errorf("the same set under a broken signature: %d %s, want 400", code, b)
	}
	body := registerBody(t, c, "Agent", nil)
	body["enc_keys"] = base64.StdEncoding.EncodeToString(broken)
	code, b := signedDo(t, srv, c, relayauth.ActionRegister, http.MethodPost, "/register", body)
	var reg aghub.RegisterResponse
	_ = json.Unmarshal(b, &reg)
	if code != 200 || reg.KeysStatus != aghub.KeysStatusInvalid {
		t.Errorf("/register with the same set under a broken signature: %d %s, want keys_status invalid", code, b)
	}
	if got := storedKeys(t, srv.URL, c.AID()); !bytes.Equal(got, before) {
		t.Fatal("a broken signature replaced the stored one")
	}

	// Rotate, register the longer KEL, and re-sign the identical set.
	if err := c.Rotate(uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if code, b := registerWithCard(t, srv, c, "Agent", nil, nil); code != 200 {
		t.Fatalf("register after rotation: %d %s", code, b)
	}
	after := signSet(t, c, set)
	if bytes.Equal(after, before) {
		t.Fatal("setup: the re-signed set has the same signature")
	}
	code, b = publishKeys(t, srv, c, after)
	var out aghub.KeysPublishResponse
	_ = json.Unmarshal(b, &out)
	if code != 200 || out.KeysStatus != aghub.KeysStatusUnchanged {
		t.Fatalf("the same set re-signed after rotation: %d %s, want 200 unchanged", code, b)
	}
	if got := storedKeys(t, srv.URL, c.AID()); !bytes.Equal(got, after) {
		t.Fatal("the hub still serves the pre-rotation signature")
	}
	if code, b := publishKeys(t, srv, c, before); code != http.StatusBadRequest {
		t.Errorf("the pre-rotation signature after the rotation: %d %s, want 400", code, b)
	}
	if got := storedKeys(t, srv.URL, c.AID()); !bytes.Equal(got, after) {
		t.Fatal("the pre-rotation signature replaced the current one")
	}
}

// The consumer rule on a peer's card stream (§3.1): a set with the stored
// seq and different content is a fork and is ignored, and the stored set
// sent again under a broken signature does not replace the stored one.
// Both come from the peer that taught the card, so neither is refused for
// coming from the wrong peer.
func TestAPeerCannotForkOrCorruptAStoredKeySet(t *testing.T) {
	hub := newFedHub(t)
	agent, _ := twoAgents(t)
	federate(t, hub, agent, "Keyed", []string{"work.do"})
	k2, _ := mintKeySet(t, agent, 2)
	if code, body := publishKeys(t, hub.srv, agent, k2); code != 200 {
		t.Fatalf("publish: %d %s", code, body)
	}
	cards, _, err := hub.store.CardsSince(0, 100, testHome)
	if err != nil || len(cards) != 1 {
		t.Fatalf("stream: %v %v", cards, err)
	}
	peer := openPeerStore(t)
	if err := peer.AdmitFedCard(homePeerAID, cards[0]); err != nil {
		t.Fatal(err)
	}
	if ks, _, _ := peer.FedCardKeys(agent.AID()); !bytes.Equal(ks, k2) {
		t.Fatal("setup: the peer did not store the set")
	}
	fork, _ := mintKeySet(t, agent, 2) // same seq, other keys, validly signed
	for name, keys := range map[string][]byte{
		"a fork (same seq, other content)":        fork,
		"the stored set under a broken signature": tamperSig(t, k2),
	} {
		entry := cards[0]
		entry.Keys = base64.StdEncoding.EncodeToString(keys)
		if err := peer.AdmitFedCard(homePeerAID, entry); err != nil {
			t.Fatalf("%s: the card itself was refused: %v", name, err)
		}
		if ks, _, _ := peer.FedCardKeys(agent.AID()); !bytes.Equal(ks, k2) {
			t.Errorf("%s replaced the stored set", name)
		}
	}
}

// One poll returns at most the byte budget, except that the first message
// is always returned so a single large envelope stays deliverable; and it
// returns the oldest messages first.
func TestAPollIsBoundedByTheBudgetAndOldestFirst(t *testing.T) {
	srv := newHub(t)
	l := aghub.DefaultLimits()
	l.PollBudget = 1000
	if err := serverOf(t, srv).SetLimits(l); err != nil {
		t.Fatal(err)
	}
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	var sent [][]byte
	for i, n := range []int{1500, 300, 300, 300} {
		env := testEnvelope(t, recip.AID(), bytes.Repeat([]byte{byte('a' + i)}, n))
		if code, b, _ := relaySend(t, srv, sender, recip.AID(), env); code != 200 {
			t.Fatalf("send %d: %d %s", i, code, b)
		}
		sent = append(sent, env)
	}
	envelopeOf := func(p polled, i int) []byte {
		b, _ := base64.StdEncoding.DecodeString(p.Messages[i].Envelope)
		return b
	}
	p := relayPoll(t, srv, recip)
	if len(p.Messages) != 1 || !bytes.Equal(envelopeOf(p, 0), sent[0]) {
		t.Fatalf("first poll returned %d messages; want only the oldest, which alone exceeds the budget", len(p.Messages))
	}
	relayAck(t, srv, recip, p.Messages[0].ID)
	p = relayPoll(t, srv, recip)
	if len(p.Messages) != 2 {
		t.Fatalf("second poll returned %d messages, want the 2 that fit in 1000 bytes", len(p.Messages))
	}
	if !bytes.Equal(envelopeOf(p, 0), sent[1]) || !bytes.Equal(envelopeOf(p, 1), sent[2]) ||
		p.Messages[0].ID >= p.Messages[1].ID {
		t.Fatal("the second poll is not the next two messages, oldest first")
	}
}

// Leaving removes the stored A2A card and its skill and tag index rows
// with the rest of the agent's routing.
func TestLeavingRemovesTheA2ACard(t *testing.T) {
	dir := t.TempDir()
	srv, _, _ := newHubAt(t, dir)
	c, _ := twoAgents(t)
	body := registerBody(t, c, "Agent", nil)
	body["a2a_card"] = signA2A(t, c, a2aCardFor(c, 1))
	code, b := signedDo(t, srv, c, relayauth.ActionRegister, http.MethodPost, "/register", body)
	if code != 200 {
		t.Fatalf("register: %d %s", code, b)
	}
	count := func(table string) int {
		var n int
		if err := openDB(t, dir).QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE aid=?`, c.AID()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("agent_a2a_card") != 1 || count("agent_skill") != 1 || count("agent_tag") != 2 {
		t.Fatal("setup: the A2A card was not admitted and indexed")
	}
	if code, b := leave(t, srv, c); code != 200 {
		t.Fatalf("leave: %d %s", code, b)
	}
	for _, table := range []string{"agent_a2a_card", "agent_skill", "agent_tag"} {
		if n := count(table); n != 0 {
			t.Errorf("%s keeps %d rows for an agent that left", table, n)
		}
	}
}

// The store re-checks KEL extension in the write transaction, so a
// registration that passed hRegister's early check before a concurrent one
// wrote cannot then replace the KEL with a fork or a shorter copy.
func TestRegisterAgentChecksTheKELInTheWriteTransaction(t *testing.T) {
	store := openPeerStore(t)
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := c.Export()
	forked, _ := identity.Restore(blob)
	initial := c.KEL()
	write := func(events []identity.SignedEvent) error {
		raw, err := identity.MarshalKEL(events)
		if err != nil {
			t.Fatal(err)
		}
		return store.RegisterAgent(c.AID(), "Agent", nil, raw, events)
	}
	if err := write(initial); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if err := c.Rotate(uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if err := write(c.KEL()); err != nil {
		t.Fatalf("an extending KEL: %v", err)
	}
	if err := forked.Rotate(uint64(time.Now().UnixMilli()) + 3); err != nil {
		t.Fatal(err)
	}
	if err := write(forked.KEL()); !errors.Is(err, aghub.ErrKELNotExtended) || !errors.Is(err, identity.ErrKELFork) {
		t.Errorf("a forked KEL: %v, want ErrKELNotExtended wrapping ErrKELFork", err)
	}
	if err := write(initial); !errors.Is(err, aghub.ErrKELNotExtended) || !errors.Is(err, identity.ErrKELRollback) {
		t.Errorf("a shorter KEL: %v, want ErrKELNotExtended wrapping ErrKELRollback", err)
	}
	raw, err := store.AgentKEL(c.AID())
	if err != nil {
		t.Fatal(err)
	}
	want, _ := identity.MarshalKEL(c.KEL())
	if !bytes.Equal(raw, want) {
		t.Fatal("the stored KEL is not the rotated one")
	}
}

// An IPv6 caller is limited per /64: every address in one /64 shares one
// registration bucket, and another /64 has its own.
func TestRegistrationIsRateLimitedPerIPv6Prefix(t *testing.T) {
	srv := newHub(t)
	l := aghub.DefaultLimits()
	l.RegisterPerMinute, l.RegisterBurst = 1, 1
	if err := serverOf(t, srv).SetLimits(l); err != nil {
		t.Fatal(err)
	}
	reg := func(ip string) int {
		c, _ := identity.Incept()
		req := signedRequest(t, srv, c, relayauth.ActionRegister, http.MethodPost, "/register",
			registerBody(t, c, "Fresh", nil))
		req.Header.Set("X-Real-IP", ip)
		code, _, _ := send(t, req)
		return code
	}
	if code := reg("2001:db8:1:2::1"); code != 200 {
		t.Fatalf("first registration from the /64: %d", code)
	}
	if code := reg("2001:db8:1:2:ffff::9"); code != http.StatusTooManyRequests {
		t.Errorf("another address in the same /64: %d, want 429", code)
	}
	if code := reg("2001:db8:1:3::1"); code != 200 {
		t.Errorf("an address in another /64: %d, want 200", code)
	}
}

// The federated half of GET /agents/{aid}/keys sends a signed request to
// every peer for an unauthenticated caller, so it is limited per client
// address; answers from local registrations are not.
func TestFederatedKeyLookupsAreRateLimitedPerClient(t *testing.T) {
	srv := newHub(t)
	l := aghub.DefaultLimits()
	l.KeysLookupPerMinute, l.KeysLookupBurst = 1, 1
	if err := serverOf(t, srv).SetLimits(l); err != nil {
		t.Fatal(err)
	}
	asked := 0
	serverOf(t, srv).SetFederatedKeyLookup(func(_ context.Context, aid string, _ func(ks, kel []byte) error) ([]byte, []byte, string, error) {
		asked++
		return nil, nil, "", fmt.Errorf("every peer: %w", federation.ErrNoKeys)
	})
	local, _ := twoAgents(t)
	register(t, srv, local, "Local", nil)
	k, _ := mintKeySet(t, local, 1)
	if code, b := publishKeys(t, srv, local, k); code != 200 {
		t.Fatalf("publish: %d %s", code, b)
	}
	get := func(aid, ip string) (int, http.Header) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/agents/"+aid+"/keys", nil)
		req.Header.Set("X-Real-IP", ip)
		code, _, hdr := send(t, req)
		return code, hdr
	}
	unknown := func() string { c, _ := identity.Incept(); return c.AID() }
	if code, _ := get(unknown(), "203.0.113.5"); code != http.StatusNotFound {
		t.Fatalf("first federated lookup: %d, want 404 from the peers", code)
	}
	code, hdr := get(unknown(), "203.0.113.5")
	if code != http.StatusTooManyRequests {
		t.Fatalf("second federated lookup from the same address: %d, want 429", code)
	}
	if ra, err := strconv.Atoi(hdr.Get("Retry-After")); err != nil || ra < 1 {
		t.Errorf("Retry-After = %q", hdr.Get("Retry-After"))
	}
	if asked != 1 {
		t.Errorf("the peers were asked %d times, want 1", asked)
	}
	if code, _ := get(local.AID(), "203.0.113.5"); code != http.StatusOK {
		t.Errorf("a local agent's keys from the limited address: %d, want 200", code)
	}
	if code, _ := get(unknown(), "203.0.113.6"); code != http.StatusNotFound {
		t.Errorf("a federated lookup from another address: %d, want 404", code)
	}
}

// A full mailbox at the recipient's hub reaches the sender as 507, the
// same answer a full local mailbox gives, not as a generic 502.
func TestAFullMailboxAtThePeerHubIs507ForTheSender(t *testing.T) {
	a, b := twoFederatedHubs(t, true)
	recip, sender := twoAgents(t)
	register(t, b.srv, recip, "Provider", nil)
	register(t, a.srv, sender, "Requester", nil)
	l := aghub.DefaultLimits()
	l.MailboxMessages = 1
	if err := b.s.SetLimits(l); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := relaySend(t, a.srv, sender, recip.AID(), testEnvelope(t, recip.AID(), []byte("one"))); code != 200 {
		t.Fatalf("first forward: %d %s", code, body)
	}
	if code, body, _ := relaySend(t, a.srv, sender, recip.AID(), testEnvelope(t, recip.AID(), []byte("two"))); code != http.StatusInsufficientStorage {
		t.Fatalf("a forward into a full mailbox: %d %s, want 507", code, body)
	}
}

// The replay cache records a signature only after it verifies. A request
// whose body does not match its signature is refused without spending the
// signature, so the genuine request carrying it is still accepted, and a
// caller without the key cannot fill the cache.
func TestARefusedRequestDoesNotSpendItsSignature(t *testing.T) {
	srv := newHub(t)
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	body := rawBody(t, map[string]any{"to_aid": recip.AID(),
		"envelope": base64.StdEncoding.EncodeToString(testEnvelope(t, recip.AID(), []byte("genuine")))})
	genuine := newRequest(t, srv, http.MethodPost, "/relay/send", body)
	signV2(t, genuine, sender, relayauth.ActionSend, hubAIDOf(t, srv), body, signingNow())

	altered := rawBody(t, map[string]any{"to_aid": recip.AID(),
		"envelope": base64.StdEncoding.EncodeToString(testEnvelope(t, recip.AID(), []byte("altered")))})
	forged := newRequest(t, srv, http.MethodPost, "/relay/send", altered)
	forged.Header = genuine.Header.Clone()
	if code, b, _ := send(t, forged); code != http.StatusUnauthorized {
		t.Fatalf("the signature over another body: %d %s, want 401", code, b)
	}
	if code, b, _ := send(t, genuine); code != http.StatusOK {
		t.Fatalf("the genuine request after a forged use of its signature: %d %s, want 200", code, b)
	}
}
