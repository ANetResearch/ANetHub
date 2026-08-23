package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// An attestation held by a third party is what makes a rewrite provable.
//
// The chain alone is fork-evident only to a reader who already has an
// older copy. A reader seeing it for the first time learns nothing about
// the past, because a hub that has never been observed can present any
// chain. A witness signs what it saw, and the pair — the hub's record and
// the witness's attestation, naming the same position with different
// contents — demonstrates the rewrite without either party agreeing.
func TestAWitnessAttestationDetectsARewrittenIssuanceChain(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	if err := store.GrantCredit(agent.AID(), 500, "operator"); err != nil {
		t.Fatal(err)
	}
	hubAID := hubAIDOf(t, srv)

	// A witness looks and signs.
	head, seq, ok := store.IssuanceHead()
	if !ok {
		t.Fatal("no head to witness")
	}
	witness, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	a := &ael.HeadAttestation{
		ChainDID: hubAID, Seq: seq, HeadID: head, ObservedAt: time.Now().UnixMilli(),
	}
	if err := a.Sign(witness); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreAttestation(a); err != nil {
		t.Fatal(err)
	}

	// The chain as it stands agrees with what the witness saw.
	entries, err := store.IssuanceSince(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	recs := recordsOf(t, entries)
	bad, err := store.CheckAgainstAttestations(hubAID, recs)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 0 {
		t.Fatalf("an unmodified chain contradicted its own attestation: %+v", bad)
	}

	// Now the record at that position is different. This is what a hub
	// rewriting its issuance history would produce.
	for _, r := range recs {
		if r.Seq == seq {
			r.ID = "bafy-rewritten"
		}
	}
	bad, err = store.CheckAgainstAttestations(hubAID, recs)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 1 {
		t.Fatalf("a rewritten chain was not caught: %d contradictions", len(bad))
	}
	if bad[0].WitnessAID != witness.AID() || bad[0].Seq != seq {
		t.Errorf("contradiction reported wrongly: %+v", bad[0])
	}
}

// A hub serves what it has been given, and can be asked for it.
func TestAHubServesTheAttestationsMadeAboutIt(t *testing.T) {
	srv, _ := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil) // produces a head to attest to
	hubAID := hubAIDOf(t, srv)

	// A witness fetches the head the way any witness would.
	resp, err := http.Get(srv.URL + "/x402/issuance/head")
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		ChainDID string `json:"chain_did"`
		Seq      uint64 `json:"seq"`
		HeadID   string `json:"head_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if h.ChainDID != hubAID || h.HeadID == "" {
		t.Fatalf("head = %+v", h)
	}

	witness, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	a := &ael.HeadAttestation{ChainDID: h.ChainDID, Seq: h.Seq, HeadID: h.HeadID,
		ObservedAt: time.Now().UnixMilli()}
	if err := a.Sign(witness); err != nil {
		t.Fatal(err)
	}
	raw, _ := a.Marshal()
	if code, b := post(t, srv.URL+"/x402/witness", map[string]any{
		"attestation": base64.StdEncoding.EncodeToString(raw)}); code != 200 {
		t.Fatalf("submit: %d %s", code, b)
	}

	// Served back, and it verifies against the witness's own key history
	// — the hub cannot forge one, only withhold it.
	resp2, err := http.Get(srv.URL + "/x402/witnesses")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var out struct {
		Attestations []aghub.AttestationView `json:"attestations"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Attestations) != 1 {
		t.Fatalf("served %d attestations", len(out.Attestations))
	}
	got, err := base64.StdEncoding.DecodeString(out.Attestations[0].Attestation)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ael.UnmarshalHeadAttestation(got)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Verify(witness.KEL(), witness.AID(), time.Now().UnixMilli()); err != nil {
		t.Errorf("the served attestation does not verify: %v", err)
	}
}

// An attestation about somebody else must not be filed as being about
// this hub, or a hub could pad its witness list with statements nobody
// made about it.
func TestAHubRefusesAttestationsAboutOtherChains(t *testing.T) {
	srv, _ := newHubWithStore(t)
	witness, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	a := &ael.HeadAttestation{ChainDID: "did:anet:some-other-hub", Seq: 3,
		HeadID: "bafy-x", ObservedAt: time.Now().UnixMilli()}
	if err := a.Sign(witness); err != nil {
		t.Fatal(err)
	}
	raw, _ := a.Marshal()
	code, b := post(t, srv.URL+"/x402/witness", map[string]any{
		"attestation": base64.StdEncoding.EncodeToString(raw)})
	if code == 200 {
		t.Fatalf("accepted an attestation about another chain: %s", b)
	}
}

// A hub must not witness itself: the statement carries no information,
// and a list padded with self-reference reads as corroboration.
func TestAHubCannotWitnessItself(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	head, seq, ok := store.IssuanceHead()
	if !ok {
		t.Fatal("no head")
	}
	if _, err := store.WitnessPeer(hubAIDOf(t, srv), head, seq); err == nil {
		t.Error("a hub signed an attestation about its own chain")
	}
}

func recordsOf(t *testing.T, entries []aghub.IssuanceEntry) []*ael.EventRecord {
	t.Helper()
	var out []*ael.EventRecord
	for _, e := range entries {
		raw, err := base64.StdEncoding.DecodeString(e.Record)
		if err != nil {
			t.Fatal(err)
		}
		var rec ael.EventRecord
		if err := coredet.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, &rec)
	}
	return out
}

// The trust model is "the hub and its witnesses did not all collude",
// which is worth something only if a reader can see how many witnesses
// there are and how recently they looked.
//
// A hub with one witness that last looked months ago is technically
// witnessed and practically not, and nothing distinguished that from a
// hub with several looking hourly.
func TestWitnessHealthMakesTheCoverageVisible(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil) // one issuance record, seq 0
	hubAID := hubAIDOf(t, srv)
	now := time.Now()

	// Nothing has looked.
	h, err := store.WitnessHealthOf(hubAID, now)
	if err != nil {
		t.Fatal(err)
	}
	if h.Witnesses != 0 || h.Attestations != 0 {
		t.Fatalf("health on an unwitnessed chain = %+v", h)
	}
	if h.UnwitnessedRecords != 1 {
		t.Errorf("unwitnessed = %d, want 1 — the whole chain is unpinned", h.UnwitnessedRecords)
	}

	// Two witnesses look at seq 0.
	head, seq, ok := store.IssuanceHead()
	if !ok {
		t.Fatal("no head")
	}
	var wids []string
	for i := 0; i < 2; i++ {
		w, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		wids = append(wids, w.AID())
		a := &ael.HeadAttestation{ChainDID: hubAID, Seq: seq, HeadID: head,
			ObservedAt: now.Add(-10 * time.Minute).UnixMilli()}
		if err := a.Sign(w); err != nil {
			t.Fatal(err)
		}
		if err := store.StoreAttestation(a); err != nil {
			t.Fatal(err)
		}
	}
	h, _ = store.WitnessHealthOf(hubAID, now)
	if h.Witnesses != 2 || h.Attestations != 2 {
		t.Errorf("health = %+v, want 2 witnesses", h)
	}
	if h.UnwitnessedRecords != 0 {
		t.Errorf("unwitnessed = %d after both pinned the head", h.UnwitnessedRecords)
	}
	if h.StaleFor < 500 || h.StaleFor > 700 {
		t.Errorf("stale_seconds = %d, want about 600", h.StaleFor)
	}
	// Who, not only how many. Two AIDs run by one operator count as two
	// here and are worth one; no hub can tell, so a reader has to look.
	if len(h.WitnessAIDs) != 2 {
		t.Errorf("witness_aids = %v", h.WitnessAIDs)
	}

	// The chain moves on. Those records are the ones the hub could still
	// rewrite without contradicting anybody.
	if err := store.GrantCredit(agent.AID(), 100, "later"); err != nil {
		t.Fatal(err)
	}
	if err := store.GrantCredit(agent.AID(), 100, "later still"); err != nil {
		t.Fatal(err)
	}
	h, _ = store.WitnessHealthOf(hubAID, now)
	if h.UnwitnessedRecords != 2 {
		t.Errorf("unwitnessed = %d, want 2 — the chain ran past the last pin",
			h.UnwitnessedRecords)
	}
	_ = wids
}

// The health figure is served with the attestations, and with the caveat
// that makes the number readable.
func TestWitnessHealthIsPublishedWithItsCaveat(t *testing.T) {
	srv, _ := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	resp, err := http.Get(srv.URL + "/x402/witnesses")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Health aghub.WitnessHealth `json:"health"`
		Note   string              `json:"note"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Health.ChainDID == "" {
		t.Error("no health reported")
	}
	// A count of distinct AIDs is not a count of independent parties, and
	// publishing the number without saying so invites it to be read as
	// one.
	if !strings.Contains(out.Note, "one operator") {
		t.Errorf("the caveat is missing: %q", out.Note)
	}
}

// Two witnesses observing the same head are two witnesses.
//
// An attestation's CID covers {chain, seq, head, observed_at} and not the
// signer — the envelope carries that. Storing on the CID alone therefore
// discarded the second of any two parties that looked at the same head at
// the same moment, and a chain watched by six reported one. That number
// is what the whole trust argument rests on.
func TestTwoWitnessesOfTheSameHeadAreBothKept(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	hubAID := hubAIDOf(t, srv)
	head, seq, ok := store.IssuanceHead()
	if !ok {
		t.Fatal("no head")
	}
	// Identical observations: same chain, same head, same instant. Only
	// the signer differs, which is exactly the case that collapsed.
	at := time.Now().UnixMilli()
	var aids []string
	for i := 0; i < 3; i++ {
		w, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		aids = append(aids, w.AID())
		a := &ael.HeadAttestation{ChainDID: hubAID, Seq: seq, HeadID: head, ObservedAt: at}
		if err := a.Sign(w); err != nil {
			t.Fatal(err)
		}
		if err := store.StoreAttestation(a); err != nil {
			t.Fatal(err)
		}
	}
	held, err := store.AttestationsAbout(hubAID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 3 {
		t.Fatalf("held %d attestations, want 3", len(held))
	}
	h, _ := store.WitnessHealthOf(hubAID, time.Now())
	if h.Witnesses != 3 {
		t.Errorf("witnesses = %d, want 3", h.Witnesses)
	}
	seen := map[string]bool{}
	for _, v := range held {
		seen[v.WitnessAID] = true
	}
	for _, a := range aids {
		if !seen[a] {
			t.Errorf("witness %s was discarded", a[:12])
		}
	}

	// The same witness repeating itself is still one attestation.
	w, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		a := &ael.HeadAttestation{ChainDID: hubAID, Seq: seq, HeadID: head, ObservedAt: at}
		if err := a.Sign(w); err != nil {
			t.Fatal(err)
		}
		if err := store.StoreAttestation(a); err != nil {
			t.Fatal(err)
		}
	}
	h, _ = store.WitnessHealthOf(hubAID, time.Now())
	if h.Witnesses != 4 || h.Attestations != 4 {
		t.Errorf("a repeated attestation was counted twice: %+v", h)
	}
}
