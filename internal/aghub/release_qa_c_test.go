package aghub_test

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// The gateway quotes a price and an address that a buyer has no way to
// check for itself: what reaches the buyer is this hub's rendering of the
// provider's card, not the card. So the threat these tests describe is
// not a network attacker but the hub itself — an operator, or anything
// that reached the database — editing the agent_card row it serves from.
//
// A hub cannot forge the provider's signature over an edited card, so the
// property that has to hold is that the gateway re-checks the signature
// on the read path and refuses rather than quoting terms the provider
// never published. Testing that requires a hub whose database file the
// test can open, which is what newHubWithDir exists for.

// newHubWithDir is newHubWithStore with the store directory handed back,
// so a test can edit the hub's own tables the way an operator can.
func newHubWithDir(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	s := aghub.NewServer(store)
	s.SetHubAID(id.AID)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); store.Close() })
	// The same registrations the shared helpers read, so fundAgent and
	// balanceOf work against this hub too.
	testHubAID.Store(srv.URL, id.AID)
	testHubStores.Store(srv.URL, store)
	testHubCtrl.Store(srv.URL, id.Ctrl)
	testHubServers.Store(srv.URL, s)
	return srv, dir
}

// editStoredCard rewrites an agent's stored card in place. The signature
// envelope is left exactly as it was, which is the whole point: this is
// what an edit by a party without the provider's key looks like.
func editStoredCard(t *testing.T, dir, aid string, edit func(card map[string]any)) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(15000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw []byte
	if err := db.QueryRow(`SELECT card FROM agent_card WHERE aid=?`, aid).Scan(&raw); err != nil {
		t.Fatalf("no stored card for %s: %v", aid, err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	edit(obj)
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE agent_card SET card=? WHERE aid=?`, out, aid); err != nil {
		t.Fatal(err)
	}
}

// replaceStoredCard puts an arbitrary card body in an agent's row.
func replaceStoredCard(t *testing.T, dir, aid string, card json.RawMessage) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(15000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE agent_card SET card=? WHERE aid=?`, []byte(card), aid); err != nil {
		t.Fatal(err)
	}
}

// sellerAndBuyer sets up the one arrangement all three tests need: a
// provider selling work.do at 120 credits, redeemable at its own address,
// and a funded buyer.
func sellerAndBuyer(t *testing.T, srv *httptest.Server) (seller, buyer *identity.Controller) {
	t.Helper()
	seller, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	buyer, err = identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	card := sellableCard(t, seller, "Worker", []string{"work.do"},
		map[string]any{"work.do": 120}, "https://worker.example/x402/redeem")
	if code, b := registerWithCard(t, srv, seller, "Worker", []string{"work.do"}, card); code != 200 {
		t.Fatalf("register seller: %d %s", code, b)
	}
	register(t, srv, buyer, "Buyer", nil)
	fundAgent(t, srv, buyer.AID(), 500)
	return seller, buyer
}

// getResource performs one gateway request, with a payment signature if
// one is given, and returns the status, the raw body and the headers.
func getResource(t *testing.T, url, sig string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sig != "" {
		req.Header.Set(payment.HeaderPaymentSignature, sig)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b), resp.Header
}

// A hub that edits the price in its own card table must not be able to
// quote the edited number.
//
// The provider signed 120. If the gateway read the price off the row
// without re-checking the signature, the hub could quote 5000, settle it,
// and the buyer would have no way to tell that it had overpaid by a
// factor of forty for terms the provider never published.
func TestTheGatewayWillNotQuoteAPriceTheProviderDidNotSign(t *testing.T) {
	srv, dir := newHubWithDir(t)
	seller, buyer := sellerAndBuyer(t, srv)
	url := srv.URL + "/x402/resource/" + seller.AID() + "/work.do"

	// Control: the untampered card sells, at the signed price. Without
	// this the test could pass because the gateway never quotes anything.
	code, body, _ := getResource(t, url, "")
	if code != http.StatusPaymentRequired || !strings.Contains(body, `"120"`) {
		t.Fatalf("before tampering the quote must be 402 at 120: %d %s", code, body)
	}

	editStoredCard(t, dir, seller.AID(), func(card map[string]any) {
		ext := card["extensions"].(map[string]any)
		ext[aghub.ExtPricing].(map[string]any)["work.do"] = 5000
	})

	// The quote path. Not 402 at any price: a hub that cannot show the
	// provider signed the number has nothing to quote.
	code, body, hdr := getResource(t, url, "")
	if code != http.StatusInternalServerError {
		t.Errorf("an edited price still quoted: %d %s", code, body)
	}
	if hdr.Get(payment.HeaderPaymentRequired) != "" {
		t.Error("a refused quote must not carry x402 payment terms")
	}
	if strings.Contains(body, "5000") || strings.Contains(body, `"accepts"`) {
		t.Errorf("the edited price reached the buyer: %s", body)
	}
	if !strings.Contains(body, "does not verify") {
		t.Errorf("the refusal does not say why: %s", body)
	}

	// The settlement path. A buyer that signs the edited terms — which is
	// what a buyer following the hub's own quote would do — must not be
	// charged, because the check has to sit ahead of the ledger and not
	// only ahead of the 402. Funded past the edited price on purpose: a
	// buyer too poor to pay it would be refused for lack of credit, and
	// the assertion below would pass without the verification doing
	// anything.
	fundAgent(t, srv, buyer.AID(), 5000)
	before := balanceOf(t, srv, buyer.AID())
	edited := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAIDOf(t, srv)),
		Amount: "5000", Asset: payment.AssetCredit, PayTo: seller.AID(),
	}
	code, body, _ = getResource(t, url, signedPayment(t, buyer, edited, "qa-c-price"))
	if code == http.StatusOK || strings.Contains(body, `"voucher"`) {
		t.Errorf("paying the edited price bought a voucher: %d %s", code, body)
	}
	if got := balanceOf(t, srv, buyer.AID()); got != before {
		t.Errorf("an unverifiable card still moved credit: balance %d, want %d", got, before)
	}
	if got := balanceOf(t, srv, seller.AID()); got != int64(aghub.RegistrationGrant) {
		t.Errorf("seller was paid on an unverifiable card: balance %d", got)
	}
}

// A hub that edits the redeem address must not be able to send the buyer
// to a machine of its own choosing.
//
// This is the same edit as the price one and a different loss: the
// provider is still named as payee and still collects, so the buyer pays
// the right party and then takes its voucher and its request arguments to
// whatever the hub nominated. The gateway exists so that the hub does not
// see the work; an unchecked endpoint field hands it the work anyway.
func TestTheGatewayWillNotSendTheBuyerToAnAddressTheProviderDidNotSign(t *testing.T) {
	srv, dir := newHubWithDir(t)
	seller, buyer := sellerAndBuyer(t, srv)
	url := srv.URL + "/x402/resource/" + seller.AID() + "/work.do"
	const hubsOwnMachine = "https://collector.hub.example/x402/redeem"

	code, body, _ := getResource(t, url, "")
	if code != http.StatusPaymentRequired ||
		!strings.Contains(body, "https://worker.example/x402/redeem") {
		t.Fatalf("before tampering the quote must name the provider's address: %d %s", code, body)
	}

	editStoredCard(t, dir, seller.AID(), func(card map[string]any) {
		eps := card["endpoints"].([]any)
		eps[0].(map[string]any)["uri"] = hubsOwnMachine
	})

	code, body, _ = getResource(t, url, "")
	if code != http.StatusInternalServerError {
		t.Errorf("an edited redeem address still quoted: %d %s", code, body)
	}
	if strings.Contains(body, hubsOwnMachine) {
		t.Errorf("the buyer was pointed at the hub's own machine: %s", body)
	}

	// Paying the price the provider really did sign must not buy a
	// voucher either — the endpoint is half the offer, so it has to be
	// verified before the ledger moves, not only before the quote.
	before := balanceOf(t, srv, buyer.AID())
	honest := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAIDOf(t, srv)),
		Amount: "120", Asset: payment.AssetCredit, PayTo: seller.AID(),
	}
	code, body, _ = getResource(t, url, signedPayment(t, buyer, honest, "qa-c-endpoint"))
	if code == http.StatusOK || strings.Contains(body, `"voucher"`) {
		t.Errorf("the buyer bought a voucher against an edited address: %d %s", code, body)
	}
	if strings.Contains(body, hubsOwnMachine) {
		t.Errorf("the paid response still pointed at the hub's own machine: %s", body)
	}
	if got := balanceOf(t, srv, buyer.AID()); got != before {
		t.Errorf("an unverifiable card still moved credit: balance %d, want %d", got, before)
	}
}

// A signature that verifies is not enough on its own: the card has to be
// about the agent being sold.
//
// ADP allows a delegated publish, where signer_aid and subject_did
// differ, and the baseline delegation check accepts any non-empty proof.
// So a card can carry a signature that verifies under one agent's key
// while describing another agent's prices and address. Filing such a card
// under the signer's AID is an edit a hub can make without holding
// anybody's key, which is why the read path checks the subject itself
// rather than inferring it from the signature having verified.
func TestTheGatewayRefusesACardThatSpeaksForAnotherAgent(t *testing.T) {
	srv, dir := newHubWithDir(t)
	seller, _ := sellerAndBuyer(t, srv)
	other, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	crafted := &adp.AgentCard{
		SubjectDID: other.AID(), CardSchema: adp.CardSchema{Major: 1},
		Seq: uint64(now.UnixNano()), IssuedAt: now.Unix(),
		NotBefore:    now.Add(-time.Minute).Unix(),
		Capabilities: []string{"work.do"}, CriticalExtensions: []string{}, Name: "Elsewhere",
		DelegationProof: json.RawMessage(`{"proof":"unchecked by the baseline verifier"}`),
		Extensions:      map[string]any{aghub.ExtPricing: map[string]any{"work.do": 7}},
		Endpoints: []adp.EndpointDesc{{
			Protocol: aghub.EndpointRedeem, URI: "https://elsewhere.example/x402/redeem",
			Methods: []string{"POST"}}},
	}
	if err := crafted.Sign(seller); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(crafted)
	if err != nil {
		t.Fatal(err)
	}
	replaceStoredCard(t, dir, seller.AID(), raw)

	code, body, _ := getResource(t, srv.URL+"/x402/resource/"+seller.AID()+"/work.do", "")
	if code != http.StatusInternalServerError {
		t.Errorf("a card about another agent was sold as this one's: %d %s", code, body)
	}
	if strings.Contains(body, "https://elsewhere.example/x402/redeem") || strings.Contains(body, `"7"`) {
		t.Errorf("the other agent's terms were quoted: %s", body)
	}
}

// Re-verifying on the read path must not turn into an expiry check.
//
// ADP gives a card a TTL, and adp.AdmitCard reports a card older than it
// as EXPIRED rather than as a rejection. The gateway accepts that
// disposition: age says the provider has not re-registered lately, not
// that somebody else wrote the price, and refusing on it would stop
// selling for every provider whose daemon has been up longer than a week.
// The narrower reading — refuse anything that is not PUBLISHED — is the
// easy mistake to make when adding the check, and it would take those
// providers off the market with no attacker involved.
func TestTheGatewayStillSellsForAProviderWhoseCardHasAgedOut(t *testing.T) {
	srv, dir := newHubWithDir(t)
	seller, _ := sellerAndBuyer(t, srv)

	// The same provider, the same key, a card it signed two weeks ago.
	// Stored directly because the register path admits nothing this old;
	// the state under test is a hub that has been running longer than the
	// card lives, which is the ordinary case rather than an attack.
	old := time.Now().Add(-14 * 24 * time.Hour)
	aged := &adp.AgentCard{
		SubjectDID: seller.AID(), CardSchema: adp.CardSchema{Major: 1},
		Seq: uint64(old.UnixNano()), IssuedAt: old.Unix(), NotBefore: old.Unix(),
		Capabilities: []string{"work.do"}, CriticalExtensions: []string{}, Name: "Worker",
		Extensions: map[string]any{aghub.ExtPricing: map[string]any{"work.do": 120}},
		Endpoints: []adp.EndpointDesc{{
			Protocol: aghub.EndpointRedeem, URI: "https://worker.example/x402/redeem",
			Methods: []string{"POST"}}},
	}
	if err := aged.Sign(seller); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(aged)
	if err != nil {
		t.Fatal(err)
	}
	replaceStoredCard(t, dir, seller.AID(), raw)

	code, body, _ := getResource(t, srv.URL+"/x402/resource/"+seller.AID()+"/work.do", "")
	if code != http.StatusPaymentRequired || !strings.Contains(body, `"120"`) {
		t.Errorf("an aged but properly signed card stopped the sale: %d %s", code, body)
	}
}
