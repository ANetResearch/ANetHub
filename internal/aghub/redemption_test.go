package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// Credit that only goes in is a score. This is the way out.
func TestRedeemingTakesCreditOutOfCirculation(t *testing.T) {
	srv := newHub(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	fundAgent(t, srv, agent.AID(), 400)
	hubAID := hubAIDOf(t, srv)

	start := supplyOf(t, srv)
	if start.Outstanding != start.Balances {
		t.Fatalf("the ledger does not balance before anything happened: %+v", start)
	}

	opt := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: "300", Asset: payment.AssetCredit, PayTo: hubAID,
	}
	code, body := post(t, srv.URL+"/x402/redeem", map[string]any{
		"x402Version":    payment.Version,
		"paymentPayload": json.RawMessage(mustPayload(t, agent, opt, "redeem:inv-77")),
		"reference":      "inv-77",
	})
	if code != 200 {
		t.Fatalf("redeem = %d %s", code, body)
	}
	var out aghub.Redemption
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Amount != 300 || out.Reference != "inv-77" {
		t.Errorf("redemption = %+v", out)
	}

	// The balance actually fell.
	if got := balanceOf(t, srv, agent.AID()); got != int64(400+aghub.RegistrationGrant-300) {
		t.Errorf("balance = %d", got)
	}

	// And the hub's outstanding liability fell with it, which is the
	// point: a redemption that left the supply unchanged would be the hub
	// taking the credit and still owing it.
	end := supplyOf(t, srv)
	if end.Outstanding != start.Outstanding-300 {
		t.Errorf("outstanding = %d, want %d", end.Outstanding, start.Outstanding-300)
	}
	if end.Outstanding != end.Balances {
		t.Errorf("the ledger no longer balances: outstanding=%d balances=%d",
			end.Outstanding, end.Balances)
	}
	if end.Redeemed != 300 {
		t.Errorf("redeemed = %d, want 300", end.Redeemed)
	}

	// The agent walks away with the hub's signature over what was taken.
	// Without it a withdrawal is the one operation that gives money away
	// and leaves nothing to point at.
	if out.Receipt == "" {
		t.Fatal("the hub took the credit and signed nothing")
	}
	raw, err := base64.StdEncoding.DecodeString(out.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := payment.UnmarshalReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Verify(hubKELOf(t, srv.URL), hubAID, time.Now().UnixMilli()); err != nil {
		t.Errorf("the redemption receipt does not verify: %v", err)
	}
	if rec.Payer != agent.AID() || rec.PayTo != hubAID || rec.Amount != 300 {
		t.Errorf("receipt = %+v", rec)
	}

	// It is listed where the agent can find it later.
	resp, err := http.Get(srv.URL + "/agents/" + agent.AID() + "/redemptions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var listed struct {
		Redemptions []aghub.Redemption `json:"redemptions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Redemptions) != 1 || listed.Redemptions[0].Reference != "inv-77" {
		t.Errorf("redemptions = %+v", listed.Redemptions)
	}
}

// A hub must not be able to redeem an agent's balance for it.
func TestOnlyTheAgentCanRedeemItsOwnCredit(t *testing.T) {
	srv := newHub(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	thief, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	register(t, srv, thief, "Thief", nil)
	fundAgent(t, srv, agent.AID(), 400)
	hubAID := hubAIDOf(t, srv)

	// The thief signs a redemption. It is a real signature over real
	// terms — and it debits the thief, because the payer is whoever
	// signed. There is no field in which to name somebody else.
	opt := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: "300", Asset: payment.AssetCredit, PayTo: hubAID,
	}
	code, _ := post(t, srv.URL+"/x402/redeem", map[string]any{
		"x402Version":    payment.Version,
		"paymentPayload": json.RawMessage(mustPayload(t, thief, opt, "redeem:theft")),
		"reference":      "theft",
	})
	if got := balanceOf(t, srv, agent.AID()); got != int64(400+aghub.RegistrationGrant) {
		t.Errorf("somebody else's redemption moved this agent's credit: %d (code %d)", got, code)
	}
}

// Redeeming more than you hold must fail, and must fail as a payment.
func TestRedeemingMoreThanYouHoldIsRefused(t *testing.T) {
	srv := newHub(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)
	hubAID := hubAIDOf(t, srv)
	before := supplyOf(t, srv)

	opt := payment.PaymentOption{
		Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: "99999", Asset: payment.AssetCredit, PayTo: hubAID,
	}
	code, body := post(t, srv.URL+"/x402/redeem", map[string]any{
		"x402Version":    payment.Version,
		"paymentPayload": json.RawMessage(mustPayload(t, agent, opt, "redeem:greedy")),
		"reference":      "greedy",
	})
	if code == 200 {
		t.Fatalf("an over-redemption succeeded: %s", body)
	}
	if !strings.Contains(string(body), payment.ReasonInsufficientFunds) {
		t.Errorf("the agent is not told why: %s", body)
	}
	if after := supplyOf(t, srv); after.Outstanding != before.Outstanding {
		t.Errorf("a refused redemption changed the supply: %d → %d",
			before.Outstanding, after.Outstanding)
	}
}

// What one hub owes another has to be able to come down.
func TestAPeerCanDischargeWhatItOwes(t *testing.T) {
	// Two hubs. A payment made on peer's ledger, cleared at ours, leaves
	// peer owing us — and then peer says it has paid.
	ours, ourStore := newHubWithStore(t)
	peerCtrl, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	payee, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, ours, payee, "Payee", nil)
	ourAID := hubAIDOf(t, ours)

	// The peer settled 250 on its own ledger in favour of our agent.
	foreign := &payment.Receipt{
		AuthID: "foreign-1", Payer: "did:anet:their-user", PayTo: payee.AID(),
		Amount: 250, Network: payment.CreditNetwork(peerCtrl.AID()),
		SettleAt: time.Now().UnixMilli(),
	}
	if err := foreign.Sign(peerCtrl); err != nil {
		t.Fatal(err)
	}
	if err := ourStore.ClearFromPeer(peerCtrl.AID(), peerCtrl.KEL(), foreign); err != nil {
		t.Fatal(err)
	}
	owed, err := ourStore.Owed(peerCtrl.AID())
	if err != nil {
		t.Fatal(err)
	}
	if owed != 250 {
		t.Fatalf("owed = %d, want 250", owed)
	}

	// The peer discharges 250 under its own key.
	discharge := &payment.Receipt{
		AuthID: "clear:1", Payer: peerCtrl.AID(), PayTo: ourAID, Amount: 250,
		Network: payment.CreditNetwork(peerCtrl.AID()), SettleAt: time.Now().UnixMilli(),
	}
	if err := discharge.Sign(peerCtrl); err != nil {
		t.Fatal(err)
	}
	if err := ourStore.SettleOwed(ourAID, peerCtrl.AID(), peerCtrl.KEL(), discharge); err != nil {
		t.Fatalf("clearing: %v", err)
	}
	if owed, _ := ourStore.Owed(peerCtrl.AID()); owed != 0 {
		t.Errorf("owed = %d after clearing, want 0", owed)
	}

	// Replaying the same discharge must not clear a debt twice.
	if err := ourStore.SettleOwed(ourAID, peerCtrl.AID(), peerCtrl.KEL(), discharge); err != nil {
		t.Errorf("a replayed discharge should be a no-op, not an error: %v", err)
	}
	if owed, _ := ourStore.Owed(peerCtrl.AID()); owed != 0 {
		t.Errorf("a replay moved the debt: %d", owed)
	}

	// And a peer cannot discharge more than it owes, nor discharge with
	// somebody else's signature.
	over := &payment.Receipt{
		AuthID: "clear:2", Payer: peerCtrl.AID(), PayTo: ourAID, Amount: 1000,
		Network: payment.CreditNetwork(peerCtrl.AID()), SettleAt: time.Now().UnixMilli(),
	}
	if err := over.Sign(peerCtrl); err != nil {
		t.Fatal(err)
	}
	if err := ourStore.SettleOwed(ourAID, peerCtrl.AID(), peerCtrl.KEL(), over); err == nil {
		t.Error("a peer cleared more than it owed")
	}
	stranger, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	forged := &payment.Receipt{
		AuthID: "clear:3", Payer: peerCtrl.AID(), PayTo: ourAID, Amount: 10,
		Network: payment.CreditNetwork(peerCtrl.AID()), SettleAt: time.Now().UnixMilli(),
	}
	if err := forged.Sign(stranger); err != nil {
		t.Fatal(err)
	}
	if err := ourStore.SettleOwed(ourAID, peerCtrl.AID(), peerCtrl.KEL(), forged); err == nil {
		t.Error("a discharge signed by a stranger was accepted")
	}
}

func supplyOf(t *testing.T, srv *httptest.Server) aghub.Supply {
	t.Helper()
	resp, err := http.Get(srv.URL + "/x402/supply")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Supply aghub.Supply `json:"supply"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Supply
}

// mustPayload builds the JSON PaymentPayload an agent signs.
func mustPayload(t *testing.T, c *identity.Controller, opt payment.PaymentOption, nonce string) []byte {
	t.Helper()
	return []byte(decodeB64(t, signedPayment(t, c, opt, nonce)))
}

func decodeB64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// An operator must be able to fund an account.
//
// GrantCredit described itself as "the operator's way in" and had no call
// site anywhere — so there was no way in, and every account was stuck
// with its registration grant for ever. The fourth seam found this month
// that compiled without being connected.
//
// The arithmetic is the part worth pinning: a grant issues credit, and
// issuing debits the hub's own row. An operator creating credit off the
// books would break the one equation that makes this custody checkable
// at all.
func TestAnOperatorGrantIsIssuedOnTheBooks(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, agent, "Agent", nil)

	before := supplyOf(t, srv)
	if err := store.GrantCredit(agent.AID(), 500, "operator grant"); err != nil {
		t.Fatal(err)
	}
	if bal, _ := store.Balance(agent.AID()); bal != 500+int64(aghub.RegistrationGrant) {
		t.Errorf("balance = %d after a 500 grant", bal)
	}
	after := supplyOf(t, srv)
	if after.Issued != before.Issued+500 {
		t.Errorf("issued = %d, want %d — a grant that does not appear as issued "+
			"is credit created off the books", after.Issued, before.Issued+500)
	}
	if after.Outstanding != after.Balances {
		t.Errorf("the ledger stopped balancing after a grant: %d vs %d",
			after.Outstanding, after.Balances)
	}
	// Zero is refused rather than treated as a no-op: an operator who
	// typed the amount wrong should find out.
	if err := store.GrantCredit(agent.AID(), 0, "typo"); err == nil {
		t.Error("a zero grant was accepted")
	}
}
