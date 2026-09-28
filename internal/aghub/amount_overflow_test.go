package aghub_test

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// An authorization amount is a uint64 on the wire and an int64 on the
// ledger. Every amount above math.MaxInt64 used to be converted with a
// bare int64(...), which made it negative: the balance check passed (any
// balance is >= a negative number), the payer's row went UP and the
// payee's went DOWN. Any registered agent could therefore sign an
// authorization naming a victim as payee and drain the victim through
// /x402/settle, mint credit for itself through /x402/redeem, and a peer
// receipt or discharge could do the same across hubs (red team si9; the
// main-line hotfix is ANetHub hotfix/settle-amount-overflow).
//
// These tests pin the refusal: every entry that takes an amount from
// outside refuses one the ledger cannot hold, with invalid_amount, and
// leaves every money table exactly as it was. Each amount gets a fresh
// hub, so one case's damage cannot mask or cause another's.

// unholdableAmounts are the amounts no int64 ledger can book: the edge
// of the sign bit, the top of the range (-1 as an int64), and the value
// that becomes -1000 — a payment of "-1000" moving 1000 credits the wrong
// way. Zero is refused too: it moves nothing and would still consume a
// settlement record.
var unholdableAmounts = []uint64{1 << 63, math.MaxUint64, math.MaxUint64 - 999, 0}

// overflowAmounts are the three that used to turn negative.
var overflowAmounts = unholdableAmounts[:3]

// victimFunds is what the victim holds on top of its registration grant.
const victimFunds = 5000

// moneyTables is every table a payment, redemption or clearing writes.
var moneyTables = []string{
	"credit_balance", "credit_entry", "credit_settled", "credit_cleared",
	"credit_redemption", "credit_issuance", "hub_owed", "hub_due", "hub_cleared",
}

// moneyState dumps every row of every money table, so "nothing moved"
// is checked against the database rather than against the few balances a
// test thought to look at. credit_issuance is the signed issuance chain,
// so an unchanged dump also means no new chain record.
func moneyState(t *testing.T, dir string) string {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(15000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var b strings.Builder
	for _, table := range moneyTables {
		rows, err := db.Query(`SELECT * FROM ` + table + ` ORDER BY rowid`)
		if err != nil {
			t.Fatalf("reading %s: %v", table, err)
		}
		cols, _ := rows.Columns()
		n := 0
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatalf("scanning %s: %v", table, err)
			}
			fmt.Fprintf(&b, "%s %v\n", table, vals)
			n++
		}
		rows.Close()
		fmt.Fprintf(&b, "%s rows=%d\n", table, n)
	}
	return b.String()
}

// execHubDB runs one statement on a test hub's database, the way an
// operator (or a hub from before a fix) could have written a row.
func execHubDB(t *testing.T, dir, stmt string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(15000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(stmt, args...); err != nil {
		t.Fatal(err)
	}
}

type overflowWorld struct {
	srv              *httptest.Server
	dir              string
	store            *aghub.Store
	hubAID           string
	attacker, victim *identity.Controller
}

// newOverflowWorld is a hub with a victim holding real credit and an
// attacker holding only the registration grant.
func newOverflowWorld(t *testing.T) overflowWorld {
	t.Helper()
	srv, dir := newHubWithDir(t)
	v, ok := testHubStores.Load(srv.URL)
	if !ok {
		t.Fatal("no store for this hub")
	}
	w := overflowWorld{srv: srv, dir: dir, store: v.(*aghub.Store), hubAID: hubAIDOf(t, srv)}
	w.attacker, w.victim = twoAgents(t)
	register(t, srv, w.attacker, "Attacker", nil)
	register(t, srv, w.victim, "Victim", []string{"work.do"})
	fundAgent(t, srv, w.victim.AID(), victimFunds)
	return w
}

// eachAmount runs body once per amount, each on a fresh hub.
func eachAmount(t *testing.T, amounts []uint64, body func(t *testing.T, w overflowWorld, amt uint64)) {
	t.Helper()
	for _, amt := range amounts {
		t.Run(fmt.Sprint(amt), func(t *testing.T) {
			body(t, newOverflowWorld(t), amt)
		})
	}
}

// untouched checks nothing moved: the two balances spelled out so a
// failure says who gained and who lost, then the full table dump.
func (w overflowWorld) untouched(t *testing.T, before string) {
	t.Helper()
	if got, want := balanceOf(t, w.srv, w.attacker.AID()), int64(aghub.RegistrationGrant); got != want {
		t.Errorf("attacker balance = %d, want %d", got, want)
	}
	if got, want := balanceOf(t, w.srv, w.victim.AID()), int64(aghub.RegistrationGrant+victimFunds); got != want {
		t.Errorf("victim balance = %d, want %d", got, want)
	}
	if after := moneyState(t, w.dir); after != before {
		t.Errorf("the money tables changed.\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// refusedAsAmount reports an error string led by invalid_amount (a
// Refusal's Error() is its reason, then the detail).
func refusedAsAmount(reason string) bool {
	return reason == payment.ReasonInvalidAmount || strings.HasPrefix(reason, payment.ReasonInvalidAmount+":")
}

// The red team's PoC (si9, 5df6220), kept with its own inputs: the
// attacker signs 2^64-5000 to the victim and posts it to the open
// /x402/settle with requirements of its own writing. It moved 5000 from
// the victim to the attacker; it must move nothing.
func TestRedteamSI9SettleOfANegativeAmountDoesNotDrainTheVictim(t *testing.T) {
	w := newOverflowWorld(t)
	own := payment.CreditNetwork(w.hubAID)
	amount := ^uint64(0) - 5000 + 1 // int64(amount) == -5000
	before := moneyState(t, w.dir)
	a := signedAuth(t, w.attacker, w.victim.AID(), amount, w.hubAID, "")
	for _, reqAmount := range []uint64{0, 1} {
		code, sr := settleCall(t, w.srv, creditPayload(t, a, w.victim.AID(), own),
			requirementsFor(w.victim.AID(), reqAmount, own))
		if code != http.StatusOK || sr.Success {
			t.Errorf("requirements %d: settled: %d %+v", reqAmount, code, sr)
		}
		if sr.ErrorReason != payment.ReasonInvalidAmount {
			t.Errorf("requirements %d: errorReason = %q, want %s", reqAmount, sr.ErrorReason, payment.ReasonInvalidAmount)
		}
	}
	w.untouched(t, before)
}

// The PoC's second half: the hub as payee (a redemption) minted
// 1,000,000 credits for the redeemer.
func TestRedteamSI9RedemptionOfANegativeAmountMintsNothing(t *testing.T) {
	w := newOverflowWorld(t)
	own := payment.CreditNetwork(w.hubAID)
	amount := ^uint64(0) - 1_000_000 + 1
	before := moneyState(t, w.dir)
	a := signedAuth(t, w.attacker, w.hubAID, amount, w.hubAID, "redeem:x")
	code, b := post(t, w.srv.URL+"/x402/redeem", map[string]any{
		"x402Version": payment.Version, "paymentPayload": creditPayload(t, a, w.hubAID, own), "reference": "x"})
	if code == http.StatusOK {
		t.Errorf("redeemed: %d %s", code, b)
	}
	var out struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &out)
	if !refusedAsAmount(out.Error) {
		t.Errorf("error = %q, want %s", out.Error, payment.ReasonInvalidAmount)
	}
	w.untouched(t, before)
}

func TestAnUnholdableAmountDoesNotVerify(t *testing.T) {
	eachAmount(t, unholdableAmounts, func(t *testing.T, w overflowWorld, amt uint64) {
		before := moneyState(t, w.dir)
		own := payment.CreditNetwork(w.hubAID)
		auth := signedAuth(t, w.attacker, w.victim.AID(), amt, w.hubAID, "ov-verify")
		_, vr := verifyCall(t, w.srv, creditPayload(t, auth, w.victim.AID(), own),
			requirementsFor(w.victim.AID(), 1, own))
		if vr.IsValid {
			t.Errorf("amount %d verified as payable", amt)
		}
		if vr.InvalidReason != payment.ReasonInvalidAmount {
			t.Errorf("invalidReason = %q, want %s", vr.InvalidReason, payment.ReasonInvalidAmount)
		}
		w.untouched(t, before)
	})
}

// The attack itself: the attacker signs, the victim is the payee.
func TestAnUnholdableAmountCannotBeSettled(t *testing.T) {
	for _, payee := range []string{"local", "foreign"} {
		t.Run(payee, func(t *testing.T) {
			eachAmount(t, unholdableAmounts, func(t *testing.T, w overflowWorld, amt uint64) {
				payTo := w.victim.AID()
				if payee == "foreign" {
					// A payee that banks elsewhere takes the hub_due branch.
					payTo = "did:anet:banks-elsewhere"
				}
				own := payment.CreditNetwork(w.hubAID)
				before := moneyState(t, w.dir)
				auth := signedAuth(t, w.attacker, payTo, amt, w.hubAID, "ov-settle")
				_, sr := settleCall(t, w.srv, creditPayload(t, auth, payTo, own), requirementsFor(payTo, 1, own))
				if sr.Success {
					t.Errorf("amount %d settled", amt)
				}
				if sr.ErrorReason != payment.ReasonInvalidAmount {
					t.Errorf("errorReason = %q, want %s", sr.ErrorReason, payment.ReasonInvalidAmount)
				}
				if _, ok := sr.Extensions[payment.ExtReceipt]; ok {
					t.Error("a refused settlement carried a signed receipt")
				}
				w.untouched(t, before)
			})
		})
	}
}

// A requirement the ledger could not hold is not a requirement: 0 is met
// by anything, and above MaxInt64 nothing in range meets it.
func TestAnUnholdableRequiredAmountIsRefused(t *testing.T) {
	eachAmount(t, unholdableAmounts, func(t *testing.T, w overflowWorld, want uint64) {
		own := payment.CreditNetwork(w.hubAID)
		before := moneyState(t, w.dir)
		auth := signedAuth(t, w.attacker, w.victim.AID(), 50, w.hubAID, "ov-req")
		p := creditPayload(t, auth, w.victim.AID(), own)
		req := requirementsFor(w.victim.AID(), want, own)
		if _, sr := settleCall(t, w.srv, p, req); sr.Success || sr.ErrorReason != payment.ReasonInvalidRequirements {
			t.Errorf("settle against required %d = %+v, want %s", want, sr, payment.ReasonInvalidRequirements)
		}
		if _, vr := verifyCall(t, w.srv, p, req); vr.IsValid || vr.InvalidReason != payment.ReasonInvalidRequirements {
			t.Errorf("verify against required %d = %+v, want %s", want, vr, payment.ReasonInvalidRequirements)
		}
		w.untouched(t, before)
	})
}

// Redemption is a payment to the hub; an overflowing one minted credit
// for the redeemer and recorded a negative redemption.
func TestAnUnholdableAmountCannotBeRedeemed(t *testing.T) {
	eachAmount(t, unholdableAmounts, func(t *testing.T, w overflowWorld, amt uint64) {
		before := moneyState(t, w.dir)
		opt := payment.PaymentOption{
			Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(w.hubAID),
			Amount: payment.Amount(amt), Asset: payment.AssetCredit, PayTo: w.hubAID,
		}
		code, body := post(t, w.srv.URL+"/x402/redeem", map[string]any{
			"x402Version":    payment.Version,
			"paymentPayload": json.RawMessage(mustPayload(t, w.attacker, opt, "ov-redeem")),
			"reference":      "ov-redeem",
		})
		if code == http.StatusOK {
			t.Errorf("amount %d redeemed: %s", amt, body)
		}
		var out struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &out)
		if !refusedAsAmount(out.Error) {
			t.Errorf("error = %q, want %s", out.Error, payment.ReasonInvalidAmount)
		}
		w.untouched(t, before)
		if n, sum, err := w.store.RedemptionTotals(w.attacker.AID()); err != nil || n != 0 || sum != 0 {
			t.Errorf("redemptions recorded: n=%d sum=%d err=%v", n, sum, err)
		}
	})
}

// The gateway settles whatever authorization rides in the header, so it
// is another door onto the same settlement.
func TestTheGatewayCannotSettleAnUnholdableAmount(t *testing.T) {
	eachAmount(t, overflowAmounts, func(t *testing.T, w overflowWorld, amt uint64) {
		seller, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		if code, b := registerWithCard(t, w.srv, seller, "Worker", []string{"work.do"},
			sellableCard(t, seller, "Worker", []string{"work.do"},
				map[string]any{"work.do": 120}, "https://worker.example/x402/redeem")); code != 200 {
			t.Fatalf("register seller: %d %s", code, b)
		}
		before := moneyState(t, w.dir)
		// Terms that meet the quote in every way the gateway compares:
		// the seller as payee, an amount "at least" the price. Booked as
		// a negative number, it took the amount from the seller and
		// credited the buyer, and the buyer still got the voucher.
		auth := signedAuth(t, w.attacker, seller.AID(), amt, w.hubAID, "ov-gw")
		raw, err := auth.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		pp, err := json.Marshal(payment.PaymentPayload{
			X402Version: payment.Version,
			Accepted: payment.PaymentOption{
				Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(w.hubAID),
				Amount: payment.Amount(amt), Asset: payment.AssetCredit, PayTo: seller.AID(),
				MaxTimeoutSeconds: 300,
			},
			Payload: map[string]any{"authorization": base64.StdEncoding.EncodeToString(raw)},
		})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet,
			w.srv.URL+"/x402/resource/"+seller.AID()+"/work.do", nil)
		req.Header.Set(payment.HeaderPaymentSignature, base64.StdEncoding.EncodeToString(pp))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || body["voucher"] != nil {
			t.Errorf("amount %d bought a voucher (status %d)", amt, resp.StatusCode)
		}
		w.untouched(t, before)
	})
}

// A card cannot publish a price the ledger could not settle: the hub
// would be quoting, and signing vouchers for, an amount that only exists
// as a wrapped-around negative.
func TestTheGatewayDoesNotQuoteAnUnholdablePrice(t *testing.T) {
	srv := newHub(t)
	for _, price := range []any{payment.Amount(1 << 63), payment.Amount(math.MaxUint64),
		payment.Amount(math.MaxUint64 - 999), "0", float64(1 << 63), float64(1 << 64), 1e30} {
		seller, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		if code, b := registerWithCard(t, srv, seller, "Greedy", []string{"work.do"},
			sellableCard(t, seller, "Greedy", []string{"work.do"},
				map[string]any{"work.do": price}, "https://greedy.example/x402/redeem")); code != 200 {
			t.Fatalf("register: %d %s", code, b)
		}
		resp, err := http.Get(srv.URL + "/x402/resource/" + seller.AID() + "/work.do")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusPaymentRequired {
			t.Errorf("the gateway quoted a price of %v", price)
		}
	}
}

// Cross-hub, payer's side: a payment on a peer's ledger is forwarded to
// the peer, and the peer's receipt is cleared here. The peer settler
// below plays an UNPATCHED peer — it settles whatever it is sent and
// signs a receipt for it — so this pins that this hub refuses before
// forwarding and does not depend on the peer to get it right.
func TestAnUnholdableAmountIsNotForwardedToAPeer(t *testing.T) {
	eachAmount(t, unholdableAmounts, func(t *testing.T, w overflowWorld, amt uint64) {
		peer, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		foreignPayer, err := identity.Incept() // banks on the peer, never registered here
		if err != nil {
			t.Fatal(err)
		}
		var forwarded atomic.Int32
		w.store.SetPeerSettler(func(network string, p *payment.PaymentPayload, req *payment.PaymentRequirements,
			auth *payment.Authorization) (payment.SettlementResponse, bool) {
			forwarded.Add(1)
			id, _ := auth.ID()
			rec := &payment.Receipt{AuthID: id, Payer: auth.Payer, PayTo: auth.PayTo,
				Amount: auth.Amount, Network: network, SettleAt: time.Now().UnixMilli()}
			if err := rec.Sign(peer); err != nil {
				return payment.SettlementResponse{Success: false, ErrorReason: payment.ReasonSettlementFailed}, true
			}
			raw, _ := rec.Marshal()
			out := payment.SettlementResponse{Success: true, Payer: auth.Payer, Transaction: id,
				Network: network, Amount: payment.Amount(auth.Amount),
				Extensions: map[string]any{payment.ExtReceipt: base64.StdEncoding.EncodeToString(raw)}}
			return w.store.ClearPeerSettlement(peer.AID(),
				func(string) ([]identity.SignedEvent, error) { return peer.KEL(), nil }, out, auth, req), true
		})
		before := moneyState(t, w.dir)
		net := payment.CreditNetwork(peer.AID())
		auth := signedAuth(t, foreignPayer, w.victim.AID(), amt, peer.AID(), "ov-fwd")
		_, sr := settleCall(t, w.srv, creditPayload(t, auth, w.victim.AID(), net),
			requirementsFor(w.victim.AID(), 1, net))
		if sr.Success {
			t.Errorf("amount %d settled across hubs", amt)
		}
		if sr.ErrorReason != payment.ReasonInvalidAmount {
			t.Errorf("errorReason = %q, want %s", sr.ErrorReason, payment.ReasonInvalidAmount)
		}
		if n := forwarded.Load(); n != 0 {
			t.Errorf("forwarded to the peer %d time(s); want it refused here", n)
		}
		w.untouched(t, before)
		if owed, _ := w.store.Owed(peer.AID()); owed != 0 {
			t.Errorf("owed by peer = %d, want 0", owed)
		}
	})
}

// Cross-hub, entry hub's second half: an in-range authorization was
// forwarded, and the ledger hub's receipt states an amount this ledger
// cannot hold. It is not cleared against the local payee.
func TestAPeerReceiptForAnUnholdableAmountIsNotClearedForAForwardedPayment(t *testing.T) {
	eachAmount(t, overflowAmounts, func(t *testing.T, w overflowWorld, amt uint64) {
		peer, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		foreignPayer, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		net := payment.CreditNetwork(peer.AID())
		auth := signedAuth(t, foreignPayer, w.victim.AID(), 50, peer.AID(), "ov-lie")
		id, err := auth.ID()
		if err != nil {
			t.Fatal(err)
		}
		rec := &payment.Receipt{AuthID: id, Payer: auth.Payer, PayTo: w.victim.AID(), Amount: amt,
			Network: net, SettleAt: time.Now().UnixMilli()}
		if err := rec.Sign(peer); err != nil {
			t.Fatal(err)
		}
		raw, _ := rec.Marshal()
		before := moneyState(t, w.dir)
		out := w.store.ClearPeerSettlement(peer.AID(),
			func(string) ([]identity.SignedEvent, error) { return peer.KEL(), nil },
			payment.SettlementResponse{Success: true, Transaction: id, Network: net,
				Extensions: map[string]any{payment.ExtReceipt: base64.StdEncoding.EncodeToString(raw)}},
			auth, requirementsFor(w.victim.AID(), 50, net))
		if out.Success || out.ErrorReason != payment.ReasonInvalidAmount {
			t.Errorf("a peer receipt for %d cleared: %+v", amt, out)
		}
		w.untouched(t, before)
		if owed, _ := w.store.Owed(peer.AID()); owed != 0 {
			t.Errorf("owed by peer = %d, want 0", owed)
		}
	})
}

// Cross-hub, payee's side: a peer-signed receipt for an amount that
// turns negative debited the local payee and the peer's debt to us.
func TestAPeerReceiptForAnUnholdableAmountIsNotCleared(t *testing.T) {
	eachAmount(t, unholdableAmounts, func(t *testing.T, w overflowWorld, amt uint64) {
		peer, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		before := moneyState(t, w.dir)
		rec := &payment.Receipt{
			AuthID: "bafy-ov-clear", Payer: "did:anet:their-user",
			PayTo: w.victim.AID(), Amount: amt, Network: payment.CreditNetwork(peer.AID()),
			SettleAt: time.Now().UnixMilli(),
		}
		if err := rec.Sign(peer); err != nil {
			t.Fatal(err)
		}
		err = w.store.ClearFromPeer(peer.AID(), peer.KEL(), rec)
		if err == nil {
			t.Errorf("a peer receipt for %d cleared", amt)
		} else if !refusedAsAmount(err.Error()) {
			t.Errorf("error = %q, want %s", err, payment.ReasonInvalidAmount)
		}
		w.untouched(t, before)
		if owed, _ := w.store.Owed(peer.AID()); owed != 0 {
			t.Errorf("owed by peer = %d, want 0", owed)
		}
	})
}

// Cross-hub discharge: "I owe you 250 and hereby pay 2^64-1000" passed
// the owed check (a negative is never more than owed) and RAISED the
// debt by 1000.
func TestAPeerDischargeForAnUnholdableAmountIsRefused(t *testing.T) {
	eachAmount(t, unholdableAmounts, func(t *testing.T, w overflowWorld, amt uint64) {
		peer, err := identity.Incept()
		if err != nil {
			t.Fatal(err)
		}
		legit := &payment.Receipt{
			AuthID: "bafy-ov-legit", Payer: "did:anet:their-user", PayTo: w.victim.AID(),
			Amount: 250, Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli(),
		}
		if err := legit.Sign(peer); err != nil {
			t.Fatal(err)
		}
		if err := w.store.ClearFromPeer(peer.AID(), peer.KEL(), legit); err != nil {
			t.Fatal(err)
		}
		if owed, _ := w.store.Owed(peer.AID()); owed != 250 {
			t.Fatalf("owed = %d, want 250", owed)
		}
		before := moneyState(t, w.dir)
		rec := &payment.Receipt{
			AuthID: "clear:ov", Payer: peer.AID(), PayTo: w.hubAID, Amount: amt,
			Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli(),
		}
		if err := rec.Sign(peer); err != nil {
			t.Fatal(err)
		}
		err = w.store.SettleOwed(w.hubAID, peer.AID(), peer.KEL(), rec)
		if err == nil {
			t.Errorf("a discharge of %d was applied", amt)
		} else if !refusedAsAmount(err.Error()) {
			t.Errorf("error = %q, want %s", err, payment.ReasonInvalidAmount)
		}
		if after := moneyState(t, w.dir); after != before {
			t.Errorf("the money tables changed.\nbefore:\n%s\nafter:\n%s", before, after)
		}
		if owed, _ := w.store.Owed(peer.AID()); owed != 250 {
			t.Errorf("owed = %d, want 250", owed)
		}
	})
}

// The operator's side of a discharge. `anet-hub -clear -amount -1000`
// reached IssueOwedSettlement as uint64(-1000), and DischargeDue took the
// int64 straight: a negative discharge raised what was due. (The flag
// itself is tested in cmd/anet-hub.)
func TestAnOperatorCannotDischargeAnUnholdableAmount(t *testing.T) {
	w := newOverflowWorld(t)
	peer, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	for _, amt := range unholdableAmounts {
		if _, err := w.store.IssueOwedSettlement(w.hubAID, peer.AID(), amt, "ov"); err == nil {
			t.Errorf("signed a discharge statement for %d", amt)
		}
	}
	// A real obligation, so there is a due row to aim at.
	const payee = "did:anet:banks-elsewhere"
	own := payment.CreditNetwork(w.hubAID)
	auth := signedAuth(t, w.attacker, payee, 50, w.hubAID, "ov-due")
	if _, sr := settleCall(t, w.srv, creditPayload(t, auth, payee, own), requirementsFor(payee, 50, own)); !sr.Success {
		t.Fatalf("settling 50 to a foreign payee: %+v", sr)
	}
	before := moneyState(t, w.dir)
	for _, n := range []int64{0, -1, -1000, math.MinInt64} {
		if err := w.store.DischargeDue(payee, n); err == nil {
			t.Errorf("discharged %d", n)
		}
	}
	if after := moneyState(t, w.dir); after != before {
		t.Errorf("a refused discharge changed the money tables.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if due, _ := w.store.Due(); due[payee] != 50 {
		t.Errorf("due = %d, want 50", due[payee])
	}
}

// The reverse conversion. A settlement row from before the range check
// holds the overflowed amount as a negative number; presenting the same
// authorization again used to answer it as a success stating
// uint64(-1000) = 2^64-1000, with a receipt re-signed for that amount.
// A row like that is not answered as a settlement, and nothing is signed.
func TestALegacyNegativeSettlementRowIsNotRepeatedAsASuccess(t *testing.T) {
	w := newOverflowWorld(t)
	own := payment.CreditNetwork(w.hubAID)
	auth := signedAuth(t, w.attacker, w.victim.AID(), 50, w.hubAID, "ov-legacy")
	p := creditPayload(t, auth, w.victim.AID(), own)
	req := requirementsFor(w.victim.AID(), 50, own)
	if _, sr := settleCall(t, w.srv, p, req); !sr.Success {
		t.Fatalf("settle: %+v", sr)
	}
	id, err := auth.ID()
	if err != nil {
		t.Fatal(err)
	}
	// What a hub without the check stored for 2^64-1000, with no stored
	// receipt (rows from before receipts were kept are re-signed).
	execHubDB(t, w.dir, `UPDATE credit_settled SET amount = -1000, receipt = NULL WHERE auth_id = ?`, id)
	_, sr := settleCall(t, w.srv, p, req)
	if sr.Success {
		t.Errorf("a stored -1000 was answered as a settlement of %s", sr.Amount)
	}
	if _, ok := sr.Extensions[payment.ExtReceipt]; ok {
		t.Errorf("a receipt was signed for the stored -1000: %+v", sr)
	}
	if sr.Amount == payment.Amount(math.MaxUint64-999) {
		t.Errorf("the answer states the overflowed amount %s", sr.Amount)
	}
}

// And a redemption row like it is listed as what it is, not as a
// withdrawal of 2^64-1000.
func TestALegacyNegativeRedemptionRowIsNotListedAsAnAmount(t *testing.T) {
	w := newOverflowWorld(t)
	execHubDB(t, w.dir, `INSERT INTO credit_redemption(auth_id, aid, amount, reference, at) VALUES(?,?,?,?,?)`,
		"bafy-legacy", w.attacker.AID(), -1000, "legacy", time.Now().UTC().Format(time.RFC3339Nano))
	list, err := w.store.Redemptions(w.attacker.AID(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("listed %d redemptions, want 1", len(list))
	}
	if list[0].Amount != 0 || list[0].StoredAmount != -1000 {
		t.Errorf("legacy row listed as amount %d (stored %d), want 0 and stored -1000",
			list[0].Amount, list[0].StoredAmount)
	}
	if _, sum, err := w.store.RedemptionTotals(w.attacker.AID()); err != nil || sum != 0 {
		t.Errorf("sum = %d (%v), want 0", sum, err)
	}
}
