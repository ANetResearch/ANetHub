package aghub_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/liabtree"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// Supply epochs and liability proofs (hub-payment-privacy §2.3, §4.2.1).

// epochRuns counts the epochs each test store has been made to publish.
var epochRuns sync.Map // *aghub.Store -> *atomic.Int64

// publishEpoch closes and publishes the next supply epoch of store, as the
// hub would once one is due: each call publishes at a time eight days after
// the one before (the first eight days from now), so the seven-day rule
// always finds one due. The rest of the hub keeps its own clock.
func publishEpoch(tb testing.TB, store *aghub.Store) aghub.SupplyEpochEntry {
	tb.Helper()
	v, _ := epochRuns.LoadOrStore(store, new(atomic.Int64))
	n := v.(*atomic.Int64).Add(1)
	e, err := store.PublishDueAtForTest(time.Now().Add(time.Duration(n) * 8 * 24 * time.Hour))
	if err != nil {
		tb.Fatalf("publish a supply epoch: %v", err)
	}
	if e == nil {
		tb.Fatal("no supply epoch was due")
	}
	return *e
}

// dayStart is the first millisecond of the UTC day d days after today.
func dayStart(d int) time.Time {
	return time.Now().UTC().Truncate(24 * time.Hour).Add(time.Duration(d) * 24 * time.Hour)
}

func today() uint64 { return uint64(time.Now().UnixMilli() / 86_400_000) }

// recordOf decodes and verifies an epoch's record against the hub's KEL and
// reads what it states.
func recordOf(t *testing.T, raw string, hubKEL []identity.SignedEvent) (*ael.EventRecord, *ael.SupplyEpoch) {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		t.Fatalf("record is not base64url: %v", err)
	}
	rec, err := ael.UnmarshalEventRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Verify(hubKEL); err != nil {
		t.Fatalf("the epoch record does not verify against the hub's KEL: %v", err)
	}
	ep, err := ael.ParseSupplyEpoch(rec)
	if err != nil {
		t.Fatal(err)
	}
	return rec, ep
}

// redeemVia redeems amount of c's credit through the store.
func redeemVia(t *testing.T, store *aghub.Store, hubAID string, c *identity.Controller, amount uint64, ref string) {
	t.Helper()
	opt := payment.PaymentOption{Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: payment.Amount(amount), Asset: payment.AssetCredit, PayTo: hubAID}
	var pp payment.PaymentPayload
	if err := json.Unmarshal(mustPayload(t, c, opt, ref), &pp); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Redeem(hubAID, &pp, ref); err != nil {
		t.Fatalf("redeem %d: %v", amount, err)
	}
}

// payVia settles amount from payer to payTo on the hub's own ledger.
func payVia(t *testing.T, store *aghub.Store, hubAID string, payer *identity.Controller, payTo string, amount uint64, ix string) {
	t.Helper()
	opt := payment.PaymentOption{Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: payment.Amount(amount), Asset: payment.AssetCredit, PayTo: payTo}
	var pp payment.PaymentPayload
	if err := json.Unmarshal(mustPayload(t, payer, opt, ix), &pp); err != nil {
		t.Fatal(err)
	}
	if out := store.SettleWithRequirements(hubAID, &pp, &opt); !out.Success {
		t.Fatalf("pay %d to %s: %s %v", amount, payTo, out.ErrorReason, out.Extensions)
	}
}

// clearVia credits payTo with a peer's signed settlement of amount.
func clearVia(t *testing.T, store *aghub.Store, peer *identity.Controller, payTo string, amount uint64, id string) {
	t.Helper()
	rec := &payment.Receipt{AuthID: id, Payer: "did:anet:their-user", PayTo: payTo, Amount: amount,
		Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli()}
	if err := rec.Sign(peer); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearFromPeer(peer.AID(), peer.KEL(), rec); err != nil {
		t.Fatalf("clear %d from a peer: %v", amount, err)
	}
}

// PAY-S1: every supply event — a grant, a redemption, a peer's settlement
// cleared here, a payment here to an agent on a peer — moves the totals and
// counts once, in the transaction that moves the credit; a payment between
// two accounts here is not a supply event. After every step the agent
// balances add up to issued − redeemed and the hub's row holds the negative
// (P-PAY-3).
func TestEverySupplyEventCountsAndATransferDoesNot(t *testing.T) {
	srv, store := newHubWithStore(t)
	hubAID := hubAIDOf(t, srv)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "Payer", nil) // each funded: one grant
	register(t, srv, payee, "Payee", nil)
	peer, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	type want struct{ issued, redeemed, events int64 }
	check := func(stage string, w want) {
		t.Helper()
		sup := supplyOf(t, srv)
		if sup.Issued != w.issued || sup.Redeemed != w.redeemed || sup.EventsSincePublish != w.events {
			t.Errorf("%s: issued %d redeemed %d events %d, want %d %d %d", stage,
				sup.Issued, sup.Redeemed, sup.EventsSincePublish, w.issued, w.redeemed, w.events)
		}
		if !sup.Consistent() {
			t.Errorf("%s: the supply does not add up: %+v", stage, sup)
		}
	}
	f := int64(testRegistrationFunds)
	check("two registrations", want{2 * f, 0, 2})
	payVia(t, store, hubAID, payer, payee.AID(), 30, "transfer-1")
	check("a transfer", want{2 * f, 0, 2})
	redeemVia(t, store, hubAID, payer, 20, "redeem-1")
	check("a redemption", want{2 * f, 20, 3})
	if err := store.GrantCredit(payee.AID(), 50, "operator"); err != nil {
		t.Fatal(err)
	}
	check("a grant", want{2*f + 50, 20, 4})
	clearVia(t, store, peer, payee.AID(), 7, "peer-auth-1")
	check("a peer's settlement", want{2*f + 57, 20, 5})
	payVia(t, store, hubAID, payer, "did:anet:their-provider", 5, "out-1")
	check("a payment to a peer's agent", want{2*f + 57, 25, 6})
	// A refused payment moves nothing and counts nothing.
	opt := payment.PaymentOption{Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
		Amount: "100000", Asset: payment.AssetCredit, PayTo: payee.AID()}
	var pp payment.PaymentPayload
	if err := json.Unmarshal(mustPayload(t, payer, opt, "too-much"), &pp); err != nil {
		t.Fatal(err)
	}
	if out := store.SettleWithRequirements(hubAID, &pp, &opt); out.Success {
		t.Fatal("a payment above the balance settled")
	}
	check("a refused payment", want{2*f + 57, 25, 6})
	// Nothing per event goes anywhere public: no epoch is published by an
	// event, only by the daily rule.
	if _, _, ok := store.SupplyHead(); ok {
		t.Error("a supply event published an epoch")
	}
}

// A running total that cannot take a supply event refuses the event with
// invalid_amount, in the transaction that moves the credit, so nothing
// moves: not the account, not the hub's row, not the count. Issuance meets
// issuanceRoom first, and what is redeemed never passes what was issued, so
// this is the last bound and not the one a hub normally reaches; it is the
// one Credit, which does not check the room, has.
func TestASupplyTotalThatCannotTakeTheEventRefusesIt(t *testing.T) {
	srv, store := newHubWithStore(t)
	hubAID := hubAIDOf(t, srv)
	a, _ := twoAgents(t)
	register(t, srv, a, "A", nil)
	for _, c := range []struct {
		name, col string
		event     func() error
	}{
		{"issued", "issued", func() error { return store.Credit(a.AID(), 10, "past the bound") }},
		{"redeemed", "redeemed", func() error {
			opt := payment.PaymentOption{Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(hubAID),
				Amount: "10", Asset: payment.AssetCredit, PayTo: hubAID}
			var pp payment.PaymentPayload
			if err := json.Unmarshal(mustPayload(t, a, opt, "past-the-bound"), &pp); err != nil {
				t.Fatal(err)
			}
			_, err := store.Redeem(hubAID, &pp, "past-the-bound")
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := store.DBForTest().Exec(`UPDATE supply_totals SET `+c.col+` = ?`, int64(math.MaxInt64)-5); err != nil {
				t.Fatal(err)
			}
			before := supplyOf(t, srv)
			bal := balanceOf(t, srv, a.AID())
			err := c.event()
			if err == nil || !strings.Contains(err.Error(), payment.ReasonInvalidAmount) {
				t.Fatalf("an event of 10 on a %s total of 2^63-6: %v, want %s", c.col, err, payment.ReasonInvalidAmount)
			}
			if after := supplyOf(t, srv); after.Issued != before.Issued || after.Redeemed != before.Redeemed ||
				after.EventsSincePublish != before.EventsSincePublish || after.HubRow != before.HubRow {
				t.Errorf("the refused event moved the supply: %+v -> %+v", before, after)
			}
			if got := balanceOf(t, srv, a.AID()); got != bal {
				t.Errorf("the refused event moved the balance: %d -> %d", bal, got)
			}
			if _, err := store.DBForTest().Exec(`UPDATE supply_totals SET ` + c.col + ` = 0`); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// PAY-S2: an epoch closes when 20 supply events happened since the last one
// or 7 UTC days passed, covering the days since the last one up to the day
// that just ended; never before a first supply event, never twice for a day,
// and with nothing written when it is not due.
func TestTheEpochRule(t *testing.T) {
	srv, store := newHubWithStore(t)
	agent, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	publishAt := func(at time.Time) *aghub.SupplyEpochEntry {
		t.Helper()
		e, err := store.PublishDueAtForTest(at)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	// Nothing has happened: nothing to publish, however long it has been.
	if e := publishAt(dayStart(30)); e != nil {
		t.Fatalf("a hub with no supply event published %+v", e)
	}
	register(t, srv, agent, "Agent", nil) // the first supply event, today
	d0 := today()
	// One event, under 7 days: not due.
	for _, d := range []int{0, 1, 6} {
		if e := publishAt(dayStart(d).Add(time.Minute)); e != nil {
			t.Fatalf("day +%d: published %+v with one event and %d days", d, e, d)
		}
	}
	// The 7th day after the day before the first event ends: due.
	e := publishAt(dayStart(7).Add(time.Minute))
	if e == nil {
		t.Fatal("seven days after the first event, no epoch")
	}
	if e.FromDay != d0 || e.ToDay != d0+6 || e.Seq != 0 {
		t.Errorf("first epoch covers %d..%d seq %d, want %d..%d seq 0", e.FromDay, e.ToDay, e.Seq, d0, d0+6)
	}
	if sup := supplyOf(t, srv); sup.EventsSincePublish != 0 {
		t.Errorf("after the publication %d events are counted", sup.EventsSincePublish)
	}
	// The same day again: it is covered.
	if again := publishAt(dayStart(7).Add(time.Hour)); again != nil {
		t.Fatalf("published twice for one day: %+v", again)
	}
	// 19 events, one day later: not due; the 20th makes it due.
	for i := 0; i < 19; i++ {
		if err := store.GrantCredit(agent.AID(), 1, "event"); err != nil {
			t.Fatal(err)
		}
	}
	if e := publishAt(dayStart(8).Add(time.Minute)); e != nil {
		t.Fatalf("19 events and one day: published %+v", e)
	}
	if err := store.GrantCredit(agent.AID(), 1, "event"); err != nil {
		t.Fatal(err)
	}
	e2 := publishAt(dayStart(8).Add(time.Minute))
	if e2 == nil {
		t.Fatal("20 events: no epoch")
	}
	if e2.FromDay != d0+7 || e2.ToDay != d0+7 || e2.Seq != 1 || e2.PrevID != e.ID {
		t.Errorf("second epoch %+v, want %d..%d seq 1 after %s", e2, d0+7, d0+7, e.ID)
	}
	// Without events, 7 days on: due again, a period with no change.
	e3 := publishAt(dayStart(15).Add(time.Minute))
	if e3 == nil || e3.FromDay != d0+8 || e3.ToDay != d0+14 || e3.Outstanding != e2.Outstanding {
		t.Errorf("a quiet week: %+v", e3)
	}
}

// supplyBodies are the three public answers about the supply, byte for byte.
func supplyBodies(t *testing.T, srv *httptest.Server) [3]string {
	t.Helper()
	var out [3]string
	for i, p := range []string{"/x402/supply", "/x402/issuance?from=0", "/x402/issuance/head"} {
		code, b := getJSON(t, srv.URL+p)
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", p, code, b)
		}
		out[i] = string(b)
	}
	return out
}

// PAY-S4: /x402/supply, /x402/issuance and /x402/issuance/head say only what
// the published epochs say. Between two publications they are the same bytes
// whatever moves on the ledger, and none of them carries the time.
func TestThePublicSupplyIsTheSameBytesBetweenPublications(t *testing.T) {
	srv, store := newHubWithStore(t)
	hubAID := hubAIDOf(t, srv)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)

	none := supplyBodies(t, srv)
	if !strings.Contains(none[0], `"hub":"`+hubAID+`"`) || strings.Contains(none[0], `"epoch"`) {
		t.Errorf("/x402/supply before any epoch: %s", none[0])
	}
	if none[1] != "{\"entries\":[]}\n" || none[2] != "{}\n" {
		t.Errorf("before any epoch: issuance %q head %q", none[1], none[2])
	}
	if err := store.GrantCredit(payer.AID(), 40, "more"); err != nil {
		t.Fatal(err)
	}
	if got := supplyBodies(t, srv); got != none {
		t.Errorf("a grant changed the public supply before any epoch:\n%v\n%v", none, got)
	}

	e := publishEpoch(t, store)
	first := supplyBodies(t, srv)
	if first == none {
		t.Fatal("publishing changed nothing public")
	}
	var sup aghub.SupplyResponse
	if err := json.Unmarshal([]byte(first[0]), &sup); err != nil {
		t.Fatal(err)
	}
	if sup.Epoch == nil || sup.Epoch.Seq != e.Seq || sup.Epoch.Outstanding != e.Outstanding ||
		sup.Epoch.Root != e.Root || sup.Record != e.Record || sup.Hub != hubAID {
		t.Errorf("/x402/supply = %+v, want the epoch %+v", sup, e)
	}
	// Everything that moves credit, and time passing.
	payVia(t, store, hubAID, payer, payee.AID(), 11, "between-1")
	redeemVia(t, store, hubAID, payee, 3, "between-2")
	if err := store.GrantCredit(payee.AID(), 9, "between"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if got := supplyBodies(t, srv); got != first {
		t.Errorf("the public supply changed without a publication:\n%v\n%v", first, got)
	}
	publishEpoch(t, store)
	if got := supplyBodies(t, srv); got == first {
		t.Error("a second epoch changed nothing public")
	}
}

// What an epoch publishes: its record, signed by the hub, states the six
// members of a supply epoch and nothing else — no AID, no amount of a
// single event, no count (SI-45) — its outstanding is the tree's sum and
// issued − redeemed at the close, and the epochs link into one chain.
func TestAnEpochStatesOnlyTheTotal(t *testing.T) {
	srv, store := newHubWithStore(t)
	hubAID := hubAIDOf(t, srv)
	hubKEL := hubKELOf(t, srv.URL)
	payer, payee := twoAgents(t)
	register(t, srv, payer, "Payer", nil)
	register(t, srv, payee, "Payee", nil)
	payVia(t, store, hubAID, payer, payee.AID(), 37, "the-37-payment")
	redeemVia(t, store, hubAID, payee, 13, "the-13-reference")

	var prev *aghub.SupplyEpochEntry
	for i := 0; i < 3; i++ {
		e := publishEpoch(t, store)
		rec, ep := recordOf(t, e.Record, hubKEL)
		if rec.ChainDID != hubAID || rec.EventType != ael.EvSupplyEpoch || rec.Seq != e.Seq || rec.ID != e.ID {
			t.Errorf("epoch %d record: %+v", i, rec)
		}
		sup := supplyOf(t, srv)
		if ep.Outstanding != uint64(sup.Outstanding) || e.Outstanding != ep.Outstanding ||
			liabtree.Hex(ep.Root) != e.Root || ep.FromDay != e.FromDay || ep.ToDay != e.ToDay {
			t.Errorf("epoch %d states %+v; entry %+v; outstanding now %d", i, ep, e, sup.Outstanding)
		}
		if prev == nil {
			if e.PrevID != ael.GenesisPrev() || e.Seq != 0 {
				t.Errorf("the first epoch: seq %d prev %s", e.Seq, e.PrevID)
			}
		} else if e.PrevID != prev.ID || e.Seq != prev.Seq+1 || e.FromDay != prev.ToDay+1 {
			t.Errorf("epoch %d does not continue %d: %+v after %+v", i, i-1, e, *prev)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(e.Record)
		for _, secret := range []string{payer.AID(), payee.AID(), "the-37-payment", "the-13-reference"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Errorf("epoch %d's record carries %q", i, secret)
			}
		}
		prev = &e
	}
	// The chain as served verifies as one ael chain from seq 0.
	entries, err := store.SupplyEpochs(0, 0)
	if err != nil || len(entries) != 3 {
		t.Fatalf("served %d epochs, %v", len(entries), err)
	}
	ledger := ael.NewLedger()
	for _, r := range recordsOf(t, entries) {
		if err := ledger.Append(r, hubKEL); err != nil {
			t.Fatal(err)
		}
	}
	if id, seq, ok := ledger.Head(hubAID); !ok || seq != 2 || id != entries[2].ID {
		t.Errorf("the chain's head is %s %d %v", id, seq, ok)
	}
	// From a cursor, inclusive, and past the end empty.
	if es, _ := store.SupplyEpochs(1, 0); len(es) != 2 || es[0].Seq != 1 {
		t.Errorf("from 1: %+v", es)
	}
	if es, _ := store.SupplyEpochs(3, 0); len(es) != 0 {
		t.Errorf("past the head: %+v", es)
	}
}

// liabilityProof asks for c's proof, signed by signer, and returns the
// status, the proof and the raw body.
func liabilityProof(t *testing.T, srv *httptest.Server, c, signer *identity.Controller, query string) (int, aghub.LiabilityProof, []byte) {
	t.Helper()
	path := "/agents/" + c.AID() + "/liability-proof" + query
	req := newRequest(t, srv, http.MethodGet, path, nil)
	signV2(t, req, signer, relayauth.ActionLiabProof, hubAIDOf(t, srv), nil, signingNow())
	code, body, _ := send(t, req)
	var p aghub.LiabilityProof
	if code == http.StatusOK {
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
	}
	return code, p, body
}

// PAY-S5: an account's proof reaches the signed root with its balance at the
// close, for the latest epoch or the one it names; aid, to_day, from_day,
// ledger_hw and the record are those of the epoch, and side is the side the
// sibling is on (liabtree.Side).
func TestALiabilityProofReachesTheSignedRoot(t *testing.T) {
	srv, store := newHubWithStore(t)
	hubAID := hubAIDOf(t, srv)
	hubKEL := hubKELOf(t, srv.URL)
	var agents []*identity.Controller
	for i := 0; i < 5; i++ {
		c, err := identitytest.Hub()
		if err != nil {
			t.Fatal(err)
		}
		register(t, srv, c, "Agent", nil)
		agents = append(agents, c)
	}
	payVia(t, store, hubAID, agents[0], agents[1].AID(), 60, "p1")
	if err := store.GrantCredit(agents[2].AID(), 1234, "operator"); err != nil {
		t.Fatal(err)
	}
	e1 := publishEpoch(t, store)
	balances1 := map[string]uint64{}
	for _, c := range agents {
		balances1[c.AID()] = uint64(balanceOf(t, srv, c.AID()))
	}
	var hw uint64
	if err := store.DBForTest().QueryRow(`SELECT MAX(seq) FROM credit_entry`).Scan(&hw); err != nil {
		t.Fatal(err)
	}
	// The ledger moves on and a second epoch closes.
	payVia(t, store, hubAID, agents[2], agents[3].AID(), 500, "p2")
	e2 := publishEpoch(t, store)

	check := func(c *identity.Controller, query string, e aghub.SupplyEpochEntry, balance, ledgerHW uint64) {
		t.Helper()
		code, p, body := liabilityProof(t, srv, c, c, query)
		if code != http.StatusOK {
			t.Fatalf("proof of %s%s: %d %s", c.AID()[:12], query, code, body)
		}
		_, ep := recordOf(t, p.Record, hubKEL)
		proof, err := p.WireProof.Parse()
		if err != nil {
			t.Fatal(err)
		}
		if err := liabtree.Verify(proof, ep.Root, ep.Outstanding, ep.Depth); err != nil {
			t.Errorf("the proof of %s does not verify: %v", c.AID()[:12], err)
		}
		if p.AID != c.AID() || p.ToDay != e.ToDay || p.FromDay != e.FromDay || p.Balance != balance ||
			p.Record != e.Record || ep.ToDay != e.ToDay {
			t.Errorf("proof %+v, want aid %s to_day %d from_day %d balance %d", p, c.AID()[:12], e.ToDay, e.FromDay, balance)
		}
		if ledgerHW != 0 && p.LedgerHW != ledgerHW {
			t.Errorf("ledger_hw = %d, want %d", p.LedgerHW, ledgerHW)
		}
		if len(p.Path) != ep.Depth {
			t.Errorf("the path has %d steps; the tree has depth %d", len(p.Path), ep.Depth)
		}
	}
	for _, c := range agents {
		check(c, "", e2, uint64(balanceOf(t, srv, c.AID())), 0)
		check(c, "?to_day="+strconv.FormatUint(e1.ToDay, 10), e1, balances1[c.AID()], hw)
		check(c, "?to_day="+strconv.FormatUint(e2.ToDay, 10), e2, uint64(balanceOf(t, srv, c.AID())), 0)
	}
	// side is the sibling's side: flipping one breaks the proof.
	_, p, _ := liabilityProof(t, srv, agents[0], agents[0], "")
	proof, _ := p.WireProof.Parse()
	_, ep := recordOf(t, p.Record, hubKEL)
	if proof.Path[0].Side == liabtree.Left {
		proof.Path[0].Side = liabtree.Right
	} else {
		proof.Path[0].Side = liabtree.Left
	}
	if liabtree.Verify(proof, ep.Root, ep.Outstanding, ep.Depth) == nil {
		t.Error("a proof with a flipped side still verifies")
	}
}

// The refusals of /agents/{aid}/liability-proof: only the account holder
// (401 otherwise); 404 proof_unavailable for a period never published, for
// an account that was not on the books at its close, and once the period is
// 14 days old; 400 bad_request for a to_day that is not one day number.
func TestTheLiabilityProofRefusals(t *testing.T) {
	srv, store := newHubWithStore(t)
	a, b := twoAgents(t)
	register(t, srv, a, "A", nil)
	register(t, srv, b, "B", nil)
	expect := func(what string, code int, body []byte, wantCode int, reason string) {
		t.Helper()
		if code != wantCode || !strings.Contains(string(body), `"reason":"`+reason+`"`) {
			t.Errorf("%s: %d %s, want %d %s", what, code, body, wantCode, reason)
		}
	}
	code, _, body := liabilityProof(t, srv, a, a, "")
	expect("before any epoch", code, body, 404, "proof_unavailable")

	e := publishEpoch(t, store)
	if code, _, body := liabilityProof(t, srv, a, a, ""); code != 200 {
		t.Fatalf("a's own proof: %d %s", code, body)
	}
	code, _, body = liabilityProof(t, srv, a, b, "")
	expect("signed by another account", code, body, 401, "unauthorized")
	resp, err := http.Get(srv.URL + "/agents/" + a.AID() + "/liability-proof")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	expect("unsigned", resp.StatusCode, raw, 401, "unauthorized")
	code, _, body = liabilityProof(t, srv, a, a, "?to_day="+strconv.FormatUint(e.ToDay+1, 10))
	expect("a period never published", code, body, 404, "proof_unavailable")
	for _, q := range []string{"?to_day=x", "?to_day=-1", "?to_day=+3", "?to_day=", "?to_day=1&to_day=2",
		"?to_day=18446744073709551616"} {
		code, _, body = liabilityProof(t, srv, a, a, q)
		expect("to_day "+q, code, body, 400, "bad_request")
	}
	// Registered after the close: not on the books of that period.
	late, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, late, "Late", nil)
	code, _, body = liabilityProof(t, srv, late, late, "")
	expect("an account that was not on the books", code, body, 404, "proof_unavailable")

	// 14 days after publication the proof is gone (PAY-S5).
	var raw2 []byte
	if err := store.DBForTest().QueryRow(`SELECT record FROM supply_chain WHERE seq = ?`, e.Seq).Scan(&raw2); err != nil {
		t.Fatal(err)
	}
	rec, err := ael.UnmarshalEventRecord(raw2)
	if err != nil {
		t.Fatal(err)
	}
	published := time.UnixMilli(rec.Timestamp)
	if _, err := store.LiabilityProofAtForTest(a.AID(), nil, published.Add(14*24*time.Hour-time.Millisecond)); err != nil {
		t.Errorf("a proof just inside its 14 days: %v", err)
	}
	if _, err := store.LiabilityProofAtForTest(a.AID(), nil, published.Add(14*24*time.Hour)); !errors.Is(err, aghub.ErrProofUnavailable) {
		t.Errorf("a proof 14 days after publication: %v, want ErrProofUnavailable", err)
	}
	if err := store.PruneLiabilityProofsAtForTest(published.Add(14*24*time.Hour - time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, store, `SELECT COUNT(*) FROM liab_leaf`); n == 0 {
		t.Error("leaves inside their 14 days were deleted")
	}
	if err := store.PruneLiabilityProofsAtForTest(published.Add(14 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`SELECT COUNT(*) FROM liab_leaf`, `SELECT COUNT(*) FROM liab_meta`} {
		if n := countRows(t, store, q); n != 0 {
			t.Errorf("%s = %d after 14 days", q, n)
		}
	}
	if n := countRows(t, store, `SELECT COUNT(*) FROM supply_chain`); n != 1 {
		t.Errorf("the epoch record went with its leaves: %d records", n)
	}
	code, _, body = liabilityProof(t, srv, a, a, "")
	expect("after the leaves were dropped", code, body, 404, "proof_unavailable")
}

// The leaves of every epoch are stored, padding included, so the tree that
// answers a proof is the one the record was signed over; an account
// appears once per epoch.
func TestTheStoredLeavesRebuildTheSignedRoot(t *testing.T) {
	srv, store := newHubWithStore(t)
	for i := 0; i < 3; i++ {
		c, err := identitytest.Hub()
		if err != nil {
			t.Fatal(err)
		}
		register(t, srv, c, "Agent", nil)
	}
	e := publishEpoch(t, store)
	rows, err := store.DBForTest().Query(`SELECT pos, aid, balance, salt FROM liab_leaf WHERE to_day = ? ORDER BY pos`, e.ToDay)
	if err != nil {
		t.Fatal(err)
	}
	var entries []liabtree.Entry
	padding := 0
	for rows.Next() {
		var pos int
		var en liabtree.Entry
		var salt []byte
		if err := rows.Scan(&pos, &en.AID, &en.Balance, &salt); err != nil {
			t.Fatal(err)
		}
		copy(en.Salt[:], salt)
		if en.Padding() {
			padding++
		}
		entries = append(entries, en)
	}
	rows.Close()
	if len(entries) != liabtree.MinLeaves || padding != liabtree.MinLeaves-3 {
		t.Fatalf("%d leaves, %d padding; want %d and %d", len(entries), padding, liabtree.MinLeaves, liabtree.MinLeaves-3)
	}
	tree, err := liabtree.Rebuild(e.ToDay, entries)
	if err != nil {
		t.Fatal(err)
	}
	if liabtree.Hex(tree.Root()) != e.Root || tree.Outstanding() != e.Outstanding || tree.Depth() != e.DepthForTest() {
		t.Errorf("the stored leaves rebuild %s/%d/%d, the epoch states %s/%d/%d",
			liabtree.Hex(tree.Root()), tree.Outstanding(), tree.Depth(), e.Root, e.Outstanding, e.DepthForTest())
	}
	var meta struct{ hw, leaves int64 }
	if err := store.DBForTest().QueryRow(`SELECT ledger_hw, leaves FROM liab_meta WHERE to_day = ?`, e.ToDay).
		Scan(&meta.hw, &meta.leaves); err != nil || meta.leaves != int64(len(entries)) || meta.hw == 0 {
		t.Errorf("liab_meta = %+v, %v", meta, err)
	}
}

// ledger_hw is where the ledger stood at the close: the largest
// credit_entry.seq written by then. Entries are deleted once they leave the
// 14-day ledger window, so an epoch that closes after a quiet fortnight
// finds none; it still states the same mark, never 0 or one below the
// previous epoch's, which is what a node's balance continuity counts from
// (hub-payment-privacy PAY-S9).
func TestTheLedgerHighWaterMarkOutlivesTheEntries(t *testing.T) {
	srv, store := newHubWithStore(t)
	a, _ := twoAgents(t)
	register(t, srv, a, "A", nil)
	hw := func(e aghub.SupplyEpochEntry) uint64 {
		t.Helper()
		toDay := e.ToDay
		p, err := store.LiabilityProofAtForTest(a.AID(), &toDay, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return p.LedgerHW
	}
	first := hw(publishEpoch(t, store))
	if first == 0 {
		t.Fatal("setup: the ledger had no entries at the first close")
	}
	// A quiet fortnight: the window deletes every entry.
	if _, err := store.DBForTest().Exec(`DELETE FROM credit_entry`); err != nil {
		t.Fatal(err)
	}
	if second := hw(publishEpoch(t, store)); second != first {
		t.Errorf("after the entries were deleted the epoch states ledger_hw %d, the one before %d", second, first)
	}
	// The next entry is numbered after the mark, and the next close states it.
	if err := store.GrantCredit(a.AID(), 3, "operator"); err != nil {
		t.Fatal(err)
	}
	if third := hw(publishEpoch(t, store)); third <= first {
		t.Errorf("after a grant the epoch states ledger_hw %d, not above %d", third, first)
	}
}

// supplyOfStore is supplyOf for a store without a test server.
func supplyOfStore(t testing.TB, store *aghub.Store, hubAID string) aghub.Supply {
	t.Helper()
	sup, err := store.Supply(hubAID)
	if err != nil {
		t.Fatal(err)
	}
	return sup
}

// A deregistered account keeps its balance on the books: it is a leaf of
// the next epoch, though it no longer has a registration.
func TestADeregisteredBalanceIsStillOnTheBooks(t *testing.T) {
	srv, store := newHubWithStore(t)
	a, b := twoAgents(t)
	register(t, srv, a, "A", nil)
	register(t, srv, b, "B", nil)
	if _, err := store.Deregister(a.AID(), aghub.DeregOperator); err != nil {
		t.Fatal(err)
	}
	e := publishEpoch(t, store)
	if e.Outstanding != uint64(2*testRegistrationFunds) {
		t.Errorf("outstanding %d, want both balances %d", e.Outstanding, 2*testRegistrationFunds)
	}
	if n := countRows(t, store, `SELECT COUNT(*) FROM liab_leaf WHERE aid = ?`, a.AID()); n != 1 {
		t.Errorf("the deregistered account has %d leaves", n)
	}
	if sup := supplyOfStore(t, store, hubAIDOf(t, srv)); !sup.Consistent() {
		t.Errorf("supply %+v", sup)
	}
}

// The hub answers a proof only from leaves that rebuild the root it signed:
// a stored leaf changed after the close (a salt, a balance moved between
// two leaves so the sum still holds, a leaf gone) is not served as a proof,
// which would fail at the account and look like the hub shrinking it; the
// answer is 500 internal, and the operator has the log.
func TestALeafChangedAfterTheCloseIsNotServed(t *testing.T) {
	for _, c := range []struct {
		name   string
		tamper []string
	}{
		{"a salt", []string{`UPDATE liab_leaf SET salt = zeroblob(32) WHERE aid = ?1`}},
		{"a balance moved", []string{
			`UPDATE liab_leaf SET balance = balance - 1 WHERE aid = ?1`,
			`UPDATE liab_leaf SET balance = balance + 1 WHERE aid = ?2`}},
		{"a leaf gone", []string{`DELETE FROM liab_leaf WHERE aid = ?2`}},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, store := newHubWithStore(t)
			a, b := twoAgents(t)
			register(t, srv, a, "A", nil)
			register(t, srv, b, "B", nil)
			publishEpoch(t, store)
			for _, q := range c.tamper {
				if _, err := store.DBForTest().Exec(q, a.AID(), b.AID()); err != nil {
					t.Fatal(err)
				}
			}
			logs := captureLog(t)
			code, _, body := liabilityProof(t, srv, a, a, "")
			if code != http.StatusInternalServerError || !strings.Contains(string(body), `"reason":"internal"`) {
				t.Errorf("a proof from changed leaves: %d %s, want 500 internal", code, body)
			}
			if !strings.Contains(logs.String(), "epoch 0") {
				t.Errorf("nothing logged for the operator: %q", logs.String())
			}
		})
	}
}
