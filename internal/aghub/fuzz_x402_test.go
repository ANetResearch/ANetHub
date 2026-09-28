package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// x402Terms are the fuzzed terms of one payment: what the payer signs,
// what the payload states, and what the merchant requires.
type x402Terms struct {
	amount              uint64
	reqAmount, accepted string
	payTo, network      string
	accPayTo, accNet    string
	scheme, reqPayTo    string
	ix, nonce           string
	issuedAt, notAfter  int64
}

// payload signs the authorization of t as payer and wraps it.
func (x x402Terms) payload(tb testing.TB, payer *identity.Controller) (*payment.PaymentPayload, *payment.Authorization) {
	tb.Helper()
	a := &payment.Authorization{PayTo: x.payTo, Amount: x.amount, Network: x.network, Nonce: x.nonce,
		IssuedAt: x.issuedAt, NotAfter: x.notAfter, InteractionID: x.ix}
	if err := a.Sign(payer); err != nil {
		tb.Fatal(err)
	}
	raw, err := a.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	return &payment.PaymentPayload{
		X402Version: payment.Version,
		Accepted: payment.PaymentOption{Scheme: x.scheme, Network: x.accNet, Amount: x.accepted,
			Asset: payment.AssetCredit, PayTo: x.accPayTo},
		Payload: map[string]any{"authorization": base64.StdEncoding.EncodeToString(raw)},
	}, a
}

// x402World is the accounts a payment fuzz target moves credit between.
type x402World struct {
	h            *fz
	payer, payee *identity.Controller
	foreign      string // an AID registered nowhere
}

func newX402World(f *testing.F) *x402World {
	h := newFZ(f)
	payer, _ := h.agent(f, "fuzz-payer", nil, false)
	payee, _ := h.agent(f, "fuzz-payee", nil, false)
	foreign, err := identity.Incept()
	if err != nil {
		f.Fatal(err)
	}
	return &x402World{h: h, payer: payer, payee: payee, foreign: foreign.AID()}
}

// pick names a party by selector: the payee, the hub, a foreign AID, the
// payer itself, or raw.
func (w *x402World) pick(sel uint8, raw string) string {
	switch sel % 5 {
	case 0:
		return w.payee.AID()
	case 1:
		return w.h.hubAID
	case 2:
		return w.foreign
	case 3:
		return w.payer.AID()
	}
	return raw
}

// net names a ledger by selector: this hub's, another hub's, or raw.
func (w *x402World) net(sel uint8, raw string) string {
	switch sel % 3 {
	case 0:
		return payment.CreditNetwork(w.h.hubAID)
	case 1:
		return payment.CreditNetwork(w.foreign)
	}
	return raw
}

// terms builds x402Terms from fuzz selectors.
func (w *x402World) terms(amount uint64, reqAmount, accAmount string, payToSel uint8, rawAID string,
	netSel uint8, rawNet string, flags uint8, ix string, issuedDelta, window int64) x402Terms {
	// What the payer signs is CBOR, whose text strings are UTF-8: a
	// payer cannot sign anything else, so the fuzzer is not asked to.
	rawAID, rawNet, ix = strings.ToValidUTF8(rawAID, "?"), strings.ToValidUTF8(rawNet, "?"), strings.ToValidUTF8(ix, "?")
	now := time.Now().UnixMilli()
	x := x402Terms{
		amount: amount, reqAmount: reqAmount, accepted: accAmount,
		payTo: w.pick(payToSel, rawAID), network: w.net(netSel, rawNet),
		scheme: payment.SchemeCredit, ix: ix, nonce: w.h.nonce(),
		issuedAt: now + issuedDelta%(20*60_000), notAfter: 0,
	}
	x.notAfter = x.issuedAt + window%(40*60_000)
	if flags&1 == 0 {
		x.accepted = payment.Amount(amount)
	}
	if flags&2 == 0 {
		x.reqAmount = payment.Amount(amount)
	}
	x.accPayTo, x.accNet, x.reqPayTo = x.payTo, x.network, x.payTo
	if flags&4 != 0 {
		x.accPayTo = w.pick(payToSel+1, rawAID)
	}
	if flags&8 != 0 {
		x.accNet = w.net(netSel+1, rawNet)
	}
	if flags&16 != 0 {
		x.reqPayTo = w.pick(payToSel+2, rawAID)
	}
	if flags&32 != 0 {
		x.scheme = rawNet
	}
	return x
}

// requirements are what the merchant asks for.
func (w *x402World) requirements(x x402Terms) *payment.PaymentRequirements {
	return &payment.PaymentRequirements{Scheme: payment.SchemeCredit, Network: payment.CreditNetwork(w.h.hubAID),
		Amount: x.reqAmount, Asset: payment.AssetCredit, PayTo: x.reqPayTo}
}

// snapshot is every balance a payment could move.
type snapshot struct {
	payer, payee, hub, foreignDue, payerEntries int64
}

func (w *x402World) snap(t *testing.T) snapshot {
	t.Helper()
	var due int64
	_ = w.h.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM hub_due`).Scan(&due)
	return snapshot{
		payer: w.h.balance(t, w.payer.AID()), payee: w.h.balance(t, w.payee.AID()),
		hub: w.h.balance(t, w.h.hubAID), foreignDue: due,
		payerEntries: w.h.count(t, `SELECT COUNT(*) FROM credit_entry WHERE aid=?`, w.payer.AID()),
	}
}

// topUp keeps the payer able to pay, so the fuzzer is not left looking
// only at insufficient_funds.
func (w *x402World) topUp(t *testing.T) {
	t.Helper()
	if b := w.h.balance(t, w.payer.AID()); b < 10_000 {
		if err := w.h.store.GrantCredit(w.payer.AID(), 100_000, "fuzz top-up"); err != nil {
			t.Fatal(err)
		}
	}
}

// post sends a JSON body to an unauthenticated route.
func (h *fz) post(path string, body []byte) (int, []byte) {
	rec := h.serve(h.request(http.MethodPost, path, "", body))
	return rec.Code, rec.Body.Bytes()
}

// movedAsSettled checks the balances moved by exactly one settlement of
// x, or not at all when it did not settle.
func (w *x402World) movedAsSettled(t *testing.T, x x402Terms, before, after snapshot, settled bool) {
	t.Helper()
	if !settled {
		if before != after {
			t.Fatalf("an unsettled payment moved balances: %+v -> %+v", before, after)
		}
		return
	}
	amt := int64(x.amount)
	want := before
	want.payer -= amt
	want.payerEntries++
	switch x.payTo {
	case w.payer.AID():
		want.payer += amt
		want.payerEntries++
	case w.payee.AID():
		want.payee += amt
	case w.h.hubAID:
		want.hub += amt
	default:
		want.hub += amt
		want.foreignDue += amt
	}
	if after != want {
		t.Fatalf("settling %d to %s: balances %+v -> %+v, want %+v", amt, x.payTo, before, after, want)
	}
}

// FuzzHubX402Facilitator asks /x402/verify and then /x402/settle about a
// payment built from fuzzed terms (amount across the whole uint64 range,
// payee, network, stated and required amounts, window, interaction id),
// signed by a registered payer, and optionally settles it twice.
// Properties:
//
//   - both answer 200 (400 only for a body that does not decode);
//   - verify says valid exactly when settle then succeeds;
//   - a settlement succeeds only for a payment on this hub's ledger, to
//     the required payee, of at least the required amount, within the
//     payer's balance and the ledger's range, and moves exactly that
//     amount; a refusal moves nothing;
//   - settling the same authorization again answers the original
//     settlement, flagged replayed, and moves nothing;
//   - the ledger invariants hold.
func FuzzHubX402Facilitator(f *testing.F) {
	w := newX402World(f)
	f.Add(uint64(10), "", "", uint8(0), "", uint8(0), "", uint8(0), "ix-1", int64(-1000), int64(60_000), true, []byte(nil))
	f.Add(uint64(math.MaxInt64), "", "", uint8(0), "", uint8(0), "", uint8(0), "", int64(-1000), int64(60_000), false, []byte(nil))
	f.Add(uint64(math.MaxUint64-999), "", "", uint8(1), "", uint8(0), "", uint8(0), "", int64(-1000), int64(60_000), false, []byte(nil))
	f.Add(uint64(0), "", "", uint8(2), "", uint8(0), "", uint8(0), "", int64(-1000), int64(60_000), false, []byte(nil))
	f.Add(uint64(10), "", "", uint8(2), "", uint8(0), "", uint8(0), "", int64(-1000), int64(60_000), false, []byte(nil))
	f.Add(uint64(50), "60", "50", uint8(3), "", uint8(0), "", uint8(2), "ix-2", int64(-1000), int64(60_000), true, []byte(nil))
	f.Add(uint64(50), "40", "51", uint8(0), "", uint8(1), "", uint8(3), "", int64(-1000), int64(60_000), false, []byte(nil))
	f.Add(uint64(5), "5", "5", uint8(0), "", uint8(0), "", uint8(4|16), "", int64(-1000), int64(60_000), false, []byte(nil))
	f.Add(uint64(5), "", "", uint8(4), "raw-aid", uint8(2), "raw-net", uint8(8|32), "", int64(10*60_000), int64(-5), false, []byte(nil))
	f.Add(uint64(5), "", "", uint8(0), "", uint8(0), "", uint8(0), "", int64(0), int64(0), false, []byte(`{"paymentPayload":{},"paymentRequirements":{}}`))
	f.Add(uint64(5), "", "", uint8(0), "", uint8(0), "", uint8(0), "", int64(0), int64(0), false, []byte(`{"x402Version":2,"paymentPayload":{"payload":{"authorization":"AAAA"}},"paymentRequirements":{"amount":"-1"}}`))

	f.Fuzz(func(t *testing.T, amount uint64, reqAmount, accAmount string, payToSel uint8, rawAID string,
		netSel uint8, rawNet string, flags uint8, ix string, issuedDelta, window int64, repeat bool, raw []byte) {
		reqAmount, accAmount, rawAID, rawNet, ix = clip(reqAmount, 64), clip(accAmount, 64), clip(rawAID, 128), clip(rawNet, 128), clip(ix, 128)
		raw = clipB(raw, 16<<10)
		h := w.h
		w.topUp(t)
		defer h.ledgerInvariants(t)
		if len(raw) > 0 {
			before := w.snap(t)
			for _, path := range []string{"/x402/verify", "/x402/settle"} {
				code, b := h.post(path, raw)
				if !allowed(code, 200, 400) {
					t.Fatalf("%s: unexpected %d %s", path, code, b)
				}
			}
			if after := w.snap(t); after != before {
				// A raw body carries no signature the payer made here, so
				// nothing it says can move credit.
				t.Fatalf("a raw facilitator body moved balances: %+v -> %+v", before, after)
			}
			return
		}
		x := w.terms(amount, reqAmount, accAmount, payToSel, rawAID, netSel, rawNet, flags, ix, issuedDelta, window)
		p, auth := x.payload(t, w.payer)
		body := fzJSON(t, payment.FacilitatorRequest{X402Version: payment.Version,
			PaymentPayload: p, PaymentRequirements: w.requirements(x)})

		code, vb := h.post("/x402/verify", body)
		if code != http.StatusOK {
			t.Fatalf("verify: %d %s", code, vb)
		}
		var v payment.VerifyResponse
		if err := json.Unmarshal(vb, &v); err != nil {
			t.Fatal(err)
		}
		before := w.snap(t)
		code, sb := h.post("/x402/settle", body)
		if code != http.StatusOK {
			t.Fatalf("settle: %d %s", code, sb)
		}
		var s payment.SettlementResponse
		if err := json.Unmarshal(sb, &s); err != nil {
			t.Fatal(err)
		}
		after := w.snap(t)
		w.movedAsSettled(t, x, before, after, s.Success)

		// Near the window's edges verify and settle may see different
		// clocks; elsewhere they must agree.
		now := time.Now().UnixMilli()
		edge := func(at int64) bool {
			d := at - now
			return d > -payment.ClockSkew-3000 && d < -payment.ClockSkew+3000 || d > payment.ClockSkew-3000 && d < payment.ClockSkew+3000
		}
		if !edge(auth.IssuedAt) && !edge(auth.NotAfter) && v.IsValid != s.Success {
			t.Fatalf("verify said valid=%v (%s), settle said success=%v (%s)", v.IsValid, v.InvalidReason, s.Success, sb)
		}
		if s.Success {
			want, err := payment.ParseAmount(x.reqAmount)
			switch {
			case x.network != payment.CreditNetwork(h.hubAID) || x.accNet != x.network:
				t.Fatalf("settled a payment on %s (stated %s)", x.network, x.accNet)
			case x.payTo != x.reqPayTo || x.accPayTo != x.payTo:
				t.Fatalf("settled a payment to %s; required %s, stated %s", x.payTo, x.reqPayTo, x.accPayTo)
			case err != nil || x.amount < want || x.amount == 0 || x.amount > math.MaxInt64:
				t.Fatalf("settled %d against a requirement of %q", x.amount, x.reqAmount)
			case x.accepted != payment.Amount(x.amount):
				t.Fatalf("settled %d, the payload stated %q", x.amount, x.accepted)
			case s.Amount != payment.Amount(x.amount) || s.Payer != w.payer.AID():
				t.Fatalf("settlement response names %s paying %s", s.Payer, s.Amount)
			}
			if s.Extensions[payment.ExtReplayed] == true {
				t.Fatalf("a fresh authorization was answered as a repeat: %s", sb)
			}
			if repeat {
				code, sb2 := h.post("/x402/settle", body)
				var s2 payment.SettlementResponse
				_ = json.Unmarshal(sb2, &s2)
				if code != http.StatusOK || !s2.Success || s2.Transaction != s.Transaction || s2.Extensions[payment.ExtReplayed] != true {
					t.Fatalf("a repeated settlement was answered %d %s", code, sb2)
				}
				if again := w.snap(t); again != after {
					t.Fatalf("a repeated settlement moved balances: %+v -> %+v", after, again)
				}
			}
		}
	})
}

// FuzzHubX402Redeem redeems a fuzzed authorization with a fuzzed
// reference. Properties: the answer is 200 or 400; a redemption succeeds
// only for an authorization paying this hub on its own ledger, within the
// payer's balance, and moves exactly its amount from the payer to the
// hub's row; a repeat answers the recorded redemption and moves nothing;
// the ledger invariants hold (supply falls by what was redeemed).
func FuzzHubX402Redeem(f *testing.F) {
	w := newX402World(f)
	f.Add(uint64(10), uint8(1), "", uint8(0), "", uint8(0), "ref-1", int64(-1000), int64(60_000), true)
	f.Add(uint64(math.MaxInt64), uint8(1), "", uint8(0), "", uint8(0), "", int64(-1000), int64(60_000), false)
	f.Add(uint64(math.MaxUint64-999), uint8(1), "", uint8(0), "", uint8(0), "", int64(-1000), int64(60_000), false)
	f.Add(uint64(10), uint8(0), "", uint8(0), "", uint8(0), "ref", int64(-1000), int64(60_000), false)
	f.Add(uint64(10), uint8(1), "", uint8(1), "", uint8(0), "ref", int64(-1000), int64(60_000), false)
	f.Add(uint64(10), uint8(1), "", uint8(0), "", uint8(0), "ref", int64(20*60_000), int64(1), false)

	f.Fuzz(func(t *testing.T, amount uint64, payToSel uint8, rawAID string, netSel uint8, rawNet string,
		flags uint8, reference string, issuedDelta, window int64, repeat bool) {
		rawAID, rawNet, reference = clip(rawAID, 128), clip(rawNet, 128), clip(reference, 1024)
		// The reference travels as JSON, which has no invalid UTF-8: what
		// the hub receives is the string as JSON re-reads it.
		_ = json.Unmarshal(fzJSON(t, reference), &reference)
		h := w.h
		w.topUp(t)
		defer h.ledgerInvariants(t)
		x := w.terms(amount, "", "", payToSel, rawAID, netSel, rawNet, flags&(8|32), "", issuedDelta, window)
		p, _ := x.payload(t, w.payer)
		body := fzJSON(t, map[string]any{"x402Version": payment.Version, "paymentPayload": p, "reference": reference})
		before := w.snap(t)
		supBefore, _ := h.store.Supply(h.hubAID)
		code, b := h.post("/x402/redeem", body)
		if !allowed(code, 200, 400) {
			t.Fatalf("redeem: unexpected %d %s", code, b)
		}
		after := w.snap(t)
		w.movedAsSettled(t, x, before, after, code == http.StatusOK)
		if code != http.StatusOK {
			return
		}
		var red aghub.Redemption
		if err := json.Unmarshal(b, &red); err != nil {
			t.Fatal(err)
		}
		if x.payTo != h.hubAID || x.network != payment.CreditNetwork(h.hubAID) || x.accNet != x.network ||
			red.Amount != x.amount || red.AID != w.payer.AID() || red.Reference != reference {
			t.Fatalf("redeemed %+v for terms %+v", red, x)
		}
		supAfter, _ := h.store.Supply(h.hubAID)
		if supBefore.Outstanding-supAfter.Outstanding != int64(x.amount) {
			t.Fatalf("redeeming %d moved outstanding %d -> %d", x.amount, supBefore.Outstanding, supAfter.Outstanding)
		}
		if repeat {
			code, b2 := h.post("/x402/redeem", body)
			var red2 aghub.Redemption
			_ = json.Unmarshal(b2, &red2)
			if code != http.StatusOK || red2.AuthID != red.AuthID {
				t.Fatalf("a repeated redemption was answered %d %s", code, b2)
			}
			if again := w.snap(t); again != after {
				t.Fatalf("a repeated redemption moved balances: %+v -> %+v", after, again)
			}
		}
	})
}

// FuzzHubX402Gateway buys a priced capability through
// GET /x402/resource/{aid}/{capability} with a PAYMENT-SIGNATURE header
// that is either raw fuzz or a signed payment on fuzzed terms.
// Properties: the answer is 200, 400, 402, 404 or 409; a voucher is
// issued only for a settlement to the seller of at least the price, and
// it verifies against the hub's key and names the seller, the capability
// and the amount paid; any other answer moves nothing; the ledger
// invariants hold.
func FuzzHubX402Gateway(f *testing.F) {
	w := newX402World(f)
	h := w.h
	seller, err := identity.Incept()
	if err != nil {
		f.Fatal(err)
	}
	card := fzSellableCard(f, seller, "Seller", []string{"work.do", "work.free"},
		map[string]any{"work.do": 120, "work.str": "7", "work.big": "9223372036854775807",
			"work.neg": -1, "work.frac": 1.5}, "https://seller.example/x402/redeem")
	body := h.registration(f, seller, "Seller", []string{"work.do", "work.free"})
	body["card"] = card
	if rec := h.register(seller, fzJSON(f, body)); rec.Code != http.StatusOK {
		f.Fatalf("register seller: %d %s", rec.Code, rec.Body.Bytes())
	}
	w.payee = seller
	caps := []string{"work.do", "work.str", "work.big", "work.neg", "work.frac", "work.free", "nothing"}
	f.Add(uint8(0), uint64(120), "", uint8(0), "", uint8(0), "", uint8(0), "ix", false, "")
	f.Add(uint8(0), uint64(119), "", uint8(0), "", uint8(0), "", uint8(0), "ix", false, "")
	f.Add(uint8(1), uint64(7), "", uint8(0), "", uint8(0), "", uint8(0), "", true, "")
	f.Add(uint8(2), uint64(math.MaxInt64), "", uint8(0), "", uint8(0), "", uint8(0), "", false, "")
	f.Add(uint8(0), uint64(120), "", uint8(1), "", uint8(0), "", uint8(4), "", false, "")
	f.Add(uint8(0), uint64(0), "", uint8(0), "", uint8(0), "", uint8(0), "", false, "not base64 {")
	f.Add(uint8(5), uint64(1), "", uint8(0), "", uint8(0), "", uint8(0), "", false, `{"accepted":{"payTo":"x","amount":"1"}}`)

	f.Fuzz(func(t *testing.T, capSel uint8, amount uint64, rawAID string, payToSel uint8, rawNet string,
		netSel uint8, accAmount string, flags uint8, ix string, repeat bool, rawHeader string) {
		rawAID, rawNet, accAmount, ix, rawHeader = clip(rawAID, 128), clip(rawNet, 128), clip(accAmount, 64), clip(ix, 128), clip(rawHeader, 16<<10)
		w.topUp(t)
		defer h.ledgerInvariants(t)
		capID := caps[int(capSel)%len(caps)]
		x := w.terms(amount, "", accAmount, payToSel, rawAID, netSel, rawNet, flags&(1|4|8|32), ix, -1000, 5*60_000)
		header := rawHeader
		if header == "" {
			p, _ := x.payload(t, w.payer)
			header = base64.StdEncoding.EncodeToString(fzJSON(t, p))
		}
		send := func() *httpResult {
			req := h.request(http.MethodGet, "/x402/resource/"+seller.AID()+"/"+capID, "", nil)
			req.Header.Set(payment.HeaderPaymentSignature, header)
			rec := h.serve(req)
			return &httpResult{rec.Code, rec.Body.Bytes()}
		}
		before := w.snap(t)
		res := send()
		if !allowed(res.code, 200, 400, 402, 404, 409) {
			t.Fatalf("gateway: unexpected %d %s", res.code, res.body)
		}
		after := w.snap(t)
		if res.code != http.StatusOK {
			// A settlement may have happened on a 409 (a repeat for another
			// capability); anything else moved nothing.
			if after != before && res.code != http.StatusConflict {
				t.Fatalf("gateway %d moved balances: %+v -> %+v", res.code, before, after)
			}
			return
		}
		var out struct {
			Voucher     string `json:"voucher"`
			Capability  string `json:"capability"`
			Provider    string `json:"provider"`
			Transaction string `json:"transaction"`
		}
		if err := json.Unmarshal(res.body, &out); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(out.Voucher)
		if err != nil {
			t.Fatalf("voucher not base64: %v", err)
		}
		v, err := payment.UnmarshalVoucher(raw)
		if err != nil {
			t.Fatalf("voucher undecodable: %v", err)
		}
		if err := v.Verify(h.hub.KEL(), h.hubAID, seller.AID(), capID, payment.CreditNetwork(h.hubAID),
			time.Now().UnixMilli()); err != nil {
			t.Fatalf("voucher does not verify against the hub: %v", err)
		}
		price := map[string]uint64{"work.do": 120, "work.str": 7, "work.big": math.MaxInt64}[capID]
		if price == 0 || v.PayTo != seller.AID() || v.Capability != capID || v.Amount < price ||
			out.Provider != seller.AID() || out.Capability != capID {
			t.Fatalf("voucher %+v for %s at price %d", v, capID, price)
		}
		paid := after.payer - before.payer
		if paid != 0 && (-paid != int64(v.Amount) || after.payee-before.payee != int64(v.Amount)) {
			t.Fatalf("voucher for %d, balances %+v -> %+v", v.Amount, before, after)
		}
		if repeat {
			again := send()
			if again.code != http.StatusOK && again.code != http.StatusConflict {
				t.Fatalf("a repeated purchase answered %d %s", again.code, again.body)
			}
			if s := w.snap(t); s != after {
				t.Fatalf("a repeated purchase moved balances: %+v -> %+v", after, s)
			}
		}
	})
}

// fzSellableCard is sellableCard for a testing.TB.
func fzSellableCard(tb testing.TB, c *identity.Controller, name string, caps []string,
	prices map[string]any, redeemAt string) json.RawMessage {
	tb.Helper()
	now := time.Now()
	card := &adp.AgentCard{
		SubjectDID: c.AID(), CardSchema: adp.CardSchema{Major: 1},
		Seq: uint64(now.UnixNano()), IssuedAt: now.Unix(),
		NotBefore:    now.Add(-time.Minute).Unix(),
		Capabilities: caps, CriticalExtensions: []string{}, Name: name,
		Extensions: map[string]any{aghub.ExtPricing: prices},
		Endpoints:  []adp.EndpointDesc{{Protocol: aghub.EndpointRedeem, URI: redeemAt, Methods: []string{"POST"}}},
	}
	if err := card.Sign(c); err != nil {
		tb.Fatal(err)
	}
	return fzJSON(tb, card)
}

// httpResult is a status and a body.
type httpResult struct {
	code int
	body []byte
}

// FuzzHubClearFromPeer applies a peer hub's signed receipts: the credit a
// peer's settlement creates for a local payee (Store.ClearFromPeer, the
// second half of a cross-hub settlement) and a peer's discharge of what
// it owes (POST /federation/clear). Amount, payee, network, auth id and
// signer are fuzzed. Properties: a receipt clears only when the peer
// signed it, for the peer's own ledger, with an amount the ledger can
// hold; one auth id credits once; /federation/clear answers 200, 400 or
// 403 and never takes owed below zero; the ledger invariants hold after
// each.
func FuzzHubClearFromPeer(f *testing.F) {
	w := newX402World(f)
	h := w.h
	peer, err := identity.Incept()
	if err != nil {
		f.Fatal(err)
	}
	h.srv.SetPeerKELResolver(func(aid string) ([]identity.SignedEvent, error) {
		if aid == peer.AID() {
			return peer.KEL(), nil
		}
		return nil, errNotPeer
	})
	f.Add(uint64(10), uint8(0), "", uint8(0), "", "auth-1", false, uint8(0), uint64(5), true)
	f.Add(uint64(math.MaxInt64), uint8(0), "", uint8(0), "", "auth-2", false, uint8(0), uint64(math.MaxInt64), false)
	f.Add(uint64(math.MaxUint64), uint8(0), "", uint8(0), "", "auth-3", false, uint8(0), uint64(math.MaxUint64), false)
	f.Add(uint64(10), uint8(3), "", uint8(0), "", "auth-4", false, uint8(0), uint64(1), false)
	f.Add(uint64(10), uint8(2), "", uint8(0), "", "auth-5", false, uint8(1), uint64(1), false)
	f.Add(uint64(10), uint8(0), "", uint8(1), "", "auth-6", true, uint8(2), uint64(1), false)
	f.Add(uint64(10), uint8(4), "", uint8(2), "hub:x", "", false, uint8(3), uint64(0), false)

	f.Fuzz(func(t *testing.T, amount uint64, payToSel uint8, rawAID string, netSel uint8, rawNet, authID string,
		byStranger bool, clearSel uint8, clearAmount uint64, repeat bool) {
		rawAID, rawNet, authID = clip(rawAID, 128), clip(rawNet, 128), clip(authID, 256)
		defer h.ledgerInvariants(t)
		signer := peer
		if byStranger {
			signer = w.payer
		}
		// A receipt is CBOR, whose text strings are UTF-8: a peer cannot
		// sign anything else.
		rawAID, rawNet, authID = strings.ToValidUTF8(rawAID, "?"), strings.ToValidUTF8(rawNet, "?"), strings.ToValidUTF8(authID, "?")
		network := payment.CreditNetwork(peer.AID())
		switch netSel % 3 {
		case 1:
			network = payment.CreditNetwork(h.hubAID)
		case 2:
			network = rawNet
		}
		payTo := w.pick(payToSel, rawAID)
		rec := &payment.Receipt{AuthID: authID + "/" + h.nonce(), Payer: w.foreign, PayTo: payTo, Amount: amount,
			Network: network, SettleAt: time.Now().UnixMilli()}
		if err := rec.Sign(signer); err != nil {
			t.Fatal(err)
		}
		payeeBefore := h.balance(t, payTo)
		owedBefore, _ := h.store.Owed(peer.AID())
		cerr := h.store.ClearFromPeer(peer.AID(), peer.KEL(), rec)
		payeeAfter := h.balance(t, payTo)
		owedAfter, _ := h.store.Owed(peer.AID())
		valid := !byStranger && network == payment.CreditNetwork(peer.AID()) && amount > 0 && amount <= math.MaxInt64
		if cerr == nil {
			if !valid {
				t.Fatalf("cleared a receipt that should be refused: %+v", rec)
			}
			if owedAfter-owedBefore != int64(amount) {
				t.Fatalf("clearing %d moved owed %d -> %d", amount, owedBefore, owedAfter)
			}
			if payTo != h.hubAID && payeeAfter-payeeBefore != int64(amount) {
				t.Fatalf("clearing %d to %s moved its balance %d -> %d", amount, payTo, payeeBefore, payeeAfter)
			}
			if repeat {
				if err := h.store.ClearFromPeer(peer.AID(), peer.KEL(), rec); err != nil {
					t.Fatalf("a repeated receipt: %v", err)
				}
				if b := h.balance(t, payTo); b != payeeAfter {
					t.Fatalf("a repeated receipt credited again: %d -> %d", payeeAfter, b)
				}
			}
		} else if payeeAfter != payeeBefore || owedAfter != owedBefore {
			t.Fatalf("a refused receipt (%v) moved credit", cerr)
		}

		// The peer discharges some of what it owes.
		dis := &payment.Receipt{AuthID: "clear:" + h.nonce(), Payer: peer.AID(), PayTo: h.hubAID,
			Amount: clearAmount, Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli()}
		peerAID := peer.AID()
		switch clearSel % 4 {
		case 1:
			dis.PayTo = w.foreign
		case 2:
			dis.Payer = w.foreign
		case 3:
			peerAID = w.foreign
		}
		if err := dis.Sign(signer); err != nil {
			t.Fatal(err)
		}
		raw, err := dis.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		owedBefore, _ = h.store.Owed(peer.AID())
		code, b := h.post("/federation/clear", fzJSON(t, map[string]string{
			"peer_aid": peerAID, "receipt": base64.StdEncoding.EncodeToString(raw)}))
		if !allowed(code, 200, 400, 403) {
			t.Fatalf("clear: unexpected %d %s", code, b)
		}
		owedAfter, _ = h.store.Owed(peer.AID())
		if code == http.StatusOK && owedAfter != owedBefore {
			if byStranger || clearSel%4 != 0 || int64(clearAmount) != owedBefore-owedAfter {
				t.Fatalf("clear %d (sel %d, stranger %v) moved owed %d -> %d", clearAmount, clearSel, byStranger, owedBefore, owedAfter)
			}
		}
		if code != http.StatusOK && owedAfter != owedBefore {
			t.Fatalf("a refused clear moved owed %d -> %d", owedBefore, owedAfter)
		}
	})
}

// errNotPeer is the peer resolver's answer for anyone but the peer.
var errNotPeer = strconv.ErrSyntax
