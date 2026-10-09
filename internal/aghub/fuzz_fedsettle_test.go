package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// The decoders of the settlement routes a peer hub calls
// (hub-payment-privacy PAY-L4, PAY-U2): POST /fed/v3/settle and
// /fed/v3/clear as the kernel answers them once federation has checked the
// peer's signature (ServeFedSettle, ServeFedClear).

// fedPeers are the hubs a fuzzed request is signed by, by selector.
var fedPeers = []string{"bafy-peer-hub-a", "bafy-peer-hub-b"}

// FuzzHubFedSettle hands /fed/v3/settle a payment built from fuzzed terms
// (amount, payee, network, amounts stated and required, window up to more
// than a day, binding), or fuzzed bytes, as signed by one of two peer hubs,
// and optionally again by the same or the other peer. Properties:
//
//   - the answer is always 200 with an x402 SettlementResponse (core G3);
//   - fuzzed bytes move nothing;
//   - a settlement succeeds only on this hub's ledger, for a payee that is
//     neither an account here, nor this hub, nor the peer, within 24 hours
//     of validity, of at least the required amount; it moves exactly the
//     amount off the payer onto the hub's row and makes this hub owe that
//     peer exactly as much more (hub_due by peer), and no other peer;
//   - the same authorization again: for the same peer the original
//     success, flagged replayed; for the other, duplicate_nonce; neither
//     moves anything;
//   - the ledger invariants hold.
func FuzzHubFedSettle(f *testing.F) {
	w := newX402World(f)
	f.Add(uint64(10), "", "", uint8(2), "", uint8(0), "", uint8(0), "ix-1", int64(-1000), int64(60_000), false, uint8(0), uint8(1), []byte(nil))
	f.Add(uint64(10), "", "", uint8(0), "", uint8(0), "", uint8(0), "", int64(-1000), int64(60_000), false, uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(10), "", "", uint8(1), "", uint8(0), "", uint8(0), "", int64(-1000), int64(60_000), false, uint8(1), uint8(0), []byte(nil))
	f.Add(uint64(10), "", "", uint8(4), "bafy-peer-hub-a", uint8(0), "", uint8(0), "", int64(-1000), int64(60_000), false, uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(10), "", "", uint8(2), "", uint8(0), "", uint8(0), "ix-2", int64(-1000), int64(60_000), true, uint8(0), uint8(2), []byte(nil))
	f.Add(uint64(math.MaxUint64), "", "", uint8(2), "", uint8(0), "", uint8(0), "", int64(-1000), int64(60_000), false, uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(5), "", "", uint8(2), "", uint8(1), "", uint8(0), "", int64(-1000), int64(60_000), false, uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(5), "", "", uint8(0), "", uint8(0), "", uint8(0), "", int64(0), int64(0), false, uint8(0), uint8(0),
		[]byte(`{"x402Version":2,"paymentPayload":{"payload":{"authorization":"AAAA"}},"paymentRequirements":{"amount":"5"}}`))

	f.Fuzz(func(t *testing.T, amount uint64, reqAmount, accAmount string, payToSel uint8, rawAID string,
		netSel uint8, rawNet string, flags uint8, ix string, issuedDelta, window int64, long bool,
		peerSel, again uint8, raw []byte) {
		reqAmount, accAmount, rawAID, rawNet, ix = clip(reqAmount, 64), clip(accAmount, 64), clip(rawAID, 128), clip(rawNet, 128), clip(ix, 128)
		raw = clipB(raw, 16<<10)
		h := w.h
		w.topUp(t)
		defer h.ledgerInvariants(t)
		peer := fedPeers[int(peerSel)%len(fedPeers)]
		serve := func(peer string, body []byte) payment.SettlementResponse {
			t.Helper()
			rec := httptest.NewRecorder()
			h.srv.ServeFedSettle(rec, peer, body)
			var out payment.SettlementResponse
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
				t.Fatalf("/fed/v3/settle: %d %s", rec.Code, rec.Body)
			}
			return out
		}
		dueOf := func() map[string]int64 {
			d, err := h.store.Due()
			if err != nil {
				t.Fatal(err)
			}
			return d
		}
		if len(raw) > 0 {
			before, due := w.snap(t), dueOf()
			if out := serve(peer, raw); out.Success {
				t.Fatalf("fuzzed bytes settled: %+v", out)
			}
			if after, due2 := w.snap(t), dueOf(); after != before || due2[peer] != due[peer] {
				t.Fatalf("fuzzed bytes moved balances: %+v -> %+v", before, after)
			}
			return
		}
		x := w.terms(amount, reqAmount, accAmount, payToSel, rawAID, netSel, rawNet, flags, ix, issuedDelta, window)
		if long {
			x.notAfter = x.issuedAt + int64(payment.MaxAuthWindow/1e6) + window%(2*60_000)
		}
		p, _ := x.payload(t, w.payer)
		body := fzJSON(t, payment.FacilitatorRequest{X402Version: payment.Version,
			PaymentPayload: p, PaymentRequirements: w.requirements(x)})
		before, dueBefore := w.snap(t), dueOf()
		out := serve(peer, body)
		after, dueAfter := w.snap(t), dueOf()
		if !out.Success {
			if after != before || dueAfter[peer] != dueBefore[peer] {
				t.Fatalf("a refused forwarded settlement (%s) moved balances: %+v -> %+v", out.ErrorReason, before, after)
			}
			return
		}
		amt := int64(x.amount)
		want, err := payment.ParseAmount(x.reqAmount)
		switch {
		case x.network != payment.CreditNetwork(h.hubAID) || x.accNet != x.network:
			t.Fatalf("settled a payment on %s", x.network)
		case x.payTo == w.payee.AID() || x.payTo == w.payer.AID() || x.payTo == h.hubAID || x.payTo == peer:
			t.Fatalf("settled a forwarded payment to %s, who is not a payee elsewhere", x.payTo)
		case x.payTo != x.reqPayTo || x.accPayTo != x.payTo:
			t.Fatalf("settled a payment to %s; required %s", x.payTo, x.reqPayTo)
		case x.notAfter-x.issuedAt > int64(payment.MaxAuthWindow/1e6):
			t.Fatalf("settled an authorization valid for %d ms", x.notAfter-x.issuedAt)
		case err != nil || x.amount < want || x.amount == 0 || x.amount > math.MaxInt64:
			t.Fatalf("settled %d against a requirement of %q", x.amount, x.reqAmount)
		}
		moved := before
		moved.payer -= amt
		moved.payerEntries++
		moved.hub += amt
		moved.foreignDue += amt
		if after != moved || dueAfter[peer] != dueBefore[peer]+amt {
			t.Fatalf("settling %d for %s: %+v -> %+v (due %d -> %d)", amt, peer, before, after, dueBefore[peer], dueAfter[peer])
		}
		for _, other := range fedPeers {
			if other != peer && dueAfter[other] != dueBefore[other] {
				t.Fatalf("settling for %s made this hub owe %s", peer, other)
			}
		}
		if again == 0 {
			return
		}
		next := peer
		if again%2 == 0 {
			next = fedPeers[(int(peerSel)+1)%len(fedPeers)]
		}
		rep := serve(next, body)
		switch {
		case next == peer && (!rep.Success || rep.Extensions[payment.ExtReplayed] != true || rep.Transaction != out.Transaction):
			t.Fatalf("the same peer again: %+v", rep)
		case next != peer && (rep.Success || rep.ErrorReason != payment.ReasonDuplicateNonce):
			t.Fatalf("another peer with the same authorization: %+v", rep)
		}
		if again2, due2 := w.snap(t), dueOf(); again2 != after || due2[peer] != dueAfter[peer] || due2[next] != dueAfter[next] {
			t.Fatalf("a repeat moved balances: %+v -> %+v", after, again2)
		}
	})
}

// FuzzHubFedClear hands /fed/v3/clear fuzzed bodies as the peer hub's
// (seeded with real discharge statements of the peer, in base64url and in
// other spellings). Properties: the answer is 200 or a G1 400
// bad_request; a 400 changes nothing; what the peer owes this hub never
// rises, and falls only on a 200; the ledger invariants hold.
func FuzzHubFedClear(f *testing.F) {
	h := newFZ(f)
	peer, err := identitytest.Hub()
	if err != nil {
		f.Fatal(err)
	}
	h.srv.SetPeerKELResolver(func(aid string) ([]identity.SignedEvent, error) {
		if aid == peer.AID() {
			return peer.KEL(), nil
		}
		return nil, errNotPeer
	})
	payee, _ := h.agent(f, "fuzz-clear-payee", nil, false)
	owed := &payment.Receipt{AuthID: "fuzz-owed", Payer: "did:anet:their-user", PayTo: payee.AID(), Amount: 1 << 40,
		Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli()}
	if err := owed.Sign(peer); err != nil {
		f.Fatal(err)
	}
	if err := h.store.ClearFromPeer(peer.AID(), peer.KEL(), owed); err != nil {
		f.Fatal(err)
	}
	statement := func(id string, amount uint64) []byte {
		rec := &payment.Receipt{AuthID: id, Payer: peer.AID(), PayTo: h.hubAID, Amount: amount,
			Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli()}
		if err := rec.Sign(peer); err != nil {
			f.Fatal(err)
		}
		raw, err := rec.Marshal()
		if err != nil {
			f.Fatal(err)
		}
		return raw
	}
	seed := func(peerAID, receipt string) []byte {
		return fzJSON(f, aghub.ClearRequest{PeerAID: peerAID, Receipt: receipt})
	}
	one := statement("clear:fuzz:1", 1)
	f.Add(seed(peer.AID(), base64.RawURLEncoding.EncodeToString(one)))
	f.Add(seed(peer.AID(), base64.StdEncoding.EncodeToString(statement("clear:fuzz:2", 2))))
	f.Add(seed(peer.AID(), base64.RawURLEncoding.EncodeToString(statement("clear:fuzz:big", math.MaxUint64))))
	f.Add(seed("did:anet:someone", base64.RawURLEncoding.EncodeToString(one)))
	f.Add([]byte(`{"peer_aid":"x","receipt":"AA","extra":1}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		body = clipB(body, 64<<10)
		defer h.ledgerInvariants(t)
		before, _ := h.store.Owed(peer.AID())
		rec := httptest.NewRecorder()
		h.srv.ServeFedClear(rec, peer.AID(), body)
		after, _ := h.store.Owed(peer.AID())
		switch rec.Code {
		case http.StatusOK:
			var out aghub.ClearResponse
			if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Peer != peer.AID() || out.Owed != after {
				t.Fatalf("200 %s, owed %d", rec.Body, after)
			}
		case http.StatusBadRequest:
			var rf struct{ Reason, Error string }
			if json.Unmarshal(rec.Body.Bytes(), &rf) != nil || rf.Reason != "bad_request" || rf.Error == "" {
				t.Fatalf("400 that is not a G1 bad_request: %s", rec.Body)
			}
			if after != before {
				t.Fatalf("a refused discharge moved owed %d -> %d", before, after)
			}
		default:
			t.Fatalf("unexpected %d %s", rec.Code, rec.Body)
		}
		if after > before {
			t.Fatalf("a discharge raised what the peer owes: %d -> %d", before, after)
		}
	})
}
