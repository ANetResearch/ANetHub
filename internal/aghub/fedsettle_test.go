package aghub

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Cross-hub settlement (hub-payment-privacy §2.4, PAY-L3 to PAY-L5; SI-9,
// SI-54): /x402/settle settles only for a payee this hub keeps
// (payee_not_local), a peer's signed /fed/v3/settle is the one way to settle
// for a payee elsewhere and leaves this hub owing that peer (hub_due by
// peer), an authorization valid for more than 24 hours is refused
// everywhere (auth_window_too_long), and a peer's receipt is cleared only
// within 7 days of its settlement (receipt_too_old).

// ledgerRows is what the money tables of s hold, for checking that a refusal
// moved nothing.
func ledgerRows(t *testing.T, s *Store) string {
	t.Helper()
	var b strings.Builder
	for _, q := range []string{
		`SELECT aid || '=' || credits FROM credit_balance ORDER BY aid`,
		`SELECT auth_id FROM credit_settled ORDER BY auth_id`,
		`SELECT hex(h) FROM settle_guard ORDER BY h`,
		`SELECT peer_aid || '=' || amount FROM hub_due ORDER BY peer_aid`,
		`SELECT peer_aid || '=' || amount FROM hub_owed ORDER BY peer_aid`,
		`SELECT auth_id FROM credit_cleared ORDER BY auth_id`,
		`SELECT seq FROM credit_entry ORDER BY seq`,
		`SELECT issued || '/' || redeemed || '/' || events_since_publish FROM supply_totals`,
	} {
		rows, err := s.db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			b.WriteString(v + "\n")
		}
		rows.Close()
		b.WriteString("--\n")
	}
	return b.String()
}

// authAt is an authorization of amount from payer to payTo on network,
// issued at issued and valid for window, signed.
func authAt(t *testing.T, payer *identity.Controller, payTo string, amount uint64, network, bind, nonce string,
	issued time.Time, window time.Duration) *payment.Authorization {
	t.Helper()
	a := &payment.Authorization{PayTo: payTo, Amount: amount, Network: network, Nonce: nonce,
		IssuedAt: issued.UnixMilli(), NotAfter: issued.Add(window).UnixMilli(), InteractionID: bind}
	if err := a.Sign(payer); err != nil {
		t.Fatal(err)
	}
	return a
}

// requirementsOf is the requirements a's payee would state for it.
func requirementsOf(a *payment.Authorization) *payment.PaymentRequirements {
	return &payment.PaymentRequirements{Scheme: payment.SchemeCredit, Network: a.Network,
		Amount: payment.Amount(a.Amount), Asset: payment.AssetCredit, PayTo: a.PayTo}
}

// M-PAY-9, N9: /x402/settle and /x402/verify refuse a payee that is not an
// account of this hub with payee_not_local, before anything is decoded, and
// nothing moves or is owed; on a peer's ledger the entry hub does not
// forward a payment for a payee it does not keep. Only the peer's signed
// /fed/v3/settle (SettleForPeer) settles it.
func TestSettleRefusesAPayeeThatIsNotHere(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	own := payment.CreditNetwork(hub.AID())
	stranger, _ := identitytest.Hub()
	forwarded := 0
	s.SetPeerSettler(func(string, *payment.PaymentPayload, *payment.PaymentRequirements,
		*payment.Authorization) (payment.SettlementResponse, bool) {
		forwarded++
		return payment.SettlementResponse{Success: true}, true
	})
	for _, c := range []struct {
		name    string
		network string
		payTo   string
	}{
		{"own ledger, a payee on no hub", own, stranger.AID()},
		{"own ledger, a payee written as anything", own, "did:anet:their-provider"},
		{"a peer's ledger, a payee not here", payment.CreditNetwork("did:anet:peer-hub"), stranger.AID()},
	} {
		before := ledgerRows(t, s)
		a := authAt(t, payer, c.payTo, 40, c.network, "bind-"+c.name, "n-"+c.name, s.now().Add(-time.Second), 5*time.Minute)
		p, req := payloadFor(t, a), requirementsOf(a)
		if out := s.SettleWithRequirements(hub.AID(), p, req); out.Success || out.ErrorReason != payment.ReasonPayeeNotLocal {
			t.Errorf("%s: settle = %+v, want %s", c.name, out, payment.ReasonPayeeNotLocal)
		}
		if c.network == own {
			if v := s.VerifyWithRequirements(hub.AID(), p, req); v.IsValid || v.InvalidReason != payment.ReasonPayeeNotLocal {
				t.Errorf("%s: verify = %+v, want %s", c.name, v, payment.ReasonPayeeNotLocal)
			}
		}
		if after := ledgerRows(t, s); after != before {
			t.Errorf("%s: a refused settlement changed the ledger:\n%s\n%s", c.name, before, after)
		}
	}
	if forwarded != 0 {
		t.Errorf("a payment for a payee not here was forwarded %d time(s)", forwarded)
	}
	// The same payment, forwarded by the payee's hub: settled, owed to it.
	a := authAt(t, payer, stranger.AID(), 40, own, "bind-fwd", "n-fwd", s.now().Add(-time.Second), 5*time.Minute)
	if out := s.SettleForPeer(hub.AID(), "did:anet:peer-hub", payloadFor(t, a), requirementsOf(a)); !out.Success {
		t.Fatalf("forwarded by the payee's hub: %+v", out)
	}
	// And a payee here is still settled here.
	b := authAt(t, payer, payee.AID(), 40, own, "bind-here", "n-here", s.now().Add(-time.Second), 5*time.Minute)
	if out := s.SettleWithRequirements(hub.AID(), payloadFor(t, b), requirementsOf(b)); !out.Success {
		t.Fatalf("a payee here: %+v", out)
	}
}

// M-PAY-10: what left this ledger for a peer's payee is owed to the peer
// that signed the forwarded request, one row per peer, never one per payee;
// the payer is charged, the payee gets nothing here, the hub's row and the
// supply record the credit leaving (P-PAY-3), and the receipt names the
// payee and the amount the peer's hub clears against.
func TestAForwardedSettlementIsOwedToThePeerThatSigned(t *testing.T) {
	s, hub, payer, _ := settlementStore(t)
	own := payment.CreditNetwork(hub.AID())
	const peerA, peerB = "did:anet:hub-a", "did:anet:hub-b"
	pays := []struct {
		peer, payee string
		amount      uint64
	}{
		{peerA, "did:anet:a-agent-1", 30}, {peerA, "did:anet:a-agent-2", 12}, {peerB, "did:anet:b-agent", 5},
		{peerA, "did:anet:a-agent-1", 8},
	}
	balBefore, _ := s.Balance(payer.AID())
	supBefore, _ := s.Supply(hub.AID())
	for i, p := range pays {
		a := authAt(t, payer, p.payee, p.amount, own, fmt.Sprintf("bind-%d", i), fmt.Sprintf("n-%d", i),
			s.now().Add(-time.Second), 5*time.Minute)
		out := s.SettleForPeer(hub.AID(), p.peer, payloadFor(t, a), requirementsOf(a))
		if !out.Success {
			t.Fatalf("payment %d: %+v", i, out)
		}
		raw, _ := base64.StdEncoding.DecodeString(out.Extensions[payment.ExtReceipt].(string))
		rec, err := payment.UnmarshalReceipt(raw)
		if err != nil || rec.PayTo != p.payee || rec.Amount != p.amount || rec.Network != own {
			t.Fatalf("payment %d: receipt %+v (%v)", i, rec, err)
		}
		if got, _ := s.Balance(p.payee); got != 0 {
			t.Errorf("a payee on %s was credited %d here", p.peer, got)
		}
	}
	due, err := s.Due()
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 || due[peerA] != 50 || due[peerB] != 5 {
		t.Errorf("due = %v, want %s 50 and %s 5", due, peerA, peerB)
	}
	var keys int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM hub_due WHERE peer_aid LIKE 'did:anet:%-agent%'`).Scan(&keys); err != nil || keys != 0 {
		t.Errorf("hub_due holds %d rows keyed by a payee (%v)", keys, err)
	}
	if got, _ := s.Balance(payer.AID()); got != balBefore-55 {
		t.Errorf("payer balance %d, want %d", got, balBefore-55)
	}
	sup, _ := s.Supply(hub.AID())
	if sup.Redeemed != supBefore.Redeemed+55 || !sup.Consistent() {
		t.Errorf("supply after the forwarded settlements: %+v (before %+v)", sup, supBefore)
	}
	if n, _ := s.DueTo(peerA); n != 50 {
		t.Errorf("DueTo(%s) = %d", peerA, n)
	}
	if err := s.DischargeDue(peerA, 51); !errors.Is(err, ErrOverDue) {
		t.Errorf("a discharge above what is due: %v, want ErrOverDue", err)
	}
	if err := s.DischargeDue(peerA, 50); err != nil {
		t.Fatal(err)
	}
	if due, _ := s.Due(); len(due) != 1 || due[peerB] != 5 {
		t.Errorf("due after paying %s: %v", peerA, due)
	}
}

// A peer's forwarded settlement is for a payee elsewhere, on this hub's own
// ledger: a payee of this hub is settled here (payee_mismatch), and so is a
// payment to this hub or to the forwarding hub itself (a redemption on that
// hub's own ledger); another ledger is network_mismatch. Nothing moves.
func TestAForwardedSettlementIsForAPayeeElsewhere(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	own := payment.CreditNetwork(hub.AID())
	const peer = "did:anet:peer-hub"
	for _, c := range []struct {
		name, payTo, network, reason string
	}{
		{"a payee of this hub", payee.AID(), own, payment.ReasonPayeeMismatch},
		{"this hub", hub.AID(), own, payment.ReasonPayeeMismatch},
		{"the forwarding hub", peer, own, payment.ReasonPayeeMismatch},
		{"another ledger", "did:anet:elsewhere", payment.CreditNetwork("did:anet:third"), payment.ReasonNetworkMismatch},
	} {
		before := ledgerRows(t, s)
		a := authAt(t, payer, c.payTo, 9, c.network, "", "n-"+c.name, s.now().Add(-time.Second), 5*time.Minute)
		if out := s.SettleForPeer(hub.AID(), peer, payloadFor(t, a), requirementsOf(a)); out.Success || out.ErrorReason != c.reason {
			t.Errorf("%s: %+v, want %s", c.name, out, c.reason)
		}
		if after := ledgerRows(t, s); after != before {
			t.Errorf("%s: the ledger changed", c.name)
		}
	}
	if out := s.SettleForPeer(hub.AID(), peer, nil, nil); out.Success || out.ErrorReason != payment.ReasonInvalidRequirements {
		t.Errorf("no requirements: %+v", out)
	}
}

// A settled authorization's repeat is answered with the original receipt to
// the peer it was settled for, and refused to another peer
// (duplicate_nonce), so one payment is not cleared on two hubs; at this
// hub's own /x402/settle it is payee_not_local. Nothing moves twice.
func TestARepeatIsAnsweredOnlyToThePeerItWasSettledFor(t *testing.T) {
	s, hub, payer, _ := settlementStore(t)
	own := payment.CreditNetwork(hub.AID())
	a := authAt(t, payer, "did:anet:a-agent", 20, own, "bind-r", "n-r", s.now().Add(-time.Second), 5*time.Minute)
	p, req := payloadFor(t, a), requirementsOf(a)
	first := s.SettleForPeer(hub.AID(), "did:anet:hub-a", p, req)
	if !first.Success {
		t.Fatal(first)
	}
	before := ledgerRows(t, s)
	again := s.SettleForPeer(hub.AID(), "did:anet:hub-a", p, req)
	if !again.Success || again.Extensions[payment.ExtReplayed] != true ||
		again.Extensions[payment.ExtReceipt] != first.Extensions[payment.ExtReceipt] {
		t.Errorf("the repeat for the same peer: %+v", again)
	}
	if out := s.SettleForPeer(hub.AID(), "did:anet:hub-b", p, req); out.Success || out.ErrorReason != payment.ReasonDuplicateNonce {
		t.Errorf("the repeat for another peer: %+v, want %s", out, payment.ReasonDuplicateNonce)
	}
	if out := s.SettleWithRequirements(hub.AID(), p, req); out.Success || out.ErrorReason != payment.ReasonPayeeNotLocal {
		t.Errorf("the repeat at /x402/settle: %+v, want %s", out, payment.ReasonPayeeNotLocal)
	}
	if after := ledgerRows(t, s); after != before {
		t.Errorf("a repeat moved credit:\n%s\n%s", before, after)
	}
}

// SI-9: an authorization valid for more than 24 hours (NotAfter − IssuedAt
// > payment.MaxAuthWindow) is refused at /x402/verify, /x402/settle,
// /fed/v3/settle and /x402/redeem, and on a peer's ledger before it is
// forwarded (auth_window_too_long); nothing moves. Exactly 24 hours is
// accepted.
func TestAnAuthorizationValidForMoreThanADayIsRefused(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	own := payment.CreditNetwork(hub.AID())
	forwarded := 0
	s.SetPeerSettler(func(string, *payment.PaymentPayload, *payment.PaymentRequirements,
		*payment.Authorization) (payment.SettlementResponse, bool) {
		forwarded++
		return payment.SettlementResponse{Success: true}, true
	})
	long := payment.MaxAuthWindow + time.Millisecond
	issued := s.now().Add(-time.Second)
	before := ledgerRows(t, s)
	local := authAt(t, payer, payee.AID(), 10, own, "w-1", "w-1", issued, long)
	if out := s.SettleWithRequirements(hub.AID(), payloadFor(t, local), requirementsOf(local)); out.Success ||
		out.ErrorReason != payment.ReasonAuthWindowTooLong || out.Payer != payer.AID() {
		t.Errorf("/x402/settle: %+v, want %s naming the payer", out, payment.ReasonAuthWindowTooLong)
	}
	if v := s.VerifyWithRequirements(hub.AID(), payloadFor(t, local), requirementsOf(local)); v.IsValid ||
		v.InvalidReason != payment.ReasonAuthWindowTooLong {
		t.Errorf("/x402/verify: %+v", v)
	}
	away := authAt(t, payer, "did:anet:a-agent", 10, own, "w-2", "w-2", issued, long)
	if out := s.SettleForPeer(hub.AID(), "did:anet:hub-a", payloadFor(t, away), requirementsOf(away)); out.Success ||
		out.ErrorReason != payment.ReasonAuthWindowTooLong {
		t.Errorf("/fed/v3/settle: %+v", out)
	}
	redeem := authAt(t, payer, hub.AID(), 10, own, "", "w-3", issued, long)
	if _, err := s.Redeem(hub.AID(), payloadFor(t, redeem), "ref"); err == nil ||
		!strings.HasPrefix(err.Error(), payment.ReasonAuthWindowTooLong) {
		t.Errorf("/x402/redeem: %v", err)
	}
	peerNet := authAt(t, payer, payee.AID(), 10, payment.CreditNetwork("did:anet:hub-b"), "w-4", "w-4", issued, long)
	if out := s.SettleWithRequirements(hub.AID(), payloadFor(t, peerNet), requirementsOf(peerNet)); out.Success ||
		out.ErrorReason != payment.ReasonAuthWindowTooLong {
		t.Errorf("a peer's ledger: %+v", out)
	}
	if forwarded != 0 {
		t.Errorf("forwarded %d", forwarded)
	}
	if after := ledgerRows(t, s); after != before {
		t.Errorf("a refused authorization moved credit")
	}
	day := authAt(t, payer, payee.AID(), 10, own, "w-5", "w-5", issued, payment.MaxAuthWindow)
	if out := s.SettleWithRequirements(hub.AID(), payloadFor(t, day), requirementsOf(day)); !out.Success {
		t.Errorf("exactly 24 hours: %+v", out)
	}
	// A NotAfter at the end of time does not overflow the check.
	end := &payment.Authorization{PayTo: payee.AID(), Amount: 1, Network: own, Nonce: "w-6",
		IssuedAt: -1 << 62, NotAfter: 1<<63 - 1}
	if rf := authWindow(end); rf == nil || rf.Reason != payment.ReasonAuthWindowTooLong {
		t.Errorf("the widest window: %v", rf)
	}
}

// PAY-L5: a peer's receipt is cleared only within 7 days of its SettleAt
// (receipt_too_old, logged; the entry hub answers settlement_failed, not
// pending, since no retry makes it clearable), and not when it is dated
// further ahead than the clocks can be off. A receipt already cleared is
// answered as cleared at any age; once the janitor has deleted its row (8
// days after SettleAt) the same receipt is too old, never a second credit.
func TestAPeerReceiptOlderThanSevenDaysIsNotCleared(t *testing.T) {
	s, _, _, payee := settlementStore(t)
	now := time.Now().Truncate(time.Millisecond)
	s.clock = func() time.Time { return now }
	peer, _ := identitytest.Hub()
	receipt := func(id string, at time.Time) *payment.Receipt {
		rec := &payment.Receipt{AuthID: id, Payer: "did:anet:their-user", PayTo: payee.AID(), Amount: 15,
			Network: payment.CreditNetwork(peer.AID()), SettleAt: at.UnixMilli()}
		if err := rec.Sign(peer); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	before := ledgerRows(t, s)
	for _, c := range []struct {
		name string
		at   time.Time
	}{
		{"7 days and a millisecond old", now.Add(-peerReceiptMaxAge - time.Millisecond)},
		{"a month old", now.AddDate(0, -1, 0)},
		{"from the future", now.Add(10 * time.Minute)},
	} {
		if err := s.ClearFromPeer(peer.AID(), peer.KEL(), receipt("old-"+c.name, c.at)); !errors.Is(err, errReceiptOutOfWindow) {
			t.Errorf("%s: %v, want receipt_too_old", c.name, err)
		}
	}
	// SettleAt is the peer's to write, any int64. Dated exactly 2^63 ms
	// before now, now − SettleAt does not fit an int64: it wrapped to
	// math.MinInt64, which passed both ends of the window and was cleared.
	for _, ms := range []int64{now.UnixMilli() + math.MinInt64, math.MinInt64, math.MaxInt64} {
		rec := receipt(fmt.Sprintf("edge-%d", ms), now)
		rec.SettleAt, rec.Envelope = ms, nil
		if err := rec.Sign(peer); err != nil {
			t.Fatal(err)
		}
		if err := s.ClearFromPeer(peer.AID(), peer.KEL(), rec); !errors.Is(err, errReceiptOutOfWindow) {
			t.Errorf("a receipt dated %d (now %d): %v, want receipt_too_old", ms, now.UnixMilli(), err)
		}
	}
	if after := ledgerRows(t, s); after != before {
		t.Errorf("an out-of-window receipt moved credit")
	}
	// Within the 7 days: cleared, and the same receipt again is cleared.
	rec := receipt("in-window", now.Add(-peerReceiptMaxAge+time.Minute))
	if err := s.ClearFromPeer(peer.AID(), peer.KEL(), rec); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Balance(payee.AID()); n != 15 {
		t.Fatalf("payee %d, want 15", n)
	}
	now = now.Add(time.Hour) // past its 7 days now
	if err := s.ClearFromPeer(peer.AID(), peer.KEL(), rec); err != nil {
		t.Errorf("an already-cleared receipt past its 7 days: %v, want cleared", err)
	}
	// The janitor deletes its row a day later; then it is too old.
	now = now.Add(24 * time.Hour)
	if _, err := s.PruneLedger(); err != nil {
		t.Fatal(err)
	}
	var left int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM credit_cleared WHERE auth_id = 'in-window'`).Scan(&left)
	if left != 0 {
		t.Fatalf("credit_cleared kept the row 8 days after SettleAt")
	}
	if err := s.ClearFromPeer(peer.AID(), peer.KEL(), rec); !errors.Is(err, errReceiptOutOfWindow) {
		t.Errorf("the receipt after its row was deleted: %v, want receipt_too_old", err)
	}
	if n, _ := s.Balance(payee.AID()); n != 15 {
		t.Errorf("payee %d after the old receipt came back, want 15", n)
	}
	// At the entry hub: final, with the receipt kept as the evidence.
	auth := &payment.Authorization{Payer: "did:anet:their-user", PayTo: payee.AID(), Amount: 15,
		Network: payment.CreditNetwork(peer.AID()), Nonce: "x", IssuedAt: 1, NotAfter: 2}
	id, _ := auth.ID()
	old := receipt(id, now.AddDate(0, 0, -9))
	old.Payer = auth.Payer
	old.Envelope = nil
	if err := old.Sign(peer); err != nil {
		t.Fatal(err)
	}
	raw, _ := old.Marshal()
	out := payment.SettlementResponse{Success: true, Payer: auth.Payer, Transaction: id, Network: auth.Network,
		Amount: "15", Extensions: map[string]any{payment.ExtReceipt: base64.StdEncoding.EncodeToString(raw)}}
	got := s.ClearPeerSettlement(peer.AID(), func(string) ([]identity.SignedEvent, error) { return peer.KEL(), nil },
		out, auth, requirementsOf(auth))
	if got.Success || got.ErrorReason != payment.ReasonSettlementFailed || got.Extensions[payment.ExtReceipt] == nil {
		t.Errorf("entry hub on a too-old receipt: %+v, want settlement_failed with the receipt", got)
	}
}

// POST /fed/v3/clear as the kernel answers it (ServeFedClear): the peer's
// statement in base64url (core CORE-E5), a strict body (CORE-E7), the body's
// peer_aid the hub that signed; every refusal a G1 body, 400 bad_request,
// and nothing changes; an accepted statement is applied once and answered
// {peer, owed}.
func TestFedClearIsStrictAndAppliesOnce(t *testing.T) {
	s, hub, _, payee := settlementStore(t)
	peer, _ := identitytest.Hub()
	srv := NewServer(s)
	srv.SetHubAID(hub.AID())
	srv.SetPeerKELResolver(func(aid string) ([]identity.SignedEvent, error) {
		if aid == peer.AID() {
			return peer.KEL(), nil
		}
		return nil, sql.ErrNoRows
	})
	cleared := &payment.Receipt{AuthID: "owed-1", Payer: "did:anet:their-user", PayTo: payee.AID(), Amount: 40,
		Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli()}
	if err := cleared.Sign(peer); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearFromPeer(peer.AID(), peer.KEL(), cleared); err != nil {
		t.Fatal(err)
	}
	statement := func(amount uint64) []byte {
		rec := &payment.Receipt{AuthID: fmt.Sprintf("clear:%d:%d", amount, time.Now().UnixNano()), Payer: peer.AID(),
			PayTo: hub.AID(), Amount: amount, Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli()}
		if err := rec.Sign(peer); err != nil {
			t.Fatal(err)
		}
		raw, _ := rec.Marshal()
		return raw
	}
	serve := func(body string) (int, []byte) {
		rec := httptest.NewRecorder()
		srv.ServeFedClear(rec, peer.AID(), []byte(body))
		return rec.Code, rec.Body.Bytes()
	}
	body := func(peerAID, receipt string) string {
		b, _ := json.Marshal(ClearRequest{PeerAID: peerAID, Receipt: receipt})
		return string(b)
	}
	ten := statement(10)
	before := ledgerRows(t, s)
	for _, c := range []struct{ name, body string }{
		{"standard base64 with padding", body(peer.AID(), base64.StdEncoding.EncodeToString(ten))},
		{"base64url with padding", body(peer.AID(), base64.URLEncoding.EncodeToString(ten))},
		{"an unknown member", `{"peer_aid":"` + peer.AID() + `","receipt":"` + wire3.EncodeB64URL(ten) + `","x":1}`},
		{"a member twice", `{"peer_aid":"` + peer.AID() + `","receipt":"AA","receipt":"` + wire3.EncodeB64URL(ten) + `"}`},
		{"another hub's peer_aid", body("did:anet:someone", wire3.EncodeB64URL(ten))},
		{"no receipt", body(peer.AID(), "")},
		{"not a statement", body(peer.AID(), wire3.EncodeB64URL([]byte("nope")))},
		{"more than owed", body(peer.AID(), wire3.EncodeB64URL(statement(41)))},
		{"not JSON", `{"peer_aid":`},
	} {
		code, b := serve(c.body)
		var rf struct{ Reason, Error string }
		if code != http.StatusBadRequest || json.Unmarshal(b, &rf) != nil || rf.Reason != "bad_request" || rf.Error == "" {
			t.Errorf("%s: %d %s, want 400 bad_request with a sentence", c.name, code, b)
		}
	}
	if after := ledgerRows(t, s); after != before {
		t.Errorf("a refused discharge changed the ledger")
	}
	ok := body(peer.AID(), wire3.EncodeB64URL(ten))
	for i := 0; i < 2; i++ {
		code, b := serve(ok)
		var out ClearResponse
		if code != http.StatusOK || json.Unmarshal(b, &out) != nil || out.Peer != peer.AID() || out.Owed != 30 {
			t.Errorf("attempt %d: %d %s, want 200 {peer, owed: 30}", i, code, b)
		}
	}
}

// A discharge statement whose row cannot be written is not reported as
// applied: SettleOwed answered every insert failure as "already applied",
// so the peer heard 200, reduced what it recorded as due, and the two hubs
// disagreed. Only a row that exists is "already applied".
func TestADischargeThatCannotBeRecordedIsNotReportedAsApplied(t *testing.T) {
	s, hub, _, payee := settlementStore(t)
	peer, _ := identitytest.Hub()
	cleared := &payment.Receipt{AuthID: "owed-2", Payer: "did:anet:their-user", PayTo: payee.AID(), Amount: 40,
		Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli()}
	if err := cleared.Sign(peer); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearFromPeer(peer.AID(), peer.KEL(), cleared); err != nil {
		t.Fatal(err)
	}
	rec := &payment.Receipt{AuthID: "clear:x", Payer: peer.AID(), PayTo: hub.AID(), Amount: 10,
		Network: payment.CreditNetwork(peer.AID()), SettleAt: time.Now().UnixMilli()}
	if err := rec.Sign(peer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE hub_cleared RENAME TO hub_cleared_away`); err != nil {
		t.Fatal(err)
	}
	if err := s.SettleOwed(hub.AID(), peer.AID(), peer.KEL(), rec); err == nil {
		t.Error("a discharge that could not be recorded was reported as applied")
	}
	if owed, _ := s.Owed(peer.AID()); owed != 40 {
		t.Errorf("owed %d, want 40", owed)
	}
	if _, err := s.db.Exec(`ALTER TABLE hub_cleared_away RENAME TO hub_cleared`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.SettleOwed(hub.AID(), peer.AID(), peer.KEL(), rec); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if owed, _ := s.Owed(peer.AID()); owed != 30 {
		t.Errorf("owed %d after the statement twice, want 30", owed)
	}
}

// POST /fed/v3/settle as the kernel answers it (ServeFedSettle): always 200
// with a SettlementResponse (core G3), a body that is not a facilitator
// request included.
func TestFedSettleAnswersASettlementResponse(t *testing.T) {
	s, hub, payer, _ := settlementStore(t)
	srv := NewServer(s)
	srv.SetHubAID(hub.AID())
	a := authAt(t, payer, "did:anet:a-agent", 7, payment.CreditNetwork(hub.AID()), "b", "n", s.now().Add(-time.Second), time.Minute)
	good, _ := json.Marshal(payment.FacilitatorRequest{X402Version: payment.Version,
		PaymentPayload: payloadFor(t, a), PaymentRequirements: requirementsOf(a)})
	for _, c := range []struct {
		name, body string
		success    bool
		reason     string
	}{
		{"a payment for the peer's payee", string(good), true, ""},
		{"not JSON", "{", false, payment.ReasonMalformed},
		{"no payment", `{"x402Version":2}`, false, payment.ReasonInvalidRequirements},
	} {
		rec := httptest.NewRecorder()
		srv.ServeFedSettle(rec, "did:anet:hub-a", []byte(c.body))
		var out payment.SettlementResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil ||
			out.Success != c.success || out.ErrorReason != c.reason {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
	}
	if due, _ := s.Due(); due["did:anet:hub-a"] != 7 {
		t.Errorf("due = %v", due)
	}
}
