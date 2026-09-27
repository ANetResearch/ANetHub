package aghub

import (
	"database/sql"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

// settlementStore is a store with a signing hub and two registered agents,
// the payer funded.
func settlementStore(t *testing.T) (*Store, *identity.Controller, *identity.Controller, *identity.Controller) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	hub, _ := identity.Incept()
	s.SetHubKey(hub)
	payer, _ := identity.Incept()
	payee, _ := identity.Incept()
	for _, c := range []*identity.Controller{payer, payee} {
		kel, err := identity.MarshalKEL(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.PutAgent(c.AID(), "agent", nil, kel); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Credit(payer.AID(), 500, "test grant"); err != nil {
		t.Fatal(err)
	}
	return s, hub, payer, payee
}

func payloadFor(t *testing.T, a *payment.Authorization) *payment.PaymentPayload {
	t.Helper()
	raw, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &payment.PaymentPayload{X402Version: payment.Version,
		Accepted: payment.PaymentOption{Scheme: payment.SchemeCredit, Network: a.Network,
			Amount: payment.Amount(a.Amount), Asset: payment.AssetCredit, PayTo: a.PayTo},
		Payload: map[string]any{"authorization": base64.StdEncoding.EncodeToString(raw)}}
}

// A charged authorization is answered with its original receipt after its
// window has closed (A2A-DESIGN §8.5, C25). A merchant whose settle call
// timed out retries until it learns the outcome; if the hub answered the
// retry with expired_payment, the merchant would conclude it was not paid
// while the payer had been charged.
func TestAChargedAuthorizationGetsItsReceiptAfterItsWindow(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	network := payment.CreditNetwork(hub.AID())
	now := time.Now().UnixMilli()
	// Its window closed ten minutes ago, beyond the clock skew allowance.
	late := &payment.Authorization{PayTo: payee.AID(), Amount: 40, Network: network, Nonce: "late-1",
		IssuedAt: now - 20*60_000, NotAfter: now - 10*60_000, InteractionID: "bind-late"}
	if err := late.Sign(payer); err != nil {
		t.Fatal(err)
	}
	id, err := late.ID()
	if err != nil {
		t.Fatal(err)
	}
	// Settled while it was valid. settleAuth is what SettleWithRequirements
	// calls after the window check, so calling it directly stands in for
	// the settlement made when the authorization was current.
	first := s.settleAuth(hub.AID(), late, id)
	if !first.Success {
		t.Fatalf("settling: %+v", first)
	}
	charged, _ := s.Balance(payer.AID())

	req := &payment.PaymentRequirements{Scheme: payment.SchemeCredit, Network: network,
		Amount: "40", Asset: payment.AssetCredit, PayTo: payee.AID()}
	again := s.SettleWithRequirements(hub.AID(), payloadFor(t, late), req)
	if !again.Success || again.Extensions[payment.ExtReplayed] != true || again.Transaction != id {
		t.Fatalf("the repeat after the window: %+v, want the original success", again)
	}
	if again.Extensions[payment.ExtReceipt] != first.Extensions[payment.ExtReceipt] {
		t.Errorf("the repeat carries a different receipt")
	}
	if got, _ := s.Balance(payer.AID()); got != charged {
		t.Errorf("the repeat moved credit: %d -> %d", charged, got)
	}

	// An authorization with the same window that was never settled is
	// still refused: the window applies to everything not already charged.
	fresh := &payment.Authorization{PayTo: payee.AID(), Amount: 40, Network: network, Nonce: "late-2",
		IssuedAt: now - 20*60_000, NotAfter: now - 10*60_000, InteractionID: "bind-late-2"}
	if err := fresh.Sign(payer); err != nil {
		t.Fatal(err)
	}
	if out := s.SettleWithRequirements(hub.AID(), payloadFor(t, fresh), req); out.Success ||
		out.ErrorReason != payment.ReasonExpiredPayment {
		t.Errorf("an expired authorization never settled: %+v, want %s", out, payment.ReasonExpiredPayment)
	}
}

// A settlement row written before receipts were stored is answered with a
// receipt re-signed from the row, and the same bytes every time.
func TestARepeatOfALegacyRowIsStable(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	network := payment.CreditNetwork(hub.AID())
	now := time.Now().UnixMilli()
	a := &payment.Authorization{PayTo: payee.AID(), Amount: 7, Network: network, Nonce: "legacy",
		IssuedAt: now - 1000, NotAfter: now + 60_000}
	if err := a.Sign(payer); err != nil {
		t.Fatal(err)
	}
	id, _ := a.ID()
	if out := s.settleAuth(hub.AID(), a, id); !out.Success {
		t.Fatalf("settle: %+v", out)
	}
	if _, err := s.db.Exec(`UPDATE credit_settled SET receipt = NULL WHERE auth_id = ?`, id); err != nil {
		t.Fatal(err)
	}
	r1, ok1, err1 := s.settledBefore(hub.AID(), id)
	r2, ok2, err2 := s.settledBefore(hub.AID(), id)
	if !ok1 || !ok2 || err1 != nil || err2 != nil {
		t.Fatalf("lookup: %v %v %v %v", ok1, ok2, err1, err2)
	}
	b1, _ := r1.Extensions[payment.ExtReceipt].(string)
	if b1 == "" || b1 != r2.Extensions[payment.ExtReceipt] {
		t.Fatalf("legacy receipts differ or are missing: %q / %v", b1, r2.Extensions[payment.ExtReceipt])
	}
	raw, _ := base64.StdEncoding.DecodeString(b1)
	rec, err := payment.UnmarshalReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Verify(hub.KEL(), hub.AID(), time.Now().UnixMilli()); err != nil {
		t.Errorf("the re-signed receipt does not verify: %v", err)
	}
	if rec.AuthID != id || rec.PayTo != payee.AID() || rec.Amount != 7 {
		t.Errorf("re-signed receipt = %+v", rec)
	}
}

// A hub upgraded with two settlements already on one binding starts, and
// the earlier settlement holds the binding. An index over every row would
// fail to build on such a table and the hub would not start.
func TestUpgradingAHubWithDuplicateBindingsKeepsTheFirstAsHolder(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE credit_settled (
		   auth_id TEXT PRIMARY KEY, payer TEXT NOT NULL, pay_to TEXT NOT NULL,
		   amount INTEGER NOT NULL, interaction_id TEXT NOT NULL DEFAULT '', at TEXT NOT NULL)`,
		`INSERT INTO credit_settled VALUES('a1','P','Q',5,'ix-1','2026-01-01T00:00:00Z')`,
		`INSERT INTO credit_settled VALUES('a2','P','Q',5,'ix-1','2026-01-02T00:00:00Z')`,
		`INSERT INTO credit_settled VALUES('a3','P','Q',5,'','2026-01-03T00:00:00Z')`,
		`INSERT INTO credit_settled VALUES('a4','P','Q',5,'','2026-01-04T00:00:00Z')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	for round := 0; round < 2; round++ {
		s, err := Open(dir)
		if err != nil {
			t.Fatalf("round %d: the upgraded hub did not open: %v", round, err)
		}
		holder, err := s.bindingHolder("P", "ix-1")
		if err != nil || holder != "a1" {
			t.Errorf("round %d: holder = %q (%v), want the first settlement a1", round, holder, err)
		}
		// A new row on a held binding is refused by the index.
		if _, err := s.db.Exec(`INSERT INTO credit_settled(auth_id, payer, pay_to, amount, interaction_id, at, bound)
			VALUES('a5-` + string(rune('0'+round)) + `','P','Q',5,'ix-1','x',1)`); err == nil {
			t.Errorf("round %d: a second bound row for one binding was accepted", round)
		}
		s.Close()
	}
}

// A clearing whose row cannot be written is reported as a failure, so the
// entry hub answers settlement_pending and the merchant retries. Only a
// row that already exists is "already cleared".
func TestAClearingThatCannotBeRecordedIsNotReportedAsDone(t *testing.T) {
	s, _, payer, payee := settlementStore(t)
	peer, _ := identity.Incept()
	network := payment.CreditNetwork(peer.AID())
	now := time.Now().UnixMilli()
	auth := &payment.Authorization{PayTo: payee.AID(), Amount: 25, Network: network, Nonce: "clr-1",
		IssuedAt: now - 1000, NotAfter: now + 60_000}
	if err := auth.Sign(payer); err != nil {
		t.Fatal(err)
	}
	id, _ := auth.ID()
	rec := &payment.Receipt{AuthID: id, Payer: payer.AID(), PayTo: payee.AID(), Amount: 25,
		Network: network, SettleAt: now}
	if err := rec.Sign(peer); err != nil {
		t.Fatal(err)
	}
	raw, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out := payment.SettlementResponse{Success: true, Payer: payer.AID(), Transaction: id, Network: network,
		Amount: "25", Extensions: map[string]any{payment.ExtReceipt: base64.StdEncoding.EncodeToString(raw)}}
	req := &payment.PaymentRequirements{Scheme: payment.SchemeCredit, Network: network, Amount: "25",
		Asset: payment.AssetCredit, PayTo: payee.AID()}
	kel := func(string) ([]identity.SignedEvent, error) { return peer.KEL(), nil }

	// The table the clearing is recorded in is gone: every insert fails.
	if _, err := s.db.Exec(`ALTER TABLE credit_cleared RENAME TO credit_cleared_away`); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearFromPeer(peer.AID(), peer.KEL(), rec); err == nil {
		t.Error("ClearFromPeer reported success for a clearing it could not record")
	}
	if got := s.ClearPeerSettlement(peer.AID(), kel, out, auth, req); got.Success ||
		got.ErrorReason != payment.ReasonSettlementPending {
		t.Errorf("entry hub answer = %+v, want %s", got, payment.ReasonSettlementPending)
	}
	if n, _ := s.Balance(payee.AID()); n != 0 {
		t.Fatalf("payee credited %d without a clearing record", n)
	}

	// Once the table is back the retry clears it, once.
	if _, err := s.db.Exec(`ALTER TABLE credit_cleared_away RENAME TO credit_cleared`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if got := s.ClearPeerSettlement(peer.AID(), kel, out, auth, req); !got.Success {
			t.Fatalf("retry %d: %+v", i, got)
		}
	}
	if n, _ := s.Balance(payee.AID()); n != 25 {
		t.Errorf("payee balance %d after two retries, want 25", n)
	}
}

// A redemption already recorded is returned for its authorization after
// the authorization's window has closed, as a settlement repeat is.
func TestARedemptionRepeatAfterItsWindowReturnsTheRecord(t *testing.T) {
	s, hub, payer, _ := settlementStore(t)
	network := payment.CreditNetwork(hub.AID())
	now := time.Now().UnixMilli()
	late := &payment.Authorization{PayTo: hub.AID(), Amount: 9, Network: network, Nonce: "late-redeem",
		IssuedAt: now - 20*60_000, NotAfter: now - 10*60_000, InteractionID: "redeem:late"}
	if err := late.Sign(payer); err != nil {
		t.Fatal(err)
	}
	id, _ := late.ID()
	// Redeemed while it was valid: the settlement and its note.
	if out := s.settleAuth(hub.AID(), late, id); !out.Success {
		t.Fatalf("settle: %+v", out)
	}
	if _, err := s.db.Exec(`INSERT INTO credit_redemption(auth_id, aid, amount, reference, at) VALUES(?,?,?,?,?)`,
		id, payer.AID(), 9, "late", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	bal, _ := s.Balance(payer.AID())
	got, err := s.Redeem(hub.AID(), payloadFor(t, late), "late")
	if err != nil || got.AuthID != id || got.Amount != 9 || got.Reference != "late" || got.Receipt == "" {
		t.Fatalf("repeat after the window = %+v, %v; want the recorded redemption", got, err)
	}
	if n, _ := s.Balance(payer.AID()); n != bal {
		t.Errorf("the repeat moved credit: %d -> %d", bal, n)
	}
}

// Two settlements of one authorization that both pass the lookup made
// before settleAuth (two concurrent repeats, or Redeem, which calls
// settleAuth directly) meet at the insert. The second is answered with
// the first one's success and receipt and moves nothing; it is neither a
// failure nor a duplicate binding of itself.
func TestASettlementThatLosesTheInsertIsAnsweredAsARepeat(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	network := payment.CreditNetwork(hub.AID())
	now := time.Now().UnixMilli()
	a := &payment.Authorization{PayTo: payee.AID(), Amount: 11, Network: network, Nonce: "race-1",
		IssuedAt: now - 1000, NotAfter: now + 60_000, InteractionID: "bind-race"}
	if err := a.Sign(payer); err != nil {
		t.Fatal(err)
	}
	id, _ := a.ID()
	first := s.settleAuth(hub.AID(), a, id)
	if !first.Success {
		t.Fatalf("first: %+v", first)
	}
	bal, _ := s.Balance(payer.AID())
	second := s.settleAuth(hub.AID(), a, id)
	if !second.Success || second.Extensions[payment.ExtReplayed] != true ||
		second.Extensions[payment.ExtReceipt] != first.Extensions[payment.ExtReceipt] {
		t.Errorf("second settleAuth of one authorization = %+v, want the first success replayed", second)
	}
	if n, _ := s.Balance(payer.AID()); n != bal {
		t.Errorf("the second settleAuth moved credit: %d -> %d", bal, n)
	}
}
