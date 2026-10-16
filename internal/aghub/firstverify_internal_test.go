package aghub

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"
)

// The first verification of a payment (KEL H-40, H-41): its record, how long
// it is kept, and the two settlement doors the HTTP tests do not reach
// (/fed/v3/settle, SettleForPeer, and /x402/redeem, Redeem).

// firstVerifyRow is the record of authorization id: whether the key was the
// active tip, the key state, and when the record goes.
func firstVerifyRow(t *testing.T, s *Store, id string) (tip bool, seq, deleteAfter int64, ok bool) {
	t.Helper()
	err := s.db.QueryRow(`SELECT tip_at_first, key_state_seq, delete_after FROM x402_first_verify WHERE auth_id = ?`, id).
		Scan(&tip, &seq, &deleteAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return false, 0, 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return tip, seq, deleteAfter, true
}

// rotateStored rotates c and stores its new key history, as a pushed or
// registered rotation leaves it.
func rotateStored(t *testing.T, s *Store, c *identity.Controller) {
	t.Helper()
	kel := c.KEL()
	if err := identitytest.Rotate(c, max(kel[len(kel)-1].Event.Timestamp+1, uint64(time.Now().UnixMilli()))); err != nil {
		t.Fatal(err)
	}
	raw, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutAgent(c.AID(), "agent", nil, raw); err != nil {
		t.Fatal(err)
	}
}

// TestFirstVerifyRowDeletedAfterNotAfterPlus7d (H-40, HPP PAY-L2): the first
// whole verification writes one record, at the key state that signed, the
// tip, deleted by the ledger janitor 7 days after the authorization's
// NotAfter and not before, the same round as its settlement.
func TestFirstVerifyRowDeletedAfterNotAfterPlus7d(t *testing.T) {
	s, hub, payer, payee := settlementStore(t)
	network := payment.CreditNetwork(hub.AID())
	now := time.Now().UnixMilli()
	a := &payment.Authorization{PayTo: payee.AID(), Amount: 5, Network: network, Nonce: "n-row",
		IssuedAt: now - 1000, NotAfter: now + 60_000}
	if err := a.Sign(payer); err != nil {
		t.Fatal(err)
	}
	id, _ := a.ID()
	req := &payment.PaymentRequirements{Scheme: payment.SchemeCredit, Network: network,
		Amount: payment.Amount(5), Asset: payment.AssetCredit, PayTo: payee.AID()}
	if v := s.VerifyWithRequirements(hub.AID(), payloadFor(t, a), req); !v.IsValid {
		t.Fatalf("verify: %+v", v)
	}
	tip, seq, deleteAfter, ok := firstVerifyRow(t, s, id)
	if !ok || !tip || uint64(seq) != a.Envelope.KeyStateSeq || deleteAfter != a.NotAfter+7*24*3600*1000 {
		t.Fatalf("record %v %v %d %d, want the tip at seq %d, deleted at NotAfter + 7 days", ok, tip, seq, deleteAfter,
			a.Envelope.KeyStateSeq)
	}
	// A second verification keeps the first record.
	rotateStored(t, s, payer)
	if v := s.VerifyWithRequirements(hub.AID(), payloadFor(t, a), req); !v.IsValid {
		t.Fatalf("verify again after the rotation: %+v", v)
	}
	if out := s.SettleWithRequirements(hub.AID(), payloadFor(t, a), req); !out.Success {
		t.Fatalf("settle: %+v", out)
	}
	at := time.UnixMilli(deleteAfter)
	if _, err := s.pruneLedgerAt(at.Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := firstVerifyRow(t, s, id); !ok {
		t.Fatal("deleted before NotAfter + 7 days")
	}
	n, err := s.pruneLedgerAt(at)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := firstVerifyRow(t, s, id); ok || n["x402_first_verify"] != 1 || n["credit_settled"] != 1 {
		t.Errorf("at NotAfter + 7 days: record kept %v, deleted %v; want it gone with its settlement", ok, n)
	}
}

// firstVerifyDeleteAfter does not overflow for a NotAfter near the end of
// int64 (no such authorization passes the window check, but the arithmetic
// does not rely on it).
func TestFirstVerifyDeleteAfterSaturates(t *testing.T) {
	const week = int64(7 * 24 * time.Hour / time.Millisecond)
	const top = int64(1<<63 - 1)
	for _, c := range []struct{ notAfter, want int64 }{
		{1, 1 + week},
		{top - week, top},
		{top - week + 1, top},
		{top, top},
	} {
		if got := firstVerifyDeleteAfter(c.notAfter); got != c.want {
			t.Errorf("firstVerifyDeleteAfter(%d) = %d, want %d", c.notAfter, got, c.want)
		}
	}
}

// H-40 for the two doors the HTTP tests leave: a payment forwarded by a peer
// hub (SettleForPeer, /fed/v3/settle) and a redemption (Redeem). The first
// attempt is refused for want of credit and records the first verification
// at the tip; after the payer rotates and is funded, the same payment
// settles. A payment signed by the payer's old key and first shown after the
// rotation is refused.
func TestTheOtherDoorsJudgeTheKeyAtTheFirstVerification(t *testing.T) {
	for _, door := range []string{"fed", "redeem"} {
		t.Run(door, func(t *testing.T) {
			s, hub, payer, _ := settlementStore(t)
			network := payment.CreditNetwork(hub.AID())
			peer, _ := identitytest.Hub()
			foreign, _ := identitytest.Hub() // a payee that banks on the peer
			payTo := foreign.AID()
			if door == "redeem" {
				payTo = hub.AID()
			}
			now := time.Now().UnixMilli()
			sign := func(c *identity.Controller, nonce string, amount uint64) *payment.Authorization {
				a := &payment.Authorization{PayTo: payTo, Amount: amount, Network: network, Nonce: nonce,
					IssuedAt: now - 1000, NotAfter: now + 60_000}
				if err := a.Sign(c); err != nil {
					t.Fatal(err)
				}
				return a
			}
			pay := func(a *payment.Authorization) (bool, string) {
				p := payloadFor(t, a)
				if door == "redeem" {
					_, err := s.Redeem(hub.AID(), p, "ref")
					var rf *Refusal
					if errors.As(err, &rf) {
						return false, rf.Reason
					}
					return err == nil, ""
				}
				req := &payment.PaymentRequirements{Scheme: payment.SchemeCredit, Network: network,
					Amount: payment.Amount(a.Amount), Asset: payment.AssetCredit, PayTo: payTo}
				out := s.SettleForPeer(hub.AID(), peer.AID(), p, req)
				return out.Success, out.ErrorReason
			}
			first := sign(payer, "n-first", 600) // the payer holds 500
			late := sign(payer, "n-late", 5)     // with the key the payer is about to rotate away from
			if ok, why := pay(first); ok || why != payment.ReasonInsufficientFunds {
				t.Fatalf("first attempt: %v %s, want insufficient_funds", ok, why)
			}
			id, _ := first.ID()
			if tip, _, _, ok := firstVerifyRow(t, s, id); !ok || !tip {
				t.Fatalf("the refused attempt recorded %v %v, want the first verification at the tip", ok, tip)
			}
			rotateStored(t, s, payer)
			if err := s.Credit(payer.AID(), 100, "test grant"); err != nil {
				t.Fatal(err)
			}
			if ok, why := pay(first); !ok {
				t.Errorf("after the rotation, the payment first verified at the tip: refused %s", why)
			}
			if ok, why := pay(late); ok || why != payment.ReasonInvalidSignature {
				t.Errorf("a payment by the old key first shown after the rotation: %v %s, want invalid_signature", ok, why)
			}
		})
	}
}
