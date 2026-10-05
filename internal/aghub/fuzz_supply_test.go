package aghub

import (
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/liabtree"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// FuzzSupplyEpochs drives one hub per worker through fuzzed sequences of
// supply events (grants, redemptions, payments to a peer's agent, a peer's
// settlements cleared here), transfers, days passing, publications and the
// 14-day drop of old proofs. Its state carries across inputs, as the hub's
// does across requests (the harness convention of fuzz_harness_test.go).
// Properties (hub-payment-privacy PAY-S8):
//
//   - after every step, Σ agent balances == issued − redeemed == −(the
//     hub's row) (P-PAY-3);
//   - every publication's record is a supply epoch signed by the hub whose
//     outstanding is the root's sum and issued − redeemed at the close, and
//     every account's proof in it reaches the signed root with its balance.
func FuzzSupplyEpochs(f *testing.F) {
	f.Add([]byte{0, 40, 0, 7, 5, 200, 6, 0})
	f.Add([]byte{0, 255, 2, 30, 3, 12, 4, 99, 1, 5, 5, 170, 6, 0, 7, 0})
	f.Add([]byte{4, 1, 4, 2, 4, 3, 4, 4, 4, 5, 4, 6, 4, 7, 4, 8, 4, 9, 4, 10, 4, 11, 4, 12, 4, 13, 4, 14,
		4, 15, 4, 16, 4, 17, 4, 18, 4, 19, 4, 20, 5, 25, 6, 0})
	r := newSupplyRig(f, time.Date(2026, 2, 1, 6, 0, 0, 0, time.UTC), 5)
	hubKEL := r.store.hubKey.KEL()
	f.Fuzz(func(t *testing.T, ops []byte) {
		r.tb = t
		for i := 0; i+1 < len(ops) && i < 128; i += 2 {
			op, arg := ops[i], ops[i+1]
			who := r.agents[int(arg)%len(r.agents)]
			switch op % 8 {
			case 0:
				_ = r.store.GrantCredit(who.AID(), 1+int64(arg), "fuzz")
			case 1:
				r.pay(who, r.agents[int(arg/7)%len(r.agents)].AID(), 1+uint64(arg%32))
			case 2:
				r.pay(who, r.hubAID, 1+uint64(arg%64))
			case 3:
				r.pay(who, "did:anet:elsewhere-"+r.next(), 1+uint64(arg%64))
			case 4:
				r.clear(who.AID(), 1+uint64(arg))
			case 5:
				r.now = r.now.Add(time.Duration(arg) * time.Hour)
			case 6:
				r.publish(t, hubKEL)
			case 7:
				if err := r.store.pruneLiabilityProofsAt(r.now); err != nil {
					t.Fatal(err)
				}
			}
			r.consistent()
		}
	})
}

// publish runs the hub's check at the rig's time and, when an epoch is
// published, holds it to what it must state.
func (r *supplyRig) publish(t *testing.T, hubKEL []identity.SignedEvent) {
	t.Helper()
	sup, err := r.store.Supply(r.hubAID)
	if err != nil {
		t.Fatal(err)
	}
	e, err := r.store.publishDueAt(r.now)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if e == nil {
		return
	}
	raw, err := wire3.DecodeB64URL("record", e.Record)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := ael.UnmarshalEventRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Verify(hubKEL); err != nil {
		t.Fatalf("the epoch record does not verify: %v", err)
	}
	ep, err := ael.ParseSupplyEpoch(rec)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Outstanding != uint64(sup.Outstanding) || e.Outstanding != ep.Outstanding ||
		liabtree.Hex(ep.Root) != e.Root || ep.ToDay != e.ToDay {
		t.Fatalf("epoch %+v states %+v; outstanding at the close %d", e, ep, sup.Outstanding)
	}
	for _, c := range r.agents {
		toDay := e.ToDay
		p, err := r.store.liabilityProofAt(c.AID(), &toDay, r.now)
		if err != nil {
			t.Fatalf("the proof of %s: %v", c.AID(), err)
		}
		proof, err := p.WireProof.Parse()
		if err != nil {
			t.Fatal(err)
		}
		bal, err := r.store.Balance(c.AID())
		if err != nil {
			t.Fatal(err)
		}
		if err := liabtree.Verify(proof, ep.Root, ep.Outstanding, ep.Depth); err != nil || p.Balance != uint64(bal) ||
			p.AID != c.AID() || p.ToDay != e.ToDay {
			t.Fatalf("the proof of %s (balance %d): %+v, %v", c.AID(), bal, p.WireProof, err)
		}
	}
}
