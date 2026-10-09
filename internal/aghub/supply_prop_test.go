package aghub

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// supplyRig is a hub on a clock a test moves, with a few accounts and a peer
// hub, for driving supply events (supply_prop_test.go, fuzz_supply_test.go).
type supplyRig struct {
	tb     testing.TB
	store  *Store
	h      http.Handler
	hubAID string
	now    time.Time
	agents []*identity.Controller
	peer   *identity.Controller
	n      int // a counter for nonces and ids
}

func newSupplyRig(tb testing.TB, start time.Time, agents int) *supplyRig {
	tb.Helper()
	store, err := Open(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	srv := NewServer(store)
	srv.SetHubAID(id.AID)
	r := &supplyRig{tb: tb, store: store, h: srv.Handler(), hubAID: id.AID, now: start}
	tb.Cleanup(func() { store.Close() })
	store.clock = func() time.Time { return r.now }
	for i := 0; i < agents; i++ {
		c, err := identitytest.Hub()
		if err != nil {
			tb.Fatal(err)
		}
		kel, err := identity.MarshalKEL(c.KEL())
		if err != nil {
			tb.Fatal(err)
		}
		if err := store.PutAgent(c.AID(), "agent", nil, kel); err != nil {
			tb.Fatal(err)
		}
		r.agents = append(r.agents, c)
	}
	if r.peer, err = identitytest.Hub(); err != nil {
		tb.Fatal(err)
	}
	return r
}

func (r *supplyRig) next() string { r.n++; return strconv.Itoa(r.n) }

// pay settles amt from payer to payTo on this hub's ledger (payTo the hub:
// a redemption) and reports whether it went through.
func (r *supplyRig) pay(payer *identity.Controller, payTo string, amt uint64) bool {
	now := time.Now().UnixMilli()
	network := payment.CreditNetwork(r.hubAID)
	a := &payment.Authorization{PayTo: payTo, Amount: amt, Network: network, Nonce: "n-" + r.next(),
		IssuedAt: now - 1000, NotAfter: now + 60_000}
	if err := a.Sign(payer); err != nil {
		r.tb.Fatal(err)
	}
	raw, err := a.Marshal()
	if err != nil {
		r.tb.Fatal(err)
	}
	p := &payment.PaymentPayload{X402Version: payment.Version,
		Accepted: payment.PaymentOption{Scheme: payment.SchemeCredit, Network: network,
			Amount: payment.Amount(amt), Asset: payment.AssetCredit, PayTo: payTo},
		Payload: map[string]any{"authorization": base64.StdEncoding.EncodeToString(raw)}}
	if payTo == r.hubAID {
		_, err := r.store.Redeem(r.hubAID, p, "ref-"+r.next())
		return err == nil
	}
	if strings.HasPrefix(payTo, elsewhere) {
		// An agent of the peer: only the peer's forwarded settlement pays
		// it (/fed/v3/settle).
		return r.store.SettleForPeer(r.hubAID, r.peer.AID(), p, &p.Accepted).Success
	}
	return r.store.SettleWithRequirements(r.hubAID, p, &p.Accepted).Success
}

// elsewhere starts the AIDs of the peer's agents.
const elsewhere = "did:anet:elsewhere-"

// clear credits payTo with the peer's settlement of amt.
func (r *supplyRig) clear(payTo string, amt uint64) bool {
	rec := &payment.Receipt{AuthID: "peer-" + r.next(), Payer: "did:anet:their-user", PayTo: payTo, Amount: amt,
		Network: payment.CreditNetwork(r.peer.AID()), SettleAt: time.Now().UnixMilli()}
	if err := rec.Sign(r.peer); err != nil {
		r.tb.Fatal(err)
	}
	return r.store.ClearFromPeer(r.peer.AID(), r.peer.KEL(), rec) == nil
}

// public is the three public answers about the supply, byte for byte.
func (r *supplyRig) public() string {
	var out string
	for _, p := range []string{"/x402/supply", "/x402/issuance?from=0", "/x402/issuance/head"} {
		rec := httptest.NewRecorder()
		r.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			r.tb.Fatalf("GET %s: %d %s", p, rec.Code, rec.Body)
		}
		out += rec.Body.String()
	}
	return out
}

func (r *supplyRig) consistent() {
	r.tb.Helper()
	sup, err := r.store.Supply(r.hubAID)
	if err != nil {
		r.tb.Fatal(err)
	}
	if !sup.Consistent() {
		r.tb.Fatalf("the supply does not add up: %+v", sup)
	}
}

// P-PAY-2 (hub-payment-privacy §7.2): under a random stream of supply events,
// transfers and days passing, with the hub checking once each UTC day as
// RunSupplyEpochs does, every publication meets the rule — 20 or more
// supply events since the last, or 7 or more days — and covers the days
// from the last one to the day that just ended; and between two
// publications /x402/supply, /x402/issuance and /x402/issuance/head are the
// same bytes. P-PAY-3 holds after every step.
func TestPropEpochsFollowTheRuleAndThePublicSupplyHoldsStill(t *testing.T) {
	for seed := uint64(1); seed <= 12; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 0x5eed))
			start := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(rng.IntN(86_400)) * time.Second)
			r := newSupplyRig(t, start, 4)
			var (
				haveEvent bool
				last      int64 // last day published, or the day before the first event
				events    int
				published int
				outstand  int64
			)
			event := func(delta int64) {
				if !haveEvent {
					haveEvent, last = true, utcDay(r.now)-1
				}
				events++
				outstand += delta
			}
			checkDay := int64(-1)
			pub := r.public()
			for step := 0; step < 400; step++ {
				switch op := rng.IntN(12); {
				case op < 4: // a grant
					amt := int64(1 + rng.IntN(50))
					if r.store.GrantCredit(r.agents[rng.IntN(len(r.agents))].AID(), amt, "grant") == nil {
						event(amt)
					}
				case op == 4: // a transfer here: not a supply event
					a, b := r.agents[rng.IntN(len(r.agents))], r.agents[rng.IntN(len(r.agents))]
					r.pay(a, b.AID(), uint64(1+rng.IntN(20)))
				case op == 5: // a redemption
					amt := uint64(1 + rng.IntN(20))
					if r.pay(r.agents[rng.IntN(len(r.agents))], r.hubAID, amt) {
						event(-int64(amt))
					}
				case op == 6: // a payment to an agent on a peer
					amt := uint64(1 + rng.IntN(20))
					if r.pay(r.agents[rng.IntN(len(r.agents))], elsewhere+r.next(), amt) {
						event(-int64(amt))
					}
				case op == 7: // a peer's settlement cleared here
					amt := uint64(1 + rng.IntN(30))
					if r.clear(r.agents[rng.IntN(len(r.agents))].AID(), amt) {
						event(int64(amt))
					}
				default: // time passes
					r.now = r.now.Add(time.Duration(1+rng.IntN(40)) * time.Hour)
				}
				r.consistent()
				// The hub's check: at start, then once after each UTC midnight.
				if d := utcDay(r.now); d != checkDay {
					checkDay = d
					e, err := r.store.publishDueAt(r.now)
					if err != nil {
						t.Fatalf("step %d: %v", step, err)
					}
					due := haveEvent && d-1 > last && (events >= epochEvents || d-1-last >= epochDays)
					if (e != nil) != due {
						t.Fatalf("step %d, day %d: published %v, but due is %v (last %d, %d events)",
							step, d, e != nil, due, last, events)
					}
					if e != nil {
						if e.FromDay != uint64(last+1) || e.ToDay != uint64(d-1) || e.Seq != uint64(published) ||
							int64(e.Outstanding) != outstand {
							t.Fatalf("step %d: epoch %+v, want %d..%d seq %d outstanding %d",
								step, e, last+1, d-1, published, outstand)
						}
						published++
						last, events = d-1, 0
						if next := r.public(); next == pub {
							t.Fatalf("step %d: a publication changed nothing public", step)
						} else {
							pub = next
						}
						continue
					}
				}
				if got := r.public(); got != pub {
					t.Fatalf("step %d: the public supply changed without a publication:\n%s\n%s", step, pub, got)
				}
			}
			if published == 0 {
				t.Errorf("seed %d published nothing in 400 steps", seed)
			}
		})
	}
}
