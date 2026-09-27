//go:build !no_federation

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// Cross-hub settlement through the real wiring: hub A (the entry hub, the
// payee's) forwards to hub B (the ledger hub, the payer's) with
// peerSettler and federation.SettleAtPeer, as the hub binary does
// (A2A-DESIGN §8.5).

// ledgerHub is hub B with a hook in front of its /x402/settle and
// /hub/identity, to count and capture what reaches it and to lose replies.
type ledgerHub struct {
	store *aghub.Store
	id    *hubid.Identity
	url   string

	mu     sync.Mutex
	bodies [][]byte
	// settleHook, when set, handles /x402/settle instead of the hub; next
	// is the hub's own handler.
	settleHook func(w http.ResponseWriter, r *http.Request, next http.Handler)
	// identityDown makes /hub/identity answer 500.
	identityDown bool
}

func (h *ledgerHub) calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.bodies)
}

func (h *ledgerHub) lastBody() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.bodies[len(h.bodies)-1]
}

type crossHubRig struct {
	a      *aghub.Store
	aID    *hubid.Identity
	aURL   string
	b      *ledgerHub
	payer  *identity.Controller // banks on B
	payee  *identity.Controller // banks on A
	other  *identity.Controller // banks on A
	netB   string
	stores []*aghub.Store
}

func putAgent(t *testing.T, s *aghub.Store, c *identity.Controller) {
	t.Helper()
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutAgent(c.AID(), "agent", nil, kel); err != nil {
		t.Fatal(err)
	}
}

func newCrossHubRig(t *testing.T) *crossHubRig {
	t.Helper()
	// Hub B, the ledger hub.
	dirB := t.TempDir()
	storeB, err := aghub.Open(dirB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storeB.Close() })
	idB, err := hubid.LoadOrIncept(dirB)
	if err != nil {
		t.Fatal(err)
	}
	storeB.SetHubKey(idB.Ctrl)
	srvB := aghub.NewServer(storeB)
	srvB.SetHubAID(idB.AID)
	b := &ledgerHub{store: storeB, id: idB}
	kernelB := srvB.Handler()
	identityB := idB.Handler()
	httpB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hub/identity":
			b.mu.Lock()
			down := b.identityDown
			b.mu.Unlock()
			if down {
				http.Error(w, "unavailable", http.StatusInternalServerError)
				return
			}
			identityB.ServeHTTP(w, r)
		case "/x402/settle":
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			b.mu.Lock()
			b.bodies = append(b.bodies, body)
			hook := b.settleHook
			b.mu.Unlock()
			if hook != nil {
				hook(w, r, kernelB)
				return
			}
			kernelB.ServeHTTP(w, r)
		default:
			kernelB.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(httpB.Close)
	b.url = httpB.URL

	// Hub A, the entry hub, federated with B the way main.go wires it.
	dirA := t.TempDir()
	storeA, err := aghub.Open(dirA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storeA.Close() })
	idA, err := hubid.LoadOrIncept(dirA)
	if err != nil {
		t.Fatal(err)
	}
	storeA.SetHubKey(idA.Ctrl)
	srvA := aghub.NewServer(storeA)
	srvA.SetHubAID(idA.AID)
	fedA, err := federation.New(dirA, federation.Config{Delivery: "allowlist",
		Peers: []federation.Peer{{AID: idB.AID, Endpoint: httpB.URL}}}, idA, storeDelivery{storeA})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fedA.Close() })
	storeA.SetClearablePeers(fedA.PeerAIDs)
	storeA.SetPeerSettler(peerSettler(storeA, fedA))
	httpA := httptest.NewServer(srvA.Handler())
	t.Cleanup(httpA.Close)

	r := &crossHubRig{a: storeA, aID: idA, aURL: httpA.URL, b: b, netB: payment.CreditNetwork(idB.AID)}
	r.payer, _ = identity.Incept()
	r.payee, _ = identity.Incept()
	r.other, _ = identity.Incept()
	putAgent(t, storeB, r.payer)
	putAgent(t, storeA, r.payee)
	putAgent(t, storeA, r.other)
	if err := storeB.Credit(r.payer.AID(), 1000, "test grant"); err != nil {
		t.Fatal(err)
	}
	return r
}

// pay is the payer's payload on B's ledger.
func (r *crossHubRig) pay(t *testing.T, payTo string, amount uint64, bind, nonce string) *payment.PaymentPayload {
	t.Helper()
	now := time.Now().UnixMilli()
	a := &payment.Authorization{PayTo: payTo, Amount: amount, Network: r.netB, Nonce: nonce,
		IssuedAt: now - 1000, NotAfter: now + 5*60_000, InteractionID: bind}
	if err := a.Sign(r.payer); err != nil {
		t.Fatal(err)
	}
	raw, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &payment.PaymentPayload{X402Version: payment.Version,
		Accepted: payment.PaymentOption{Scheme: payment.SchemeCredit, Network: r.netB,
			Amount: payment.Amount(amount), Asset: payment.AssetCredit, PayTo: payTo},
		Payload: map[string]any{"authorization": base64.StdEncoding.EncodeToString(raw)}}
}

func (r *crossHubRig) requires(payTo string, amount uint64) *payment.PaymentRequirements {
	return &payment.PaymentRequirements{Scheme: payment.SchemeCredit, Network: r.netB,
		Amount: payment.Amount(amount), Asset: payment.AssetCredit, PayTo: payTo}
}

// settle is the merchant (the payee's daemon) calling its own hub, A.
func settleAt(t *testing.T, url string, p *payment.PaymentPayload, req *payment.PaymentRequirements) payment.SettlementResponse {
	t.Helper()
	body, err := json.Marshal(payment.FacilitatorRequest{X402Version: payment.Version,
		PaymentPayload: p, PaymentRequirements: req})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url+"/x402/settle", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out payment.SettlementResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func mustBalance(t *testing.T, s *aghub.Store, aid string) int64 {
	t.Helper()
	n, err := s.Balance(aid)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A correct cross-hub payment is checked at both hubs, forwarded with its
// requirements, and credits the payee exactly once, including when the
// merchant repeats it (A2A-DESIGN §8.5; memory note: one payment, one
// credit). Underpayment and a payment to somebody else are refused at the
// entry hub and never reach the ledger hub; the ledger hub refuses them
// too when asked directly.
func TestACrossHubPaymentIsCheckedAtBothHubsAndCreditedOnce(t *testing.T) {
	r := newCrossHubRig(t)

	// Refused at the entry hub, not forwarded.
	for _, c := range []struct {
		name   string
		p      *payment.PaymentPayload
		reason string
	}{
		{"underpayment", r.pay(t, r.payee.AID(), 50, "", "under"), payment.ReasonInvalidAmount},
		{"another payee", r.pay(t, r.other.AID(), 120, "", "elsewhere"), payment.ReasonPayeeMismatch},
	} {
		out := settleAt(t, r.aURL, c.p, r.requires(r.payee.AID(), 120))
		if out.Success || out.ErrorReason != c.reason {
			t.Errorf("%s at the entry hub: %+v, want %s", c.name, out, c.reason)
		}
		// The ledger hub, asked directly with the same requirements, refuses
		// it as well: its check does not depend on the entry hub's.
		direct := settleAt(t, r.b.url, c.p, r.requires(r.payee.AID(), 120))
		if direct.Success || direct.ErrorReason != c.reason {
			t.Errorf("%s at the ledger hub: %+v, want %s", c.name, direct, c.reason)
		}
	}
	if n := r.b.calls(); n != 2 {
		t.Fatalf("the ledger hub saw %d settle requests; want only the 2 sent to it directly", n)
	}
	if got := mustBalance(t, r.b.store, r.payer.AID()); got != 1000 {
		t.Fatalf("a refused payment moved the payer's credit: %d", got)
	}

	// The correct payment.
	p := r.pay(t, r.payee.AID(), 120, "bind-x", "good")
	req := r.requires(r.payee.AID(), 120)
	out := settleAt(t, r.aURL, p, req)
	if !out.Success {
		t.Fatalf("a correct cross-hub payment: %+v", out)
	}
	// What was forwarded is the x402 v2 body with the requirements.
	var fwd map[string]json.RawMessage
	if err := json.Unmarshal(r.b.lastBody(), &fwd); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(fwd))
	for k := range fwd {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "paymentPayload,paymentRequirements,x402Version" {
		t.Errorf("forwarded body keys = %v", keys)
	}
	var fwdReq payment.PaymentRequirements
	if err := json.Unmarshal(fwd["paymentRequirements"], &fwdReq); err != nil ||
		fwdReq.PayTo != r.payee.AID() || fwdReq.Amount != "120" || fwdReq.Network != r.netB {
		t.Errorf("forwarded requirements = %s", fwd["paymentRequirements"])
	}

	check := func(stage string) {
		t.Helper()
		if got := mustBalance(t, r.a, r.payee.AID()); got != 120 {
			t.Errorf("%s: payee balance on A = %d, want 120 (one credit)", stage, got)
		}
		if got := mustBalance(t, r.b.store, r.payer.AID()); got != 880 {
			t.Errorf("%s: payer balance on B = %d, want 880", stage, got)
		}
		if owed, _ := r.a.Owed(r.b.id.AID); owed != 120 {
			t.Errorf("%s: A records B owing %d, want 120", stage, owed)
		}
		if due, _ := r.b.store.Due(); due[r.payee.AID()] != 120 {
			t.Errorf("%s: B records %d due to the payee, want 120", stage, due[r.payee.AID()])
		}
		// Neither hub created credit: A's supply grew by what B's fell.
		supA, _ := r.a.Supply(r.aID.AID)
		if supA.Outstanding != supA.Balances {
			t.Errorf("%s: A's ledger does not balance: %+v", stage, supA)
		}
	}
	check("after the payment")

	// The merchant repeats it: the same answer, no second credit.
	again := settleAt(t, r.aURL, p, req)
	if !again.Success || again.Transaction != out.Transaction {
		t.Errorf("repeat: %+v", again)
	}
	check("after the repeat")

	// A second authorization for the same binding is refused by the ledger
	// hub and the refusal reaches the merchant unchanged.
	second := settleAt(t, r.aURL, r.pay(t, r.payee.AID(), 120, "bind-x", "good-2"), req)
	if second.Success || second.ErrorReason != payment.ReasonDuplicateBinding {
		t.Errorf("second authorization for one binding: %+v, want %s", second, payment.ReasonDuplicateBinding)
	}
	check("after the duplicate")
}

// An unknown outcome is settlement_pending, and the merchant's retry with
// the same payload completes it with one credit: when the ledger hub
// cannot be reached, when it settled and the reply was lost, and when it
// settled and the entry hub could not yet verify its receipt (C25).
func TestACrossHubSettlementWithAnUnknownOutcomeIsPendingAndCompletesOnRetry(t *testing.T) {
	r := newCrossHubRig(t)
	req := r.requires(r.payee.AID(), 100)
	payee := func() int64 { return mustBalance(t, r.a, r.payee.AID()) }
	payer := func() int64 { return mustBalance(t, r.b.store, r.payer.AID()) }

	// 1. The ledger hub's key history cannot be fetched on first use, so its
	// receipt cannot be verified. It has settled; the payee is not credited
	// yet; the receipt is kept in the answer.
	r.b.mu.Lock()
	r.b.identityDown = true
	r.b.mu.Unlock()
	p1 := r.pay(t, r.payee.AID(), 100, "bind-1", "kel-down")
	out := settleAt(t, r.aURL, p1, req)
	if out.Success || out.ErrorReason != payment.ReasonSettlementPending {
		t.Fatalf("receipt unverifiable: %+v, want %s", out, payment.ReasonSettlementPending)
	}
	if rec, _ := out.Extensions[payment.ExtReceipt].(string); rec == "" {
		t.Error("the pending answer does not keep the ledger hub's receipt")
	}
	if payer() != 900 || payee() != 0 {
		t.Fatalf("after the unverifiable receipt: payer %d payee %d, want 900 and 0", payer(), payee())
	}
	r.b.mu.Lock()
	r.b.identityDown = false
	r.b.mu.Unlock()
	if out := settleAt(t, r.aURL, p1, req); !out.Success {
		t.Fatalf("retry after the key history is back: %+v", out)
	}
	if payer() != 900 || payee() != 100 {
		t.Fatalf("after the retry: payer %d payee %d, want 900 and 100", payer(), payee())
	}

	// 2. The ledger hub settles and the reply is lost.
	r.b.mu.Lock()
	r.b.settleHook = func(w http.ResponseWriter, req *http.Request, next http.Handler) {
		next.ServeHTTP(httptest.NewRecorder(), req)
		http.Error(w, "<html>bad gateway</html>", http.StatusBadGateway)
	}
	r.b.mu.Unlock()
	p2 := r.pay(t, r.payee.AID(), 100, "bind-2", "reply-lost")
	if out := settleAt(t, r.aURL, p2, req); out.Success || out.ErrorReason != payment.ReasonSettlementPending {
		t.Fatalf("reply lost: %+v, want %s", out, payment.ReasonSettlementPending)
	}
	if payer() != 800 || payee() != 100 {
		t.Fatalf("after the lost reply: payer %d payee %d, want 800 and 100", payer(), payee())
	}
	r.b.mu.Lock()
	r.b.settleHook = nil
	r.b.mu.Unlock()
	if out := settleAt(t, r.aURL, p2, req); !out.Success || out.Extensions[payment.ExtReplayed] != true {
		t.Fatalf("retry after the lost reply: %+v, want the ledger hub's original success", out)
	}
	if out := settleAt(t, r.aURL, p2, req); !out.Success {
		t.Fatalf("a second retry: %+v", out)
	}
	if payer() != 800 || payee() != 200 {
		t.Fatalf("after the retries: payer %d payee %d, want 800 and 200", payer(), payee())
	}

	// 3. The ledger hub cannot be reached at all: nothing settled there.
	r.b.mu.Lock()
	r.b.settleHook = func(w http.ResponseWriter, _ *http.Request, _ http.Handler) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}
	r.b.mu.Unlock()
	p3 := r.pay(t, r.payee.AID(), 100, "bind-3", "unreachable")
	if out := settleAt(t, r.aURL, p3, req); out.Success || out.ErrorReason != payment.ReasonSettlementPending {
		t.Fatalf("unreachable: %+v, want %s", out, payment.ReasonSettlementPending)
	}
	if payer() != 800 || payee() != 200 {
		t.Fatalf("after the unreachable attempt: payer %d payee %d, want 800 and 200", payer(), payee())
	}
	r.b.mu.Lock()
	r.b.settleHook = nil
	r.b.mu.Unlock()
	if out := settleAt(t, r.aURL, p3, req); !out.Success {
		t.Fatalf("retry once reachable: %+v", out)
	}
	if payer() != 700 || payee() != 300 {
		t.Fatalf("at the end: payer %d payee %d, want 700 and 300", payer(), payee())
	}
	if owed, _ := r.a.Owed(r.b.id.AID); owed != 300 {
		t.Errorf("A records B owing %d, want 300", owed)
	}
}

// A ledger hub answer that is JSON but not a facilitator answer, such as
// an error body `{"error": ...}` from a server-side failure, says nothing
// about whether the payment settled. It is settlement_pending, not a
// refusal with an empty errorReason, and the retry completes it with one
// credit.
func TestAnAnswerWithoutAReasonIsPending(t *testing.T) {
	r := newCrossHubRig(t)
	req := r.requires(r.payee.AID(), 70)
	r.b.mu.Lock()
	r.b.settleHook = func(w http.ResponseWriter, req *http.Request, next http.Handler) {
		next.ServeHTTP(httptest.NewRecorder(), req) // the ledger hub settles
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	}
	r.b.mu.Unlock()
	p := r.pay(t, r.payee.AID(), 70, "bind-noreason", "noreason")
	out := settleAt(t, r.aURL, p, req)
	if out.Success || out.ErrorReason != payment.ReasonSettlementPending {
		t.Fatalf("an answer with no reason: %+v, want %s", out, payment.ReasonSettlementPending)
	}
	r.b.mu.Lock()
	r.b.settleHook = nil
	r.b.mu.Unlock()
	if out := settleAt(t, r.aURL, p, req); !out.Success {
		t.Fatalf("the retry: %+v", out)
	}
	if got := mustBalance(t, r.a, r.payee.AID()); got != 70 {
		t.Errorf("payee balance %d, want 70", got)
	}
	if got := mustBalance(t, r.b.store, r.payer.AID()); got != 930 {
		t.Errorf("payer balance %d, want 930", got)
	}
}
