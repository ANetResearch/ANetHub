//go:build !no_federation

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Cross-hub settlement through the real wiring: hub A (the entry hub, the
// payee's) forwards to hub B (the ledger hub, the payer's) with peerSettler
// and federation.SettleAtPeer, signed, to B's /fed/v3/settle; both hubs are
// wired from their federation.json as the binary does (wireMounts), each
// naming the other as a peer (A2A-DESIGN §8.5; hub-payment-privacy PAY-L4,
// PAY-L5).

// ledgerHub is hub B with a hook in front of its /fed/v3/settle and
// /hub/identity, to count and capture what reaches it and to lose replies.
type ledgerHub struct {
	store *aghub.Store
	id    *hubid.Identity
	url   string
	dir   string

	mu     sync.Mutex
	bodies [][]byte
	// settleHook, when set, handles /fed/v3/settle instead of the hub;
	// next is the hub's own handler.
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
	aDir   string
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

// federatedHub is one hub of the rig: its store, identity, URL and data
// directory, and the mux its modules are wired into. Its server serves
// front in front of the hub (the hooks of B), under the wire-3 contract.
type federatedHub struct {
	dir   string
	store *aghub.Store
	id    *hubid.Identity
	url   string
	root  *http.ServeMux
}

// newFederatedHub opens a hub in a new directory and serves front(root) as
// the binary serves root; front nil serves root itself.
func newFederatedHub(t *testing.T, front func(root http.Handler) http.Handler) *federatedHub {
	t.Helper()
	dir := t.TempDir()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &federatedHub{dir: dir, store: store, id: id, root: http.NewServeMux()}
	var hd http.Handler = h.root
	if front != nil {
		hd = front(h.root)
	}
	srv := httptest.NewServer(hubHandler(hd))
	t.Cleanup(srv.Close)
	h.url = srv.URL
	return h
}

// peerWith writes h's federation.json naming peer, and wires h's kernel and
// modules as main does.
func (h *federatedHub) peerWith(t *testing.T, peer *federatedHub) {
	t.Helper()
	cfg := federation.Config{Delivery: "allowlist", Discovery: "off", Witness: "off", Home: h.url,
		Peers: []federation.Peer{{AID: peer.id.AID, Endpoint: peer.url}}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "federation.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	h.store.SetHubKey(h.id.Ctrl)
	srv0 := aghub.NewServer(h.store)
	srv0.SetHubAID(h.id.AID)
	h.root.Handle("/hub/identity", h.id.Handler())
	h.root.Handle("/", srv0.Handler())
	_, closers, err := wireMounts(&hubDeps{data: h.dir, store: h.store, hubID: h.id, srv0: srv0, root: h.root})
	t.Cleanup(func() {
		for i := len(closers) - 1; i >= 0; i-- {
			_ = closers[i]()
		}
		h.store.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
}

// newCrossHubRig starts hub B, the ledger hub, and hub A, the entry hub,
// each a peer of the other. Each of with sets B's hooks before A is wired:
// A reads its peers' key histories as it starts (KEL H-15), so a B that is
// to be unreadable on A's first use of it is so from the start.
func newCrossHubRig(t *testing.T, with ...func(b *ledgerHub)) *crossHubRig {
	t.Helper()
	// Hub B, the ledger hub, with its hooks in front.
	b := &ledgerHub{}
	for _, f := range with {
		f(b)
	}
	hubB := newFederatedHub(t, func(root http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/hub/identity":
				b.mu.Lock()
				down := b.identityDown
				b.mu.Unlock()
				if down {
					http.Error(w, "unavailable", http.StatusInternalServerError)
					return
				}
			case "/fed/v3/settle":
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				b.mu.Lock()
				b.bodies = append(b.bodies, body)
				hook := b.settleHook
				b.mu.Unlock()
				if hook != nil {
					hook(w, r, root)
					return
				}
			}
			root.ServeHTTP(w, r)
		})
	})
	b.store, b.id, b.url, b.dir = hubB.store, hubB.id, hubB.url, hubB.dir
	// Hub A, the entry hub.
	hubA := newFederatedHub(t, nil)
	hubB.peerWith(t, hubA)
	hubA.peerWith(t, hubB)

	r := &crossHubRig{a: hubA.store, aID: hubA.id, aURL: hubA.url, aDir: hubA.dir, b: b,
		netB: payment.CreditNetwork(hubB.id.AID)}
	r.payer, _ = identitytest.Hub()
	r.payee, _ = identitytest.Hub()
	r.other, _ = identitytest.Hub()
	putAgent(t, b.store, r.payer)
	putAgent(t, r.a, r.payee)
	putAgent(t, r.a, r.other)
	if err := b.store.Credit(r.payer.AID(), 1000, "test grant"); err != nil {
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
	hreq, err := http.NewRequest(http.MethodPost, url+"/x402/settle", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("X-ANet-Wire", strconv.Itoa(aghub.WireVersion))
	resp, err := http.DefaultClient.Do(hreq)
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
// requirements, signed, and credits the payee exactly once, including when
// the merchant repeats it (A2A-DESIGN §8.5; one payment, one credit).
// Underpayment and a payment to somebody else are refused at the entry hub
// and never reach the ledger hub. The ledger hub, asked directly at its
// /x402/settle, settles no payment for a payee it does not keep
// (payee_not_local; red-team N9): only a peer's signed /fed/v3/settle does,
// and what left its ledger is then owed to that peer (hub_due by peer,
// PAY-L4), which anet-hub due lists and anet-hub clear pays.
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
		// The ledger hub, asked directly, refuses it as well: the payee is
		// not one of its accounts.
		direct := settleAt(t, r.b.url, c.p, r.requires(r.payee.AID(), 120))
		if direct.Success || direct.ErrorReason != payment.ReasonPayeeNotLocal {
			t.Errorf("%s at the ledger hub: %+v, want %s", c.name, direct, payment.ReasonPayeeNotLocal)
		}
	}
	if n := r.b.calls(); n != 0 {
		t.Fatalf("the ledger hub was forwarded %d settlement(s) the entry hub refused", n)
	}
	if got := mustBalance(t, r.b.store, r.payer.AID()); got != 1000 {
		t.Fatalf("a refused payment moved the payer's credit: %d", got)
	}

	// The correct payment, presented to the ledger hub directly by anyone
	// holding it: refused, nothing charged, nothing owed (N9).
	p := r.pay(t, r.payee.AID(), 120, "bind-x", "good")
	req := r.requires(r.payee.AID(), 120)
	if direct := settleAt(t, r.b.url, p, req); direct.Success || direct.ErrorReason != payment.ReasonPayeeNotLocal {
		t.Fatalf("the correct payment at the ledger hub's /x402/settle: %+v, want %s", direct, payment.ReasonPayeeNotLocal)
	}
	if got := mustBalance(t, r.b.store, r.payer.AID()); got != 1000 {
		t.Fatalf("a direct settlement for a foreign payee charged the payer: %d", got)
	}
	if due, _ := r.b.store.Due(); len(due) != 0 {
		t.Fatalf("a direct settlement for a foreign payee left the ledger hub owing %v", due)
	}

	// Through the payee's hub.
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
		// B owes A, the peer that signed the forwarded request: keyed by
		// the peer hub, never by the payee (M-PAY-10).
		if due, _ := r.b.store.Due(); due[r.aID.AID] != 120 || len(due) != 1 {
			t.Errorf("%s: B records %v due, want 120 to A (%s) only", stage, due, r.aID.AID)
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

	// B's operator lists what B owes and pays part of it: anet-hub due and
	// anet-hub clear, beside the running hub. The discharge goes to A's
	// /fed/v3/clear, signed by B; A applies it and B's due falls by it.
	expectOut(t, cli(t, "en", "-data", r.b.dir, "due"), r.aID.AID+"\t120\n")
	expectOut(t, cli(t, "en", "-data", r.b.dir, "clear", r.aID.AID, "--amount", "50"),
		sentenceOf("en", "clear.ok", map[string]string{"peer": r.aID.AID, "n": "50", "m": "70"}))
	if owed, _ := r.a.Owed(r.b.id.AID); owed != 70 {
		t.Errorf("A records B owing %d after a discharge of 50, want 70", owed)
	}
	if due, _ := r.b.store.DueTo(r.aID.AID); due != 70 {
		t.Errorf("B records %d due to A after a discharge of 50, want 70", due)
	}
	// More than is due is refused before anything is signed.
	expectErr(t, cli(t, "en", "-data", r.b.dir, "clear", r.aID.AID, "--amount", "71"), 1,
		sentenceOf("en", "clear.over_due", map[string]string{"peer": r.aID.AID, "m": "70", "n": "71"}))
	if owed, _ := r.a.Owed(r.b.id.AID); owed != 70 {
		t.Errorf("a refused discharge reached A: A records B owing %d, want 70", owed)
	}
}

// An unknown outcome is settlement_pending, and the merchant's retry with
// the same payload completes it with one credit: when the ledger hub
// cannot be reached, when it settled and the reply was lost, and when it
// settled and the entry hub could not yet verify its receipt (C25).
func TestACrossHubSettlementWithAnUnknownOutcomeIsPendingAndCompletesOnRetry(t *testing.T) {
	// The ledger hub's key history cannot be read from the start, so the
	// entry hub holds none of it when it first needs it.
	r := newCrossHubRig(t, func(b *ledgerHub) { b.identityDown = true })
	req := r.requires(r.payee.AID(), 100)
	payee := func() int64 { return mustBalance(t, r.a, r.payee.AID()) }
	payer := func() int64 { return mustBalance(t, r.b.store, r.payer.AID()) }

	// 1. The ledger hub's key history cannot be fetched on first use, so its
	// receipt cannot be verified. It has settled; the payee is not credited
	// yet; the receipt is kept in the answer.
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

// A forwarded settlement that the ledger hub refused before its ledger saw
// it (its federation layer does not count this hub as a peer, or did not
// take the signature) is known not to have settled: the entry hub answers
// settlement_failed, which the merchant does not retry forever, and nothing
// is charged or credited. A busy ledger hub has not said whether it
// settled: that is settlement_pending, and the retry completes it once.
func TestAForwardRefusedBeforeTheLedgerIsFailedNotPending(t *testing.T) {
	r := newCrossHubRig(t)
	req := r.requires(r.payee.AID(), 40)
	payee := func() int64 { return mustBalance(t, r.a, r.payee.AID()) }
	payer := func() int64 { return mustBalance(t, r.b.store, r.payer.AID()) }
	refuseWith := func(reason wire3.Reason) {
		r.b.mu.Lock()
		r.b.settleHook = func(w http.ResponseWriter, _ *http.Request, _ http.Handler) { wire3.Refuse(w, reason) }
		r.b.mu.Unlock()
	}
	for _, reason := range []wire3.Reason{wire3.ReasonNotPeer, wire3.ReasonUnauthorized} {
		refuseWith(reason)
		p := r.pay(t, r.payee.AID(), 40, "bind-"+string(reason), "refused-"+string(reason))
		if out := settleAt(t, r.aURL, p, req); out.Success || out.ErrorReason != payment.ReasonSettlementFailed {
			t.Errorf("the ledger hub's federation layer answered %s: %+v, want %s", reason, out, payment.ReasonSettlementFailed)
		}
	}
	if payer() != 1000 || payee() != 0 {
		t.Fatalf("after the refusals: payer %d payee %d, want 1000 and 0", payer(), payee())
	}
	refuseWith(wire3.ReasonRateLimited)
	p := r.pay(t, r.payee.AID(), 40, "bind-busy", "busy")
	if out := settleAt(t, r.aURL, p, req); out.Success || out.ErrorReason != payment.ReasonSettlementPending {
		t.Fatalf("a busy ledger hub: %+v, want %s", out, payment.ReasonSettlementPending)
	}
	r.b.mu.Lock()
	r.b.settleHook = nil
	r.b.mu.Unlock()
	if out := settleAt(t, r.aURL, p, req); !out.Success {
		t.Fatalf("the retry once the ledger hub is not busy: %+v", out)
	}
	if payer() != 960 || payee() != 40 {
		t.Errorf("at the end: payer %d payee %d, want 960 and 40", payer(), payee())
	}
}
