package federation

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// fakeClearing stands in for the hub kernel behind the Clearing seam: it
// records what the settlement routes hand it and answers 200.
type fakeClearing struct {
	mu    sync.Mutex
	calls []clearingCall
}

type clearingCall struct {
	route, peer string
	body        string
}

func (c *fakeClearing) record(route, peer string, body []byte) {
	c.mu.Lock()
	c.calls = append(c.calls, clearingCall{route, peer, string(body)})
	c.mu.Unlock()
}

func (c *fakeClearing) ServeFedSettle(w http.ResponseWriter, peer string, body []byte) {
	c.record("settle", peer, body)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "transaction": "t-1"})
}

func (c *fakeClearing) ServeFedClear(w http.ResponseWriter, peer string, body []byte) {
	c.record("clear", peer, body)
	writeJSON(w, http.StatusOK, map[string]any{"peer": peer, "owed": 0})
}

func (c *fakeClearing) got() []clearingCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]clearingCall(nil), c.calls...)
}

// The settlement routes are /fed/v3 routes like the others (core G3;
// hub-payment-privacy PAY-L4, PAY-U2): signed by a hub of the peer table for
// fed_settle or fed_clear, and handed to the kernel with that hub's AID and
// the body it signed. A hub that is not a peer is 403 not_peer, so is every
// request while the kernel is not wired or federation is off; no signature,
// or one for the other action, is 401 unauthorized. The kernel is never
// asked about a refused request.
func TestTheSettlementRoutesTakeOnlyAPeersSignature(t *testing.T) {
	a, b, stranger := newTestHub(t), newTestHub(t), newTestHub(t)
	svc := a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, nil)
	clearing := &fakeClearing{}
	body := []byte(`{"x402Version":2}`)
	// Before the kernel is wired.
	if code, out, _ := do(t, a.signedReq(b.id, relayauth.ActionFedSettle, http.MethodPost, "/fed/v3/settle", body, 0, nil)); code != 403 ||
		reasonOf(out) != "not_peer" {
		t.Errorf("settle before the kernel is wired: %d %s", code, out)
	}
	svc.SetClearing(clearing)
	for _, c := range []struct {
		name, path, action string
		as                 *testHub
		status             int
		reason             string
	}{
		{"settle by the peer", "/fed/v3/settle", relayauth.ActionFedSettle, b, 200, ""},
		{"clear by the peer", "/fed/v3/clear", relayauth.ActionFedClear, b, 200, ""},
		{"settle by a stranger", "/fed/v3/settle", relayauth.ActionFedSettle, stranger, 403, "not_peer"},
		{"clear by a stranger", "/fed/v3/clear", relayauth.ActionFedClear, stranger, 403, "not_peer"},
		{"settle signed for fed_clear", "/fed/v3/settle", relayauth.ActionFedClear, b, 401, "unauthorized"},
		{"clear signed for fed_settle", "/fed/v3/clear", relayauth.ActionFedSettle, b, 401, "unauthorized"},
	} {
		code, out, _ := do(t, a.signedReq(c.as.id, c.action, http.MethodPost, c.path, body, 0, nil))
		if code != c.status || (c.reason != "" && reasonOf(out) != c.reason) {
			t.Errorf("%s: %d %s, want %d %s", c.name, code, out, c.status, c.reason)
		}
	}
	// Unsigned.
	req, _ := http.NewRequest(http.MethodPost, a.srv.URL+"/fed/v3/settle", strings.NewReader(string(body)))
	req.Header.Set(wire3.Header, strconv.Itoa(wire3.Version))
	if code, out, _ := do(t, req); code != http.StatusUnauthorized || reasonOf(out) != "unauthorized" {
		t.Errorf("unsigned settle: %d %s", code, out)
	}
	got := clearing.got()
	if len(got) != 2 || got[0] != (clearingCall{"settle", b.id.AID, string(body)}) ||
		got[1] != (clearingCall{"clear", b.id.AID, string(body)}) {
		t.Errorf("the kernel was handed %+v", got)
	}
	// Federation off: no peer at all.
	off := newTestHub(t)
	offSvc := off.start(Config{Delivery: "off", Peers: []Peer{b.peer()}}, nil)
	offSvc.SetClearing(clearing)
	if code, out, _ := do(t, off.signedReq(b.id, relayauth.ActionFedSettle, http.MethodPost, "/fed/v3/settle", body, 0, nil)); code != 403 ||
		reasonOf(out) != "not_peer" {
		t.Errorf("settle with federation off: %d %s", code, out)
	}
}

// SettleAtPeer forwards to the peer the network names, POST
// /fed/v3/settle, signed by this hub for fed_settle (PAY-L5): the peer's
// authPeer takes it and its kernel gets this hub's AID and the body. A
// network that is not a peer's ledger is not sent anywhere.
func TestSettleAtPeerIsASignedRequestToTheLedgersHub(t *testing.T) {
	a, b := newTestHub(t), newTestHub(t)
	svcA := a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, nil)
	svcB := b.start(Config{Delivery: "allowlist", Peers: []Peer{a.peer()}}, nil)
	clearing := &fakeClearing{}
	svcB.SetClearing(clearing)
	body := []byte(`{"x402Version":2,"paymentPayload":{}}`)
	status, answer, peer, err := svcA.SettleAtPeer(context.Background(), "hub:"+b.id.AID, body)
	if err != nil || status != http.StatusOK || peer != b.id.AID || !strings.Contains(string(answer), `"success":true`) {
		t.Fatalf("SettleAtPeer: %d %s %s %v", status, answer, peer, err)
	}
	if got := clearing.got(); len(got) != 1 || got[0] != (clearingCall{"settle", a.id.AID, string(body)}) {
		t.Errorf("the ledger hub's kernel got %+v", got)
	}
	for _, network := range []string{"hub:" + a.id.AID, "hub:did:anet:nobody", "not-a-hub"} {
		if _, _, _, err := svcA.SettleAtPeer(context.Background(), network, body); err == nil {
			t.Errorf("%s: forwarded", network)
		}
	}
	if n := b.hitsOf("/fed/v3/settle"); n != 1 {
		t.Errorf("the ledger hub saw %d settle requests, want 1", n)
	}
}

// A peer that answers replayed (its RC1 took the signing time before — the
// clock of anet-hub clear, a process beside the hub, can meet the hub's
// own) is asked once more with a new time; the request never reached its
// ledger. ClearAtPeer does so too, and sends the statement to
// /fed/v3/clear signed for fed_clear.
func TestARefusedSigningTimeIsSignedAgainOnce(t *testing.T) {
	a := newTestHub(t)
	var mu sync.Mutex
	var seen []string
	peer := httptest.NewServer(wire3.Contract(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.URL.Path+" "+r.Header.Get(relayauth.HeaderTS))
		n := len(seen)
		mu.Unlock()
		if n%2 == 1 {
			wire3.Refuse(w, wire3.ReasonReplayed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"peer": a.id.AID, "owed": 3})
	})))
	t.Cleanup(peer.Close)
	resp, err := ClearAtPeer(context.Background(), a.id, "did:anet:peer", peer.URL, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), `"owed":3`) {
		t.Errorf("ClearAtPeer: %d %s", resp.StatusCode, b)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || !strings.HasPrefix(seen[0], "/fed/v3/clear ") || !strings.HasPrefix(seen[1], "/fed/v3/clear ") ||
		seen[0] == seen[1] {
		t.Errorf("the peer saw %q, want /fed/v3/clear twice with two signing times", seen)
	}
}
