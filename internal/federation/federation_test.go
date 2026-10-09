package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"
)

// Discovery is off by default and switches independently of delivery. A
// hub may carry a peer's traffic without publishing its directory: its
// card and review streams answer a peer 403 not_peer.
func TestDiscoveryIsOffUnlessAskedFor(t *testing.T) {
	a, b := newTestHub(t), newTestHub(t)
	svc := a.start(Config{Delivery: "allowlist", Peers: []Peer{b.peer()}}, &fakeDirectory{}) // delivery on…
	if svc.DiscoveryEnabled() {
		t.Error("discovery must not follow delivery — they are separate decisions about a peer")
	}
	for _, rt := range []struct{ action, path string }{
		{relayauth.ActionFedCards, "/fed/v3/cards"},
		{relayauth.ActionFedReviews, "/fed/v3/reviews"},
	} {
		code, body, _ := do(t, a.signedReq(b.id, rt.action, http.MethodGet, rt.path, nil, 0, nil))
		if code != http.StatusForbidden || reasonOf(body) != "not_peer" {
			t.Errorf("a hub with discovery off served %s: %d %s", rt.path, code, body)
		}
	}
}

// The v0.2 federation routes are gone: /fed/v1/forward and /fed/v1/reviews,
// the ADP card stream /fed/v1/cards, /fed/v2/keys/{aid} and /fed/v2/cards
// answer 404 not_found, signed by a peer or not, whatever this hub's
// switches. /fed/v3 is the only federation path family (core G21).
func TestV1AndV2RoutesAreGone(t *testing.T) {
	a, b := newTestHub(t), newTestHub(t)
	a.start(Config{Delivery: "allowlist", Discovery: "allowlist", Home: "https://hub-a.example",
		Peers: []Peer{b.peer()}}, &fakeDirectory{})
	for _, rt := range []struct{ method, path string }{
		{http.MethodPost, "/fed/v1/forward"},
		{http.MethodGet, "/fed/v1/reviews"},
		{http.MethodGet, "/fed/v1/cards"},
		{http.MethodGet, "/fed/v2/keys/did:anet:anyone"},
		{http.MethodGet, "/fed/v2/cards"},
		{http.MethodPost, "/fed/v2/forward"},
	} {
		for _, signed := range []bool{false, true} {
			req := a.signedReq(b.id, "fedkeys", rt.method, rt.path, []byte("{}"), 0, nil)
			if !signed {
				req.Header.Del(relayauth.HeaderAID)
			}
			code, body, _ := do(t, req)
			if code != http.StatusNotFound || reasonOf(body) != "not_found" {
				t.Errorf("%s %s (signed %v): %d %s, want 404 not_found", rt.method, rt.path, signed, code, body)
			}
		}
	}
}

// A permanent refusal must NOT hold the stream, or one bad card from one
// peer wedges that peer's directory for ever.
func TestAPermanentRefusalStillAdvances(t *testing.T) {
	source := &fakeDirectory{a2a: []FedA2ACardView{
		{Format: FormatA2ACard, Card: json.RawMessage(`{"name":"bad"}`), KEL: []byte("k"), FedSeq: 1},
		{Format: FormatA2ACard, Card: json.RawMessage(`{"name":"good"}`), KEL: []byte("k"), FedSeq: 2},
	}}
	sink := &fakeDirectory{a2aRejectForever: map[int64]bool{1: true}}
	a, svcB := discoveryPair(t, source, sink)
	if admitted, refused := svcB.SyncOnce(context.Background()); admitted != 1 || refused != 1 {
		t.Errorf("a permanently bad card stopped the stream: admitted %d refused %d, want 1 and 1",
			admitted, refused)
	}
	if c := svcB.peerA2ACursor(a.id.AID); c != 2 {
		t.Errorf("cursor %d, want 2: past the card refused for good", c)
	}
}

// The cursor is an optimisation, and it can be wrong.
//
// Holding it at a transient refusal stops new entries being lost. It does
// nothing for the ones already lost — and in production there was already
// one: a card skipped before the fix existed, with the cursor sitting
// past it for ever. So a peer's directory is re-read from the start every
// so often, which heals that and every cause not yet thought of.
func TestTheDirectoryHealsWhatTheCursorSkipped(t *testing.T) {
	source := &fakeDirectory{a2a: []FedA2ACardView{
		{Format: FormatA2ACard, Card: json.RawMessage(`{"name":"a"}`), KEL: []byte("k"), FedSeq: 1},
	}}
	sink := &fakeDirectory{}
	a, svcB := discoveryPair(t, source, sink)

	svcB.SyncOnce(context.Background())
	if len(sink.gotA2A) != 1 {
		t.Fatalf("setup: admitted %d", len(sink.gotA2A))
	}
	// The entry is lost — a bad restore, an admission bug, anything. The
	// cursor is past it, so ordinary rounds will never ask again.
	sink.gotA2A = nil
	for i := 0; i < fullResyncEvery-2; i++ {
		svcB.SyncOnce(context.Background())
	}
	if len(sink.gotA2A) != 0 {
		t.Fatalf("re-read too eagerly: a full pass every round would make the cursor pointless")
	}
	// The scheduled full pass brings it back.
	svcB.SyncOnce(context.Background())
	if len(sink.gotA2A) != 1 {
		t.Errorf("the directory did not heal: admitted %d after a full resync round", len(sink.gotA2A))
	}
	if c := svcB.peerA2ACursor(a.id.AID); c != 1 {
		t.Errorf("cursor %d after the full pass, want 1", c)
	}
}

// The review stream is /fed/v3/reviews, signed by a peer for fed_reviews:
// a peer's signed request is served, and the pulling hub's sync goes
// through it and hands the reviews to its kernel.
func TestTheReviewStreamIsSignedV3(t *testing.T) {
	source := &fakeDirectory{reviews: []json.RawMessage{json.RawMessage(`{"r":1}`), json.RawMessage(`{"r":2}`)}}
	sink := &fakeDirectory{}
	a, svcB := discoveryPair(t, source, sink)
	stranger := newTestHub(t)
	if code, body, _ := do(t, a.signedReq(stranger.id, relayauth.ActionFedReviews, http.MethodGet, "/fed/v3/reviews", nil, 0, nil)); code != http.StatusForbidden || reasonOf(body) != "not_peer" {
		t.Fatalf("a stranger's request for the review stream: %d %s", code, body)
	}
	if code, body, _ := do(t, a.signedReq(svcB.id, relayauth.ActionFedCards, http.MethodGet, "/fed/v3/reviews", nil, 0, nil)); code != http.StatusUnauthorized {
		t.Fatalf("a request signed for another action: %d %s", code, body)
	}
	for _, q := range []string{"cursor=01", "cursor=-1", "cursor=1&cursor=2"} {
		if code, body, _ := do(t, a.signedReq(svcB.id, relayauth.ActionFedReviews, http.MethodGet, "/fed/v3/reviews?"+q, nil, 0, nil)); code != http.StatusBadRequest {
			t.Fatalf("%s, not one non-negative integer in canonical decimal: %d %s", q, code, body)
		}
	}
	if admitted, refused := svcB.SyncOnce(context.Background()); admitted != 2 || refused != 0 {
		t.Fatalf("admitted %d refused %d", admitted, refused)
	}
	if len(sink.gotRevs) != 2 || sink.gotRevs[0].peer != a.id.AID || string(sink.gotRevs[1].raw) != `{"r":2}` {
		t.Fatalf("reviews handed over: %+v", sink.gotRevs)
	}
	if c := svcB.peerReviewCursor(a.id.AID); c != 2 {
		t.Fatalf("review cursor %d, want 2", c)
	}
}

// A chain with exactly one record must be witnessable.
//
// WitnessOnce tested head.Seq == 0 for "nothing to pin". An AEL's first
// record is seq 0 — so a hub whose chain held only that was never
// witnessed. Live: one hub was witnessed zero times while witnessing its
// peer hourly. The head is the peer's latest supply epoch, {seq, id}; the
// attestation goes back to the peer base64url (core CORE-E5).
func TestAOneRecordChainIsStillWitnessed(t *testing.T) {
	dir := t.TempDir()
	// A peer serving a head at seq 0.
	var mu sync.Mutex
	var submitted []string
	peer := httptest.NewServer(stampWire(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/x402/issuance/head":
			_ = json.NewEncoder(w).Encode(map[string]any{"seq": 0, "id": "bafy-first-epoch"})
		case "/x402/witness":
			var body struct {
				Attestation string `json:"attestation"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			submitted = append(submitted, body.Attestation)
			mu.Unlock()
		}
	}))
	defer peer.Close()

	svc := newDiscoveryService(t, dir, Config{
		Discovery: "allowlist", Home: "https://ours.example",
		Peers: []Peer{{AID: "did:anet:peer", Endpoint: peer.URL}},
	}, &fakeDirectory{})
	w := &fakeWitness{}
	svc.SetWitness(w)

	if n := svc.WitnessOnce(context.Background()); n != 1 {
		t.Fatalf("pinned %d heads, want 1 — a one-record chain was treated as having none", n)
	}
	if len(w.pinned) != 1 || w.pinned[0].seq != 0 || w.pinned[0].headID != "bafy-first-epoch" ||
		w.pinned[0].peerAID != "did:anet:peer" {
		t.Errorf("pinned = %+v", w.pinned)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := base64.RawURLEncoding.EncodeToString([]byte("attestation")); len(submitted) != 1 || submitted[0] != want {
		t.Errorf("the peer was sent %q, want the attestation base64url %q", submitted, want)
	}
}

// A peer that has published no epoch has no head, and must not be pinned.
func TestAPeerWithNoChainIsNotWitnessed(t *testing.T) {
	dir := t.TempDir()
	peer := httptest.NewServer(stampWire(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer peer.Close()
	svc := newDiscoveryService(t, dir, Config{
		Discovery: "allowlist", Home: "https://ours.example",
		Peers: []Peer{{AID: "did:anet:peer", Endpoint: peer.URL}},
	}, &fakeDirectory{})
	w := &fakeWitness{}
	svc.SetWitness(w)
	if n := svc.WitnessOnce(context.Background()); n != 0 {
		t.Errorf("pinned %d heads for a chain that has none", n)
	}
}

// Witnessing is on by default and can be turned off.
func TestWitnessingDefaultsOnAndCanBeDisabled(t *testing.T) {
	peers := []Peer{{AID: "did:anet:peer", Endpoint: "http://unused"}}
	if !(Config{Peers: peers}).WitnessEnabled() {
		t.Error("witnessing must default on for a hub that has peers")
	}
	if (Config{Peers: peers, Witness: "off"}).WitnessEnabled() {
		t.Error(`"witness":"off" did not disable it`)
	}
	if (Config{Witness: "on"}).WitnessEnabled() {
		t.Error("a hub with no peers has nobody to witness")
	}
}

type fakeWitness struct {
	pinned []struct {
		peerAID, headID string
		seq             uint64
	}
}

func (f *fakeWitness) Attest(peerAID, headID string, seq uint64) ([]byte, error) {
	f.pinned = append(f.pinned, struct {
		peerAID, headID string
		seq             uint64
	}{peerAID, headID, seq})
	return []byte("attestation"), nil
}

// The home of a federated card is a hub URL; it names a delivery peer when
// it is that peer's endpoint, whatever the case of its scheme and host and
// with or without a trailing slash (sealed-sender SSR-H12 step 3).
func TestADeliveryPeerIsFoundByItsURL(t *testing.T) {
	a := newTestHub(t)
	peer := Peer{AID: "did:anet:peer", Endpoint: "https://Hub-B.example/"}
	svc := a.start(Config{Delivery: "allowlist", Peers: []Peer{peer}}, nil)
	for home, want := range map[string]string{
		"https://hub-b.example":     peer.AID,
		"HTTPS://HUB-B.EXAMPLE/":    peer.AID,
		"https://hub-b.example/hub": "",
		"https://hub-c.example":     "",
		"":                          "",
	} {
		if got := svc.DeliveryPeerAt(home); got != want {
			t.Errorf("DeliveryPeerAt(%q) = %q, want %q", home, got, want)
		}
	}
	off := newTestHub(t).start(Config{Delivery: "off", Peers: []Peer{peer}}, nil)
	if got := off.DeliveryPeerAt("https://hub-b.example"); got != "" {
		t.Errorf("with delivery off, %q is a delivery peer", got)
	}
}
