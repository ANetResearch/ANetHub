package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// The A2A card stream (A2A-DESIGN §10.6): /fed/v3/cards, signed by a peer,
// format dispatch, and peers that do not serve it.

var b64u = base64.RawURLEncoding.EncodeToString

// TestFedCardsV3 (sealed-sender §2.8, core §2.12.2): the card stream is
// served to the peers of the discovery sub-plane only, each request signed
// for fed_cards (no signature: 401 unauthorized; a hub that is not a peer:
// 403 not_peer; a signature for another action: 401); its binary values are
// base64url; an entry carries the witness notice of the KEL's tip as
// key_state_notice when the home hub holds one, and the pulling hub hands
// the notice to its kernel with the card.
func TestFedCardsV3(t *testing.T) {
	card := json.RawMessage(`{"name":"A2A agent"}`)
	source := &fakeDirectory{a2a: []FedA2ACardView{
		{Format: FormatA2ACard, Card: card, KEL: []byte("kel\xff\xfe"), Keys: []byte("keys\xfb"), Notice: []byte("notice\xfc"), FedSeq: 1},
		{Format: FormatA2ACard, Card: card, KEL: []byte("kel2"), FedSeq: 2},
	}}
	sink := &fakeDirectory{}
	a, b := discoveryPair(t, source, sink)

	// No signature, a stranger, another action.
	unsigned, _ := http.NewRequest(http.MethodGet, a.srv.URL+"/fed/v3/cards", nil)
	unsigned.Header.Set(wire3.Header, "3")
	if code, body, _ := do(t, unsigned); code != http.StatusUnauthorized || reasonOf(body) != "unauthorized" {
		t.Fatalf("an unsigned request: %d %s", code, body)
	}
	stranger := newTestHub(t)
	if code, body, _ := do(t, a.signedReq(stranger.id, relayauth.ActionFedCards, http.MethodGet, "/fed/v3/cards", nil, 0, nil)); code != http.StatusForbidden || reasonOf(body) != "not_peer" {
		t.Fatalf("a stranger's request: %d %s", code, body)
	}
	if code, body, _ := do(t, a.signedReq(b.id, relayauth.ActionFedBucket, http.MethodGet, "/fed/v3/cards", nil, 0, nil)); code != http.StatusUnauthorized {
		t.Fatalf("a request signed for fed_bucket: %d %s", code, body)
	}

	// The wire shape, as the peer reads it.
	code, _, raw := pageOf(t, a, b.id, 0)
	if code != http.StatusOK {
		t.Fatalf("GET /fed/v3/cards: %d %s", code, raw)
	}
	var page struct {
		Cursor int64            `json:"cursor"`
		Cards  []map[string]any `json:"cards"`
	}
	if err := json.Unmarshal(raw, &page); err != nil || len(page.Cards) != 2 || page.Cursor != 2 {
		t.Fatalf("page: %v %s", err, raw)
	}
	first := page.Cards[0]
	if first["kel"] != b64u([]byte("kel\xff\xfe")) || first["keys"] != b64u([]byte("keys\xfb")) ||
		first["key_state_notice"] != b64u([]byte("notice\xfc")) {
		t.Fatalf("the binary members are not base64url: %v", first)
	}
	if _, has := page.Cards[1]["key_state_notice"]; has {
		t.Errorf("an entry without a notice carries key_state_notice: %v", page.Cards[1])
	}
	if _, has := page.Cards[1]["keys"]; has {
		t.Errorf("an entry without keys carries keys: %v", page.Cards[1])
	}

	// The pulling hub.
	if admitted, refused := b.SyncOnce(tick(context.Background())); admitted != 2 || refused != 0 {
		t.Fatalf("admitted %d refused %d", admitted, refused)
	}
	got := sink.gotA2A[0]
	if string(got.KEL) != "kel\xff\xfe" || string(got.Keys) != "keys\xfb" || string(got.Notice) != "notice\xfc" {
		t.Fatalf("handed to the kernel: %+v", got)
	}
	if sink.gotA2A[1].Notice != nil || sink.gotA2A[1].Keys != nil {
		t.Fatalf("an entry without a notice or keys was handed over with one: %+v", sink.gotA2A[1])
	}
}

// A peer's entry whose kel is not base64url is refused, and one whose keys
// or notice are not is admitted without them: they are advisory.
func TestFedCardsV3ReadsOnlyBase64URL(t *testing.T) {
	entries := []FedA2ACardEntry{
		{Format: FormatA2ACard, Card: json.RawMessage(`{}`), KEL: base64.StdEncoding.EncodeToString([]byte("kel\xff\xfe")), Home: "https://x.example", FedSeq: 1},
		{Format: FormatA2ACard, Card: json.RawMessage(`{}`), KEL: b64u([]byte("kel")), Keys: "a+b/", KeyStateNotice: "c==", Home: "https://x.example", FedSeq: 2},
	}
	peer := newTestHub(t)
	peer.mu.Lock()
	peer.h = stampWire(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hub/identity" {
			peer.id.Handler().ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusOK, FedA2ACardPage{Cursor: 2, Cards: entries})
	})
	peer.mu.Unlock()
	sink := &fakeDirectory{}
	b := newTestHub(t).start(Config{Discovery: "allowlist", Home: "https://b.example", Peers: []Peer{peer.peer()}}, sink)
	if admitted, refused := b.SyncOnce(tick(context.Background())); admitted != 1 || refused != 1 {
		t.Fatalf("admitted %d refused %d, want 1 and 1", admitted, refused)
	}
	if got := sink.gotA2A[0]; got.FedSeq != 2 || got.Keys != nil || got.Notice != nil || string(got.KEL) != "kel" {
		t.Fatalf("handed over: %+v", got)
	}
}

// An entry carries format, card, kel, keys, home and fed_seq; the pulling
// hub hands the kernel the entries in the formats it knows, skips any
// other, and moves its cursor past all of them.
func TestTheA2ACardStreamDispatchesByFormat(t *testing.T) {
	card := json.RawMessage(`{"name":"A2A agent"}`)
	withdrawal := json.RawMessage(`{"action":"withdraw","agent_id":"did:anet:gone"}`)
	source := &fakeDirectory{a2a: []FedA2ACardView{
		{Format: FormatA2ACard, Card: card, KEL: []byte("kel"), Keys: []byte("keys"), FedSeq: 1},
		{Format: "a2a-card/9", Card: card, KEL: []byte("kel"), FedSeq: 2},
		{Format: FormatWithdrawal, Card: withdrawal, FedSeq: 3},
	}}
	sink := &fakeDirectory{}
	a, b := discoveryPair(t, source, sink)

	code, page, raw := pageOf(t, a, b.id, 0)
	if code != http.StatusOK || len(page.Cards) != 3 || page.Cursor != 3 {
		t.Fatalf("GET /fed/v3/cards: %d %s", code, raw)
	}
	first := page.Cards[0]
	if first.Format != FormatA2ACard || first.Home != "https://hub-a.example" ||
		first.KEL != b64u([]byte("kel")) || first.Keys != b64u([]byte("keys")) || first.FedSeq != 1 {
		t.Fatalf("card entry: %+v", first)
	}
	var obj map[string]any
	if json.Unmarshal(first.Card, &obj) != nil {
		t.Fatalf("the card is not carried as a JSON object: %s", first.Card)
	}
	if page.Cards[2].KEL != "" {
		t.Errorf("a withdrawal carries a kel: %+v", page.Cards[2])
	}

	admitted, refused := b.SyncOnce(tick(context.Background()))
	if admitted != 2 || refused != 0 {
		t.Fatalf("admitted %d refused %d, want 2 and 0", admitted, refused)
	}
	if len(sink.gotA2A) != 2 || sink.gotA2A[0].Format != FormatA2ACard || sink.gotA2A[1].Format != FormatWithdrawal {
		t.Fatalf("handed to the kernel: %+v", sink.gotA2A)
	}
	got := sink.gotA2A[0]
	if string(got.KEL) != "kel" || string(got.Keys) != "keys" || got.Home != "https://hub-a.example" {
		t.Fatalf("card entry as handed over: %+v", got)
	}
	if c := b.peerA2ACursor(a.id.AID); c != 3 {
		t.Fatalf("cursor %d, want 3 (past the entry in an unknown format)", c)
	}
}

// A card refused for now holds the cursor just before it, so the entry is
// asked for again once the refusal stops applying.
func TestTheA2ACardStreamStallsOnARefusalForNow(t *testing.T) {
	source := &fakeDirectory{a2a: []FedA2ACardView{
		{Format: FormatA2ACard, Card: json.RawMessage(`{}`), KEL: []byte("k"), FedSeq: 4},
		{Format: FormatA2ACard, Card: json.RawMessage(`{}`), KEL: []byte("k"), FedSeq: 7},
		{Format: FormatA2ACard, Card: json.RawMessage(`{}`), KEL: []byte("k"), FedSeq: 9},
	}}
	sink := &fakeDirectory{a2aRefuseForNow: map[int64]bool{7: true}}
	a, b := discoveryPair(t, source, sink)
	if admitted, refused := b.SyncOnce(tick(context.Background())); admitted != 1 || refused != 1 {
		t.Fatalf("admitted %d refused %d", admitted, refused)
	}
	if c := b.peerA2ACursor(a.id.AID); c != 6 {
		t.Fatalf("cursor %d, want 6: the refused-for-now entry must be asked for again", c)
	}
	sink.mu.Lock()
	delete(sink.a2aRefuseForNow, 7)
	sink.mu.Unlock()
	if admitted, _ := b.SyncOnce(tick(context.Background())); admitted != 2 {
		t.Fatalf("the entry that stopped being refused was not admitted: %d", admitted)
	}
	if c := b.peerA2ACursor(a.id.AID); c != 9 {
		t.Fatalf("cursor %d, want 9", c)
	}
}

// A peer that does not serve /fed/v3/cards (404) or does not share its
// directory with this hub (403 not_peer): that is neither a refusal nor a
// cursor move, and is asked again on the next round.
func TestAPeerWithoutTheCardStreamIsNotARefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  func(b Peer) Config
	}{
		{"no stream", nil},
		{"discovery off", func(b Peer) Config { return Config{Delivery: "allowlist", Peers: []Peer{b}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, hc := newTestHub(t), newTestHub(t)
			if tc.cfg != nil {
				old.start(tc.cfg(hc.peer()), &fakeDirectory{})
			} else {
				old.mu.Lock()
				old.h = stampWire(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/hub/identity" {
						old.id.Handler().ServeHTTP(w, r)
						return
					}
					wire3.Refuse(w, wire3.ReasonNotFound)
				})
				old.mu.Unlock()
			}
			sink := &fakeDirectory{}
			c := hc.start(Config{Discovery: "allowlist", Home: "https://hub-c.example", Peers: []Peer{old.peer()}}, sink)
			for i := 0; i < 2; i++ {
				if admitted, refused := c.SyncOnce(tick(context.Background())); admitted != 0 || refused != 0 {
					t.Fatalf("round %d: admitted %d refused %d", i, admitted, refused)
				}
			}
			if cur := c.peerA2ACursor(old.id.AID); cur != 0 || len(sink.gotA2A) != 0 {
				t.Fatalf("the cursor moved (%d) or entries arrived (%d)", cur, len(sink.gotA2A))
			}
		})
	}
}

// A page is bounded by bytes: entries past the budget are left for the
// next page, and the cursor names the last entry served.
func TestTheA2ACardPageIsBoundedByBytes(t *testing.T) {
	big := json.RawMessage(`{"d":"` + strings.Repeat("x", 60<<10) + `"}`)
	kel := make([]byte, 60<<10)
	var cards []FedA2ACardView
	for i := 1; i <= a2aCardsPageEntries; i++ {
		cards = append(cards, FedA2ACardView{Format: FormatA2ACard, Card: big, KEL: kel, FedSeq: int64(i)})
	}
	a, b := discoveryPair(t, &fakeDirectory{a2a: cards}, &fakeDirectory{})
	code, page, raw := pageOf(t, a, b.id, 0)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	n := len(page.Cards)
	if n == 0 || n == a2aCardsPageEntries {
		t.Fatalf("%d entries in a page of %d large entries: the byte bound did not apply", n, a2aCardsPageEntries)
	}
	if page.Cursor != page.Cards[n-1].FedSeq {
		t.Fatalf("cursor %d, last entry %d", page.Cursor, page.Cards[n-1].FedSeq)
	}
}

// An entry's home is taken only when it is an absolute http(s) URL with a
// host, no credentials and a bounded length; any other home, like none,
// is replaced by the peer's own endpoint. The home is served as homeHub
// wherever the card names no relay interface, so it must be a hub URL.
func TestAnA2ACardEntrysHomeMustBeAHubURL(t *testing.T) {
	homes := []string{
		"https://hub-a.example",
		"",
		"javascript:alert(1)",
		"https://user:pw@hub-a.example",
		"https://hub-a.example/" + strings.Repeat("a", maxHomeURL),
		"/relative",
	}
	var entries []FedA2ACardEntry
	for i, h := range homes {
		entries = append(entries, FedA2ACardEntry{Format: FormatA2ACard, Card: json.RawMessage(`{}`),
			KEL: b64u([]byte("kel")), Home: h, FedSeq: int64(i + 1)})
	}
	peer := newTestHub(t)
	peer.mu.Lock()
	peer.h = stampWire(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hub/identity" {
			peer.id.Handler().ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusOK, FedA2ACardPage{Cursor: int64(len(entries)), Cards: entries})
	})
	peer.mu.Unlock()
	sink := &fakeDirectory{}
	b := newTestHub(t).start(Config{Discovery: "allowlist", Home: "https://hub-b.example", Peers: []Peer{peer.peer()}}, sink)
	b.SyncOnce(tick(context.Background()))
	if len(sink.gotA2A) != len(homes) {
		t.Fatalf("admitted %d entries, want %d", len(sink.gotA2A), len(homes))
	}
	for i, got := range sink.gotA2A {
		want := peer.srv.URL
		if i == 0 {
			want = homes[0]
		}
		if got.Home != want {
			t.Errorf("entry with home %.40q: handed over with home %.40q, want %q", homes[i], got.Home, want)
		}
	}
}

var _ = httptest.NewServer
