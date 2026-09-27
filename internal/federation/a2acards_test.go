package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// The A2A card stream (A2A-DESIGN §10.6): /fed/v2/cards alongside
// /fed/v1/cards, format dispatch, and peers that serve only v1.

// discoveryPair starts hub A serving source over HTTP and returns the
// service of hub B, which pulls from A into sink.
func discoveryPair(t *testing.T, source, sink *fakeDirectory) (a *httptest.Server, b *Service) {
	t.Helper()
	dir := t.TempDir()
	svcA := newDiscoveryService(t, filepath.Join(dir, "a"), Config{
		Discovery: "allowlist", Home: "https://hub-a.example",
		Peers: []Peer{{AID: "did:anet:b", Endpoint: "http://unused"}},
	}, source)
	a = httptest.NewServer(svcA.Handler())
	t.Cleanup(a.Close)
	b = newDiscoveryService(t, filepath.Join(dir, "b"), Config{
		Discovery: "allowlist", Home: "https://hub-b.example",
		Peers: []Peer{{AID: "did:anet:a", Endpoint: a.URL}},
	}, sink)
	return a, b
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

	// The wire shape.
	resp, err := http.Get(a.URL + "/fed/v2/cards")
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		Cursor int64            `json:"cursor"`
		Cards  []map[string]any `json:"cards"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&page)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(page.Cards) != 3 || page.Cursor != 3 {
		t.Fatalf("GET /fed/v2/cards: %d %+v", resp.StatusCode, page)
	}
	first := page.Cards[0]
	if first["format"] != FormatA2ACard || first["home"] != "https://hub-a.example" ||
		first["kel"] != base64.StdEncoding.EncodeToString([]byte("kel")) ||
		first["keys"] != base64.StdEncoding.EncodeToString([]byte("keys")) || first["fed_seq"] != float64(1) {
		t.Fatalf("card entry: %v", first)
	}
	if _, ok := first["card"].(map[string]any); !ok {
		t.Fatalf("the card is not carried as a JSON object: %v", first["card"])
	}
	if _, has := page.Cards[2]["kel"]; has {
		t.Errorf("a withdrawal carries a kel: %v", page.Cards[2])
	}

	admitted, refused := b.SyncOnce(context.Background())
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
	if c := b.peerA2ACursor("did:anet:a"); c != 3 {
		t.Fatalf("cursor %d, want 3 (past the entry in an unknown format)", c)
	}
}

// A card refused for now holds the v2 cursor just before it, as on v1.
func TestTheA2ACardStreamStallsOnARefusalForNow(t *testing.T) {
	source := &fakeDirectory{a2a: []FedA2ACardView{
		{Format: FormatA2ACard, Card: json.RawMessage(`{}`), KEL: []byte("k"), FedSeq: 4},
		{Format: FormatA2ACard, Card: json.RawMessage(`{}`), KEL: []byte("k"), FedSeq: 7},
		{Format: FormatA2ACard, Card: json.RawMessage(`{}`), KEL: []byte("k"), FedSeq: 9},
	}}
	sink := &fakeDirectory{a2aRefuseForNow: map[int64]bool{7: true}}
	_, b := discoveryPair(t, source, sink)
	if admitted, refused := b.SyncOnce(context.Background()); admitted != 1 || refused != 1 {
		t.Fatalf("admitted %d refused %d", admitted, refused)
	}
	if c := b.peerA2ACursor("did:anet:a"); c != 6 {
		t.Fatalf("cursor %d, want 6: the refused-for-now entry must be asked for again", c)
	}
	delete(sink.a2aRefuseForNow, 7)
	if admitted, _ := b.SyncOnce(context.Background()); admitted != 2 {
		t.Fatalf("the entry that stopped being refused was not admitted: %d", admitted)
	}
	if c := b.peerA2ACursor("did:anet:a"); c != 9 {
		t.Fatalf("cursor %d, want 9", c)
	}
}

// A peer that serves only /fed/v1/cards (not yet upgraded) still federates
// its ADP cards; its 404 on /fed/v2/cards is neither a refusal nor a
// cursor move. v1 and v2 are pulled side by side from an upgraded peer.
func TestV1AndV2CardStreamsAreServedAndPulledTogether(t *testing.T) {
	agentCard := []byte(`{"subject_did":"did:anet:x"}`)
	source := &fakeDirectory{
		cards: []FedCardView{{Card: agentCard, KEL: []byte("k"), FedSeq: 1}},
		a2a:   []FedA2ACardView{{Format: FormatA2ACard, Card: json.RawMessage(`{}`), KEL: []byte("k"), FedSeq: 1}},
	}
	sink := &fakeDirectory{}
	_, b := discoveryPair(t, source, sink)
	if admitted, refused := b.SyncOnce(context.Background()); admitted != 2 || refused != 0 {
		t.Fatalf("upgraded peer: admitted %d refused %d, want 2 and 0", admitted, refused)
	}
	if len(sink.got) != 1 || len(sink.gotA2A) != 1 {
		t.Fatalf("v1 %d, v2 %d entries, want one each", len(sink.got), len(sink.gotA2A))
	}

	// A peer whose build has no /fed/v2/cards.
	v1only := newDiscoveryService(t, filepath.Join(t.TempDir(), "old"), Config{
		Discovery: "allowlist", Home: "https://old.example",
		Peers: []Peer{{AID: "did:anet:b", Endpoint: "http://unused"}},
	}, source)
	full := v1only.Handler()
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/fed/v2/") {
			http.NotFound(w, r)
			return
		}
		full.ServeHTTP(w, r)
	}))
	defer old.Close()
	sink2 := &fakeDirectory{}
	c := newDiscoveryService(t, filepath.Join(t.TempDir(), "c"), Config{
		Discovery: "allowlist", Home: "https://hub-c.example",
		Peers: []Peer{{AID: "did:anet:old", Endpoint: old.URL}},
	}, sink2)
	for i := 0; i < 2; i++ {
		admitted, refused := c.SyncOnce(context.Background())
		if refused != 0 {
			t.Fatalf("round %d: a peer without /fed/v2/cards counted as refusing: %d", i, refused)
		}
		if i == 0 && admitted != 1 {
			t.Fatalf("the v1 card of a v1-only peer: admitted %d", admitted)
		}
	}
	if len(sink2.got) != 1 || len(sink2.gotA2A) != 0 {
		t.Fatalf("v1-only peer: v1 %d, v2 %d entries", len(sink2.got), len(sink2.gotA2A))
	}
	if cur := c.peerA2ACursor("did:anet:old"); cur != 0 {
		t.Fatalf("the v2 cursor moved for a peer without the stream: %d", cur)
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
	a, _ := discoveryPair(t, &fakeDirectory{a2a: cards}, &fakeDirectory{})
	resp, err := http.Get(a.URL + "/fed/v2/cards")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var page FedA2ACardPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	n := len(page.Cards)
	if n == 0 || n == a2aCardsPageEntries {
		t.Fatalf("%d entries in a page of %d large entries: the byte bound did not apply", n, a2aCardsPageEntries)
	}
	if page.Cursor != page.Cards[n-1].FedSeq {
		t.Fatalf("cursor %d, last entry %d", page.Cursor, page.Cards[n-1].FedSeq)
	}
}
