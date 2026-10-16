package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Fuzz targets of the federation v3 plane. As in the kernel's targets, an
// input carries terms and the harness signs at run time, so the fuzzer
// mutates what a peer could send rather than signatures.

// fedRoutes are the /fed/v3 routes with their methods and actions.
var fedRoutes = []struct{ method, path, action string }{
	{http.MethodPost, "/fed/v3/forward", relayauth.ActionFedForward},
	{http.MethodPost, "/fed/v3/directory:bucket", relayauth.ActionFedBucket},
	{http.MethodGet, "/fed/v3/cards", relayauth.ActionFedCards},
	{http.MethodGet, "/fed/v3/reviews", relayauth.ActionFedReviews},
}

// FuzzFedV3Routes sends fuzzed requests to the /fed/v3 routes of a hub with
// delivery and discovery on: a route (or another path), a query, a body,
// signed by the peer, by a hub that is not a peer, or not at all, for the
// route's action or another one, over the body sent or another, at a time
// off the clock by a fuzzed amount. Properties:
//
//   - the answer is a wire-3 answer and never a 5xx;
//   - the kernel (or the directory) is reached only by a request the peer
//     signed for that route's action over exactly that request, within the
//     time window, and only once for one signature (RC1);
//   - a refusal is 400, 401, 403, 404 or 413, with its G1 body.
func FuzzFedV3Routes(f *testing.F) {
	a, b, stranger := newTestHub(f), newTestHub(f), newTestHub(f)
	a.start(Config{Delivery: "allowlist", Discovery: "allowlist", Home: "https://hub-a.example", Peers: []Peer{b.peer()}},
		&fakeDirectory{a2a: []FedA2ACardView{{Format: FormatA2ACard, Card: json.RawMessage(`{}`), KEL: []byte("k"), FedSeq: 1}}})
	if _, err := a.svc.peerKEL(a.svc.peer(b.id.AID)); err != nil {
		f.Fatal(err)
	}
	h := a.h
	f.Add(uint8(0), "", []byte("envelope"), uint8(0), uint8(0), false, int64(0))
	f.Add(uint8(1), "", []byte(`{"prefix":"","bits":0}`), uint8(0), uint8(1), false, int64(0))
	f.Add(uint8(2), "cursor=1", []byte(nil), uint8(0), uint8(2), false, int64(0))
	f.Add(uint8(3), "cursor=01", []byte(nil), uint8(1), uint8(3), true, int64(-700000))
	f.Add(uint8(4), "x", []byte("{}"), uint8(2), uint8(0), false, int64(5))
	var n atomic.Uint64
	f.Fuzz(func(t *testing.T, route uint8, query string, body []byte, signer, action uint8, tamper bool, skew int64) {
		method, path := http.MethodPost, "/fed/v3/other"
		var want string
		if int(route) < len(fedRoutes) {
			method, path, want = fedRoutes[route].method, fedRoutes[route].path, fedRoutes[route].action
		}
		target := path
		if query != "" {
			if strings.ContainsAny(query, " #\x00\r\n") {
				return
			}
			target += "?" + query
		}
		req, err := http.NewRequest(method, "http://hub.test"+target, bytes.NewReader(body))
		if err != nil {
			return // not a request a client can send
		}
		req.Header.Set(wire3.Header, "3")
		acts := []string{relayauth.ActionFedForward, relayauth.ActionFedBucket, relayauth.ActionFedCards, relayauth.ActionFedReviews, "fedkeys"}
		act := acts[int(action)%len(acts)]
		ts := uint64(int64(nextTS()) + skew)
		ts += n.Add(1) % 7
		var as Peer
		switch signer % 3 {
		case 0:
			as = b.peer()
		case 1:
			as = stranger.peer()
		}
		if as.AID != "" {
			id := b.id
			if signer%3 == 1 {
				id = stranger.id
			}
			signed := body
			if tamper {
				signed = append(append([]byte(nil), body...), 'x')
			}
			sig, seq := id.Ctrl.Sign(relayauth.PreimageV2(act, id.AID, a.id.AID, ts, method, req.URL.RequestURI(), signed))
			req.Header.Set(relayauth.HeaderAID, id.AID)
			req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
			req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
			req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
		}
		before := len(a.k.forwarded())
		a.k.mu.Lock()
		beforeBuckets := len(a.k.buckets)
		a.k.mu.Unlock()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("%s %s: %d %s", method, target, rec.Code, rec.Body)
		}
		if rec.Header().Get(wire3.Header) != "3" {
			t.Fatalf("an answer without X-ANet-Wire: 3")
		}
		ok := signer%3 == 0 && act == want && !tamper && withinMaxSkew(ts, a.svc.now()) &&
			(want != relayauth.ActionFedForward || int64(len(body)) <= a.k.MaxEnvelope())
		reached := len(a.k.forwarded()) != before
		a.k.mu.Lock()
		reached = reached || len(a.k.buckets) != beforeBuckets
		a.k.mu.Unlock()
		if reached && !ok {
			t.Fatalf("the kernel was reached by a request the peer did not sign for %s: signer %d action %q tamper %v skew %d",
				path, signer%3, act, tamper, skew)
		}
		if rec.Code == http.StatusOK && !ok {
			t.Fatalf("200 for a request the peer did not sign for %s: signer %d action %q tamper %v", path, signer%3, act, tamper)
		}
		if rec.Code >= 400 {
			var r struct{ Reason, Error string }
			if json.Unmarshal(rec.Body.Bytes(), &r) != nil || r.Reason == "" || r.Error == "" || wire3.Status(wire3.Reason(r.Reason)) != rec.Code {
				t.Fatalf("a refusal that is not a G1 body: %d %s", rec.Code, rec.Body)
			}
		}
	})
}

// FuzzFedCardsPage serves a fuzzed /fed/v3/cards page from a peer and pulls
// it. Properties: nothing panics; every entry handed to the kernel is in a
// format this build knows, its KEL is what the entry's kel decodes to as
// base64url (never anything else), and its key set and notice are absent or
// what the entry's members decode to; the cursor never moves backwards.
func FuzzFedCardsPage(f *testing.F) {
	f.Add([]byte(`{"cursor":2,"cards":[{"format":"a2a-card/1","card":{},"kel":"a2Vs","keys":"a2V5cw","key_state_notice":"bg","home":"https://x.example","fed_seq":1},{"format":"withdrawal/1","card":{"action":"withdraw"},"fed_seq":2}]}`))
	f.Add([]byte(`{"cursor":-5,"cards":[{"format":"a2a-card/1","card":1,"kel":"a2Vs==","fed_seq":9}]}`))
	f.Add([]byte(`{"cursor":1}`))
	f.Add([]byte(`not json`))
	var serve atomic.Pointer[[]byte]
	peer := newTestHub(f)
	peer.mu.Lock()
	peer.h = stampWire(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hub/identity" {
			peer.id.Handler().ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(*serve.Load())
	})
	peer.mu.Unlock()
	sink := &fakeDirectory{}
	b := newTestHub(f).start(Config{Discovery: "allowlist", Home: "https://b.example", Peers: []Peer{peer.peer()}}, sink)
	f.Fuzz(func(t *testing.T, page []byte) {
		serve.Store(&page)
		sink.mu.Lock()
		sink.gotA2A = nil
		sink.mu.Unlock()
		b.round = 0
		b.setPeerA2ACursor(peer.id.AID, 3)
		admitted, refused := b.SyncOnce(tick(context.Background()))
		var wire FedA2ACardPage
		// Read the page as the client does (getStream: json.Decoder.Decode); a page
		// it cannot decode is skipped whole, so nothing of it is expected.
		if err := json.NewDecoder(bytes.NewReader(page)).Decode(&wire); err != nil {
			wire = FedA2ACardPage{}
		}
		if admitted+refused > len(wire.Cards) || admitted != len(sink.gotA2A) {
			t.Fatalf("admitted %d refused %d of %d entries; the kernel got %d", admitted, refused, len(wire.Cards), len(sink.gotA2A))
		}
		// What the kernel must get: the entries of a known format, in page
		// order, but those whose kel does not decode.
		var want []FedA2ACardEntry
		for _, e := range wire.Cards {
			if e.Format != FormatA2ACard && e.Format != FormatWithdrawal {
				continue
			}
			if _, err := wire3.DecodeB64URL("kel", e.KEL); e.KEL != "" && err != nil {
				continue
			}
			want = append(want, e)
		}
		if len(want) != len(sink.gotA2A) {
			t.Fatalf("the kernel got %d entries, want %d", len(sink.gotA2A), len(want))
		}
		for i, got := range sink.gotA2A {
			e := want[i]
			if got.Format != e.Format || got.FedSeq != e.FedSeq {
				t.Fatalf("entry %d handed over as %q %d, the page has %q %d", i, got.Format, got.FedSeq, e.Format, e.FedSeq)
			}
			if kel, _ := wire3.DecodeB64URL("kel", e.KEL); e.KEL != "" && !bytes.Equal(kel, got.KEL) || e.KEL == "" && len(got.KEL) != 0 {
				t.Fatalf("the KEL handed over is not the entry's: %q -> %x", e.KEL, got.KEL)
			}
			if got.Keys != nil {
				if k, err := wire3.DecodeB64URL("keys", e.Keys); err != nil || !bytes.Equal(k, got.Keys) {
					t.Fatalf("the key set handed over is not the entry's")
				}
			}
			if got.Notice != nil {
				if n, err := wire3.DecodeB64URL("key_state_notice", e.KeyStateNotice); err != nil || !bytes.Equal(n, got.Notice) {
					t.Fatalf("the notice handed over is not the entry's")
				}
			}
		}
		if c := b.peerA2ACursor(peer.id.AID); c < 3 {
			t.Fatalf("the cursor moved backwards to %d", c)
		}
	})
}
