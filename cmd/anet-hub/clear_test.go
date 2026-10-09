//go:build !no_federation

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// fakePeer is a peer hub's /fed/v3/clear answering with answer, under the
// wire-3 contract, recording what reached it.
type fakePeer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []*http.Request
	body [][]byte
}

func newFakePeer(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) *fakePeer {
	t.Helper()
	p := &fakePeer{}
	p.srv = httptest.NewServer(wire3.Contract(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.seen = append(p.seen, r)
		p.body = append(p.body, b)
		p.mu.Unlock()
		answer(w, r)
	})))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakePeer) paths() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, r := range p.seen {
		out = append(out, r.Method+" "+r.URL.Path)
	}
	return out
}

// dueOf is what the hub in dir owes peer.
func dueOf(t *testing.T, dir, peer string) int64 {
	t.Helper()
	s, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n, err := s.DueTo(peer)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// anet-hub clear talks to the peer hub itself, as a hub: POST /fed/v3/clear
// stating wire 3 and signed by this hub for fed_clear (core CORE-V1, G3),
// the body {peer_aid, receipt} with the statement in base64url (CORE-E5).
// It never asks the peer's /x402/supply for what it is owed: a wire-3 peer
// publishes no such figure (hub-payment-privacy §2.3).
func TestClearIsASignedHubRequestToThePeer(t *testing.T) {
	dir := hubDir(t)
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, peerAID := newAID(t)
	owe(t, dir, peerAID, 30)
	peer := newFakePeer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(aghub.ClearResponse{Peer: id.AID, Owed: 7})
	})
	expectOut(t, cli(t, "en", "-data", dir, "clear", peerAID, "--amount", "5", "--peer-endpoint", peer.srv.URL),
		sentenceOf("en", "clear.ok", map[string]string{"peer": peerAID, "n": "5", "m": "25"}))
	if got := strings.Join(peer.paths(), ", "); got != "POST /fed/v3/clear" {
		t.Fatalf("the peer saw %q", got)
	}
	r := peer.seen[0]
	if r.Header.Get(wire3.Header) != "3" || r.Header.Get(relayauth.HeaderAID) != id.AID ||
		r.Header.Get(relayauth.HeaderSig) == "" || r.Header.Get(relayauth.HeaderTS) == "" {
		t.Errorf("the discharge is not a signed wire-3 hub request: %v", r.Header)
	}
	var req aghub.ClearRequest
	if err := wire3.DecodeStrict(peer.body[0], &req); err != nil || req.PeerAID != id.AID {
		t.Fatalf("body %s: %v", peer.body[0], err)
	}
	raw, err := wire3.DecodeB64URL("receipt", req.Receipt)
	if err != nil {
		t.Fatalf("the statement is not base64url: %v", err)
	}
	rec, err := payment.UnmarshalReceipt(raw)
	if err != nil || rec.Payer != id.AID || rec.PayTo != peerAID || rec.Amount != 5 {
		t.Fatalf("statement %+v: %v", rec, err)
	}
	if err := rec.Verify(id.Ctrl.KEL(), id.AID, rec.SettleAt); err != nil {
		t.Errorf("the statement does not verify under this hub's key: %v", err)
	}
	if due := dueOf(t, dir, peerAID); due != 25 {
		t.Errorf("due after an accepted discharge: %d, want 25", due)
	}
}

// What anet-hub clear says is what it knows (hub-payment-privacy §8.1 PAY-4,
// handover from PAY-3): the peer accepted (clear.ok, the due falls); the peer
// refused (clear.refused, with its reason; nothing changes here); or no
// answer it can read came back — the peer is down, a proxy answered, the
// reply was cut off — and whether the peer recorded the discharge cannot be
// told from here (clear.unconfirmed; nothing changes here, and the next step
// is the peer's operator, since another clear would be a second discharge).
func TestClearSaysWhatItKnows(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer func(self string) func(w http.ResponseWriter, r *http.Request)
		key    string
		value  string
	}{
		{"refused", func(string) func(w http.ResponseWriter, r *http.Request) {
			return func(w http.ResponseWriter, r *http.Request) {
				wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest, Error: "The statement discharges too much."})
			}
		}, "clear.refused", "bad_request"},
		{"not a peer", func(string) func(w http.ResponseWriter, r *http.Request) {
			return func(w http.ResponseWriter, r *http.Request) { wire3.Refuse(w, wire3.ReasonNotPeer) }
		}, "clear.refused", "not_peer"},
		{"a proxy's error page", func(string) func(w http.ResponseWriter, r *http.Request) {
			return func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "<html>bad gateway</html>", http.StatusBadGateway)
			}
		}, "clear.unconfirmed", ""},
		{"a 200 that is not an acknowledgement", func(string) func(w http.ResponseWriter, r *http.Request) {
			return func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) }
		}, "clear.unconfirmed", ""},
		{"another hub's acknowledgement", func(string) func(w http.ResponseWriter, r *http.Request) {
			return func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(aghub.ClearResponse{Peer: "bafy-someone-else", Owed: 0})
			}
		}, "clear.unconfirmed", ""},
		{"accepted", func(self string) func(w http.ResponseWriter, r *http.Request) {
			return func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(aghub.ClearResponse{Peer: self, Owed: 3})
			}
		}, "clear.ok", ""},
	} {
		for _, lang := range []string{"en", "zh"} {
			t.Run(c.name+"/"+lang, func(t *testing.T) {
				dir := hubDir(t)
				id, err := hubid.LoadOrIncept(dir)
				if err != nil {
					t.Fatal(err)
				}
				_, peerAID := newAID(t)
				owe(t, dir, peerAID, 12)
				peer := newFakePeer(t, c.answer(id.AID))
				r := cli(t, lang, "-data", dir, "clear", peerAID, "--amount", "5", "--peer-endpoint", peer.srv.URL)
				want := int64(12)
				if c.key == "clear.ok" {
					want = 7
					expectOut(t, r, sentenceOf(lang, c.key, map[string]string{"peer": peerAID, "n": "5", "m": "7"}))
				} else {
					expectErr(t, r, 1, sentenceOf(lang, c.key, map[string]string{"peer": peerAID, "value": c.value}))
				}
				if due := dueOf(t, dir, peerAID); due != want {
					t.Errorf("due after %s: %d, want %d", c.name, due, want)
				}
				for _, p := range peer.paths() {
					if p != "POST /fed/v3/clear" {
						t.Errorf("clear asked the peer for %s", p)
					}
				}
			})
		}
	}
	// No peer at the endpoint at all.
	dir := hubDir(t)
	_, peerAID := newAID(t)
	owe(t, dir, peerAID, 12)
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	expectErr(t, cli(t, "en", "-data", dir, "clear", peerAID, "--amount", "5", "--peer-endpoint", gone.URL), 1,
		sentenceOf("en", "clear.unconfirmed", map[string]string{"peer": peerAID}))
	if due := dueOf(t, dir, peerAID); due != 12 {
		t.Errorf("due after an unreachable peer: %d, want 12", due)
	}
}

// More than is due — including to a hub this one owes nothing — is refused
// before anything is signed or sent (clear.over_due, with anet-hub due to
// see what is owed). Without --peer-endpoint the peer's entry in
// federation.json is used, and a peer it does not list is the usage line.
func TestClearChecksTheDueFirstAndFindsThePeer(t *testing.T) {
	dir := hubDir(t)
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, peerAID := newAID(t)
	_, stranger := newAID(t)
	owe(t, dir, peerAID, 10)
	peer := newFakePeer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(aghub.ClearResponse{Peer: id.AID, Owed: 0})
	})
	for _, lang := range []string{"en", "zh"} {
		expectErr(t, cli(t, lang, "-data", dir, "clear", peerAID, "--amount", "11", "--peer-endpoint", peer.srv.URL), 1,
			sentenceOf(lang, "clear.over_due", map[string]string{"peer": peerAID, "m": "10", "n": "11"}))
		expectErr(t, cli(t, lang, "-data", dir, "clear", stranger, "--amount", "1", "--peer-endpoint", peer.srv.URL), 1,
			sentenceOf(lang, "clear.over_due", map[string]string{"peer": stranger, "m": "0", "n": "1"}))
	}
	if n := len(peer.paths()); n != 0 {
		t.Fatalf("a refused discharge reached the peer %d time(s)", n)
	}
	// Not in federation.json: the usage line, nothing sent.
	if r := cli(t, "en", "-data", dir, "clear", peerAID, "--amount", "4"); r.code != 2 ||
		!strings.HasPrefix(r.stderr, "usage: anet-hub clear") {
		t.Errorf("no endpoint known: %+v", r)
	}
	writeFederation(t, dir, peerAID, peer.srv.URL)
	expectOut(t, cli(t, "en", "-data", dir, "clear", peerAID, "--amount", "4"),
		sentenceOf("en", "clear.ok", map[string]string{"peer": peerAID, "n": "4", "m": "6"}))
}

// writeFederation writes dir/federation.json naming the peer hub aid at
// endpoint.
func writeFederation(t *testing.T, dir, aid, endpoint string) {
	t.Helper()
	raw, err := json.Marshal(federation.Config{Delivery: "allowlist", Peers: []federation.Peer{{AID: aid, Endpoint: endpoint}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "federation.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
