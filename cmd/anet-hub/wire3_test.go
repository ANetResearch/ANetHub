package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/wire3"
	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

// What anet-hub serves (hubHandler over newRoot and every compiled-in
// module) is under the wire-3 contract as a whole, not only the kernel:
// /hub/identity states the wire, /fed/* and a module's writes refuse an
// older caller like the kernel's own routes, and every response carries
// X-ANet-Wire: 3 (core CORE-V1).
func TestTheServedHubSpeaksWire3(t *testing.T) {
	h, _ := wiredHub(t)
	for _, tc := range []struct {
		method, path, wire string
		status             int
		reason             string
	}{
		{"GET", "/hub/identity", "", 200, ""},
		{"GET", "/stats", "", 200, ""},
		{"GET", "/fed/v2/cards", "", 426, "wire_too_old"},
		{"GET", "/fed/v3/cards", "2", 426, "wire_too_old"},
		{"POST", "/fed/v3/forward", "", 426, "wire_too_old"},
		{"POST", "/tasks/claim", "", 426, "wire_too_old"},
		{"POST", "/register", "", 426, "wire_too_old"},
		{"GET", "/hub/identity", "4", 400, "wire_too_new"},
		{"POST", "/hub/identity", "3", 404, "not_found"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
		if tc.wire != "" {
			req.Header.Set("X-ANet-Wire", tc.wire)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		where := tc.method + " " + tc.path + " wire " + tc.wire
		if rec.Code != tc.status {
			t.Errorf("%s: %d %s, want %d", where, rec.Code, rec.Body, tc.status)
			continue
		}
		for _, p := range wire3test.Contract(rec.Code, rec.Header(), rec.Body.Bytes()) {
			t.Errorf("%s: %s", where, p)
		}
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if tc.reason != "" && body["reason"] != tc.reason {
			t.Errorf("%s: reason %v, want %s", where, body["reason"], tc.reason)
		}
		if tc.path == "/hub/identity" && tc.status == http.StatusOK && body["wire"] != float64(3) {
			t.Errorf("/hub/identity does not state wire 3: %s", rec.Body)
		}
	}
}

// `anet-hub -clear … -peer-endpoint` talks to the peer hub itself: its
// requests are hub requests and state the wire, so a wire-3 peer takes the
// discharge instead of answering 426 (core CORE-V1).
func TestClearStatesTheWireToThePeer(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	peer := httptest.NewServer(wire3.Contract(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get(wire3.Header))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"peer":"x","owed":0}`))
	})))
	defer peer.Close()
	if err := clearOwed(t.TempDir(), "did:anet:peer-hub", 5, "wire", peer.URL, ""); err != nil {
		t.Fatalf("discharge to a wire-3 peer: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, ", ") != "POST /federation/clear 3" {
		t.Fatalf("the peer saw %q", seen)
	}
}

// A wire-3 peer publishes no figure of what it is owed (/x402/supply
// states its latest supply epoch only), so -clear does not ask for one:
// a peer that shows nothing left owed after the discharge is a discharge
// applied; one that still shows something owed may or may not have
// applied it, and the operator is told exactly that, not that it was not
// applied — sending another statement on that word would be applied too.
func TestClearToAWire3PeerDoesNotGuessWhatWasOwed(t *testing.T) {
	for _, c := range []struct {
		owedAfter int
		ok        bool
	}{{0, true}, {7, false}} {
		var supplyAsked atomic.Int32
		peer := httptest.NewServer(wire3.Contract(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/x402/supply":
				supplyAsked.Add(1)
				_, _ = w.Write([]byte(`{"hub":"did:anet:peer-hub","note":"epochs only"}`))
			case "/federation/clear":
				_, _ = fmt.Fprintf(w, `{"peer":"x","owed":%d}`, c.owedAfter)
			}
		})))
		err := clearOwed(t.TempDir(), "did:anet:peer-hub", 5, "wire", peer.URL, "")
		peer.Close()
		if c.ok && err != nil {
			t.Errorf("owed %d after: %v", c.owedAfter, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), "cannot be told") ||
			strings.Contains(err.Error(), "not applied")) {
			t.Errorf("owed %d after: %v, want an error saying it cannot be told", c.owedAfter, err)
		}
		if n := supplyAsked.Load(); n != 0 {
			t.Errorf("-clear asked the peer's /x402/supply %d time(s) for a figure it does not publish", n)
		}
	}
}
