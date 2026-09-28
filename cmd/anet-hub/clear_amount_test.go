package main

import (
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// `anet-hub -clear <peer> -amount -1000` passed the flag on as
// uint64(-1000) = 2^64-1000. The statement was signed for that amount,
// which the peer books as -1000 — a discharge that raises the debt it
// claims to settle — and delivered, and with -cleared the local
// DischargeDue(-1000) raised what this hub owes. Only a positive number of
// credits is a discharge; anything else is refused before anything is
// signed or sent.
func TestClearRefusesANonPositiveAmountBeforeSigning(t *testing.T) {
	var calls atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"peer":"x","owed":0,"supply":{"owed_by_peers":250}}`))
	}))
	defer peer.Close()
	for _, amount := range []int64{0, -1, -1000, math.MinInt64} {
		err := clearOwed(t.TempDir(), "did:anet:peer-hub", amount, "ov", peer.URL, "did:anet:payee")
		if err == nil {
			t.Errorf("-amount %d: discharge signed and delivered", amount)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("the peer was contacted %d time(s) for a refused discharge", n)
	}
}
