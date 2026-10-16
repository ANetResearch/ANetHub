//go:build !no_federation

package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// `anet-hub -clear <peer> -amount -1000` passed the flag on as
// uint64(-1000) = 2^64-1000: a statement the peer booked as -1000, which
// raised the debt it claimed to settle, and a DischargeDue of -1000, which
// raised what this hub owed. anet-hub clear takes only a positive number of
// credits; anything else is the usage line, exit 2, before anything is
// opened, signed or sent.
func TestClearRefusesANonPositiveAmountBeforeSigning(t *testing.T) {
	var calls atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer peer.Close()
	dir := hubDir(t)
	_, peerAID := newAID(t)
	for _, amount := range []string{"0", "-1", "-1000", "-9223372036854775808", "1.5", "x", "9223372036854775808"} {
		r := cli(t, "en", "-data", dir, "clear", peerAID, "--amount", amount, "--peer-endpoint", peer.URL)
		if r.code != 2 || r.stdout != "" || r.stderr != "usage: anet-hub clear <peer-aid> --amount N [--peer-endpoint URL]\n" {
			t.Errorf("--amount %s: %+v, want the usage line and exit 2", amount, r)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("the peer was contacted %d time(s) for a refused discharge", n)
	}
}
