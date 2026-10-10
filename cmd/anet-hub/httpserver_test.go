package main

import (
	"testing"
	"time"
)

// TestTheHubBoundsTheHeaders (sealed-sender SSR-H16, 2026-10-10): the hub's
// HTTP server reads a request's headers within 10 seconds, on every route.
func TestTheHubBoundsTheHeaders(t *testing.T) {
	srv := newHTTPServer(":0", nil)
	if srv.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s, want 10s", srv.ReadHeaderTimeout)
	}
	if srv.Addr != ":0" {
		t.Fatalf("Addr = %q", srv.Addr)
	}
}
