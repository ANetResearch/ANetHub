//go:build taskboard

package taskboard

// dos_redteam_test.go — adversarial review, lens=dos (A2A-DESIGN §20 F).
//
// Finding: the taskboard mutation handler (POST /tasks/{create,move,...})
// decodes the request body with a bare json.NewDecoder(r.Body).Decode with
// no size limit, and does so BEFORE authenticating the caller. The board is
// mounted straight on the hub root mux (cmd/anet-hub/wire_taskboard.go:
// d.root.Handle("/tasks/", ...)), beside — not behind — the kernel handler
// that carries the limitBody middleware, so nothing caps this body. Every
// other hub write reads its body under a cap first (authRegistered ->
// readRawBody, signedBodyLimit = 1 MiB; /register 1 MiB). Here an
// unauthenticated caller streams an arbitrarily large JSON document that the
// hub buffers into memory before the signature is even checked.
//
// Conditional on -tags taskboard (an opt-in, content-exposing build).

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRedteamTaskboardUnboundedPreAuthDecode asserts the attack succeeds: a
// 24 MiB unauthenticated body (far past the 1 MiB every other hub write
// caps at) is fully decoded, and only then rejected on the signature — the
// decode never fails with 413/400, proving no size limit gates it and it
// runs before auth.
func TestRedteamTaskboardUnboundedPreAuthDecode(t *testing.T) {
	s := openTest(t)
	auth := &stubAuth{}
	srv := httptest.NewServer(NewServer(s, auth).Handler())
	defer srv.Close()

	// A 24 MiB Note field — far past signedBodyLimit (1 MiB). The signature
	// is "bad", so stubAuth will reject it IF the decode gets that far.
	body := map[string]any{
		"aid":  "aid:mallory",
		"sig":  "bad",
		"note": strings.Repeat("A", 24<<20),
	}
	raw, _ := json.Marshal(body)
	t.Logf("unauthenticated POST body = %d bytes (every other hub write caps at 1 MiB)", len(raw))

	resp, err := srv.Client().Post(srv.URL+"/tasks/create", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)

	// 401 means the whole 24 MiB body was buffered and decoded, THEN failed
	// auth: no size cap, and the expensive read happens before the caller is
	// authenticated. A cap would have produced 413 (or a 400 decode error).
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 (full oversized body decoded, then auth failed); got %d %v", resp.StatusCode, out)
	}
	// And auth really did run last (the handler reached VerifyAgentChallenge).
	if len(auth.actions) == 0 {
		t.Fatalf("handler did not reach auth; got status %d", resp.StatusCode)
	}
	t.Logf("attack succeeded: 24 MiB unauthenticated body fully decoded before auth (status 401, auth actions=%v)", auth.actions)
}
