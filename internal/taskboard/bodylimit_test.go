//go:build taskboard

package taskboard

// [redteam:F38] Regression for the dos red-team PoC
// TestRedteamTaskboardUnboundedPreAuthDecode: the mutation handlers
// (POST /tasks/{create,move,...}) decoded the whole body with a bare
// json.Decoder before checking the signature, and the board is mounted on
// the hub's root mux beside — not behind — the kernel's limitBody, so an
// unauthenticated caller could make the hub buffer and decode a JSON
// document of any size. The handlers now read at most maxMutationBody,
// check the signature from the auth fields, and decode the content only
// for a caller that passed.

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func postRaw(t *testing.T, srv *httptest.Server, path string, raw []byte) (int, map[string]any) {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// A 24 MiB unauthenticated body is refused at the cap, before the
// signature is looked at and before anything is decoded.
func TestAnOversizedMutationIsRefusedBeforeAuthentication(t *testing.T) {
	s := openTest(t)
	auth := &stubAuth{}
	srv := httptest.NewServer(NewServer(s, auth).Handler())
	defer srv.Close()

	raw, _ := json.Marshal(map[string]any{
		"aid": "aid:mallory", "sig": "bad", "note": strings.Repeat("A", 24<<20)})
	code, out := postRaw(t, srv, "/tasks/create", raw)
	if code != 413 {
		t.Fatalf("a %d-byte unauthenticated body: %d %v, want 413", len(raw), code, out)
	}
	if len(auth.actions) != 0 {
		t.Fatalf("the oversized body reached authentication: %v", auth.actions)
	}
	// Just under the cap, a signed request is served.
	raw, _ = json.Marshal(map[string]any{"aid": "aid:alice", "sig": "ok", "title": "T",
		"taskdoc_cid": "bafyX", "note": strings.Repeat("A", maxMutationBody-200)})
	if code, out := postRaw(t, srv, "/tasks/create", raw); code != 200 {
		t.Fatalf("a %d-byte signed body: %d %v", len(raw), code, out)
	}
}

// The signature is checked before the content is decoded: an unsigned
// request is refused on its signature whatever its content holds, and
// content that does not decode is reported only to a caller that signed.
func TestAMutationIsAuthenticatedBeforeItsContentIsDecoded(t *testing.T) {
	s := openTest(t)
	auth := &stubAuth{}
	srv := httptest.NewServer(NewServer(s, auth).Handler())
	defer srv.Close()

	bad := []byte(`{"aid":"aid:mallory","sig":"bad","title":{"not":"a string"},"note":[1,2,3]}`)
	if code, out := postRaw(t, srv, "/tasks/create", bad); code != 401 {
		t.Fatalf("unsigned request with undecodable content: %d %v, want 401", code, out)
	}
	signed := []byte(`{"aid":"aid:alice","sig":"ok","title":{"not":"a string"}}`)
	if code, out := postRaw(t, srv, "/tasks/create", signed); code != 400 {
		t.Fatalf("signed request with undecodable content: %d %v, want 400", code, out)
	}
}
