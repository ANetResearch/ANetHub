package aghub_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// fuzzDirMaxBits is the width of the directory FuzzDirectoryBucket builds.
const fuzzDirMaxBits = 2

// FuzzDirectoryBucket sends fuzzed /directory:bucket bodies, with or without
// an identity header, to a hub whose directory is exactly fuzzDirMaxBits
// wide: 32 synthetic entries in each quarter, all with the third bit clear,
// and three registered agents with real boxes. Properties:
//
//   - no answer is a 5xx;
//   - a 200 answers a query that has no identity header and asks for at
//     most fuzzDirMaxBits bits, states that width, and holds only entries
//     of the bucket asked for, after the cursor when there is one, in
//     strictly rising hash order, in at most DirPageBytes;
//   - a refusal is the wire-3 error body of a 400 or a 413.
func FuzzDirectoryBucket(f *testing.F) {
	h := newFZ(f)
	for i := 0; i < 3; i++ {
		h.agent(f, fmt.Sprintf("dir-%d", i), nil, true)
	}
	db := h.store.DBForTest()
	for q := 0; q < 4; q++ {
		for i := 0; i < 32; i++ {
			hash := make([]byte, 32)
			hash[0] = byte(q<<6) | byte(i)
			hash[31] = byte(i)
			if _, err := db.Exec(`INSERT INTO agent(aid, kel, registered_at, dir_hash, dir_box) VALUES(?,?,?,?,?)`,
				fmt.Sprintf("synthetic-%d-%d", q, i), []byte{1}, time.Now().UTC().Format(time.RFC3339), hash,
				bytes.Repeat([]byte{byte(i)}, 64)); err != nil {
				f.Fatal(err)
			}
		}
	}
	h.store.ForgetDirMaxBitsForTest()
	if got, err := h.store.DirMaxBits(); err != nil || got != fuzzDirMaxBits {
		f.Fatalf("the fuzzed directory is %d bits wide (%v), want %d", got, err, fuzzDirMaxBits)
	}
	for _, s := range []string{
		`{"prefix":"","bits":0}`, `{"prefix":"gA","bits":1}`, `{"prefix":"QA","bits":2}`, `{"prefix":"wA","bits":2}`,
		`{"prefix":"gA","bits":3}`, `{"prefix":"","bits":0,"cursor":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`,
		`{"prefix":"wA","bits":1}`, `{"prefix":"gA==","bits":1}`, `{"prefix":"","bits":-1}`, `{"bits":0}`,
		`{"prefix":"","bits":0,"cursor":"AA"}`, `{"prefix":"","bits":0,"x":1}`, `[]`, `null`, ``,
		`{"prefix":"` + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32)) + `","bits":256}`,
	} {
		f.Add([]byte(s), false)
		f.Add([]byte(s), true)
	}
	f.Fuzz(func(t *testing.T, body []byte, identityHeader bool) {
		body = clipB(body, 8<<10)
		req := h.request(http.MethodPost, "/directory:bucket", "", body)
		if identityHeader {
			req.Header.Set(relayauth.HeaderSig, "AA")
		}
		rec := h.serve(req)
		if rec.Code >= 500 {
			t.Fatalf("%q: %d %s", body, rec.Code, rec.Body.Bytes())
		}
		if rec.Code != http.StatusOK {
			var refusal struct {
				Reason string `json:"reason"`
				Error  string `json:"error"`
			}
			if !allowed(rec.Code, 400, 413) || json.Unmarshal(rec.Body.Bytes(), &refusal) != nil ||
				refusal.Reason == "" || refusal.Error == "" {
				t.Fatalf("%q: %d %s, want a wire-3 400 or 413", body, rec.Code, rec.Body.Bytes())
			}
			return
		}
		if identityHeader {
			t.Fatalf("%q with an identity header was answered", body)
		}
		if rec.Body.Len() > aghub.DirPageBytes {
			t.Fatalf("an answer of %d bytes", rec.Body.Len())
		}
		var q struct {
			Prefix string `json:"prefix"`
			Bits   int    `json:"bits"`
			Cursor string `json:"cursor"`
		}
		if err := json.Unmarshal(body, &q); err != nil {
			t.Fatalf("%q was answered but does not decode: %v", body, err)
		}
		if q.Bits > fuzzDirMaxBits {
			t.Fatalf("%q asked for %d bits of a directory %d wide and was answered", body, q.Bits, fuzzDirMaxBits)
		}
		prefix, err := base64.RawURLEncoding.Strict().DecodeString(q.Prefix)
		if err != nil || dirbox.CheckPrefix(prefix, q.Bits) != nil {
			t.Fatalf("%q was answered with a malformed prefix", body)
		}
		var out aghub.DirBucketResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.MaxBits != fuzzDirMaxBits || out.Partial {
			t.Fatalf("the answer states max_bits %d, partial %v", out.MaxBits, out.Partial)
		}
		var after []byte
		if q.Cursor != "" {
			after, _ = base64.RawURLEncoding.DecodeString(q.Cursor)
		}
		var prev []byte
		for _, e := range out.Entries {
			eh, err := base64.RawURLEncoding.Strict().DecodeString(e.H)
			if err != nil || len(eh) != dirbox.HashLen {
				t.Fatalf("an entry's h %q", e.H)
			}
			if p, _ := dirbox.Prefix(eh, q.Bits); !bytes.Equal(p, prefix) {
				t.Fatalf("the bucket %x/%d answered an entry filed under %x", prefix, q.Bits, eh)
			}
			if after != nil && bytes.Compare(eh, after) <= 0 {
				t.Fatalf("an entry at or before the cursor %x: %x", after, eh)
			}
			if prev != nil && bytes.Compare(eh, prev) <= 0 {
				t.Fatalf("entries out of order: %x after %x", eh, prev)
			}
			prev = eh
		}
	})
}
