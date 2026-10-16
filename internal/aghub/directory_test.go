package aghub_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// The directory and its buckets (sealed-sender §2.9, §4.2.8; core §2.8,
// §2.12.2): directory.go.

// dirAgent registers a fresh agent at store with a key set, as /register
// and POST /agents/{aid}/keys leave it, and returns it.
func dirAgent(t *testing.T, store *aghub.Store) *identity.Controller {
	t.Helper()
	c, err := aghub.NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(c.AID(), "agent", nil, kel); err != nil {
		t.Fatal(err)
	}
	raw, _ := mintKeySet(t, c, 1)
	if _, err := store.PublishKeys(c.AID(), raw, 0, c.KEL(), time.Now()); err != nil {
		t.Fatal(err)
	}
	noteKeys(c.AID(), raw)
	return c
}

// dirHubWith is a test hub with n agents that have key sets, and the
// directory width computed over them.
func dirHubWith(t *testing.T, n int) (*httptest.Server, *aghub.Store, []*identity.Controller) {
	t.Helper()
	srv, store := newHubWithStore(t)
	agents := make([]*identity.Controller, n)
	for i := range agents {
		agents[i] = dirAgent(t, store)
	}
	store.ForgetDirMaxBitsForTest()
	return srv, store, agents
}

// bucketQuery posts a /directory:bucket body from the address ip.
func bucketQuery(t *testing.T, srv *httptest.Server, ip string, body string) (int, []byte, http.Header) {
	t.Helper()
	req := newRequest(t, srv, http.MethodPost, "/directory:bucket", []byte(body))
	if ip != "" {
		req.Header.Set("X-Real-IP", ip)
	}
	return send(t, req)
}

// bucketBody is a query for the bits-bit prefix of h.
func bucketBody(t *testing.T, h []byte, bits int, cursor string) string {
	t.Helper()
	p, err := dirbox.Prefix(h, bits)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{"prefix": base64.RawURLEncoding.EncodeToString(p), "bits": bits}
	if cursor != "" {
		m["cursor"] = cursor
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// bucketAnswer decodes a 200 answer.
func bucketAnswer(t *testing.T, code int, b []byte) aghub.DirBucketResponse {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("bucket: %d %s", code, b)
	}
	var out aghub.DirBucketResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// bucketOK posts body and decodes the answer, which must be 200.
func bucketOK(t *testing.T, srv *httptest.Server, body string) aghub.DirBucketResponse {
	t.Helper()
	code, b, _ := bucketQuery(t, srv, "", body)
	return bucketAnswer(t, code, b)
}

// lookUpInBucket finds aid's entry as a daemon does (sealed-sender SSR-D15):
// it asks for the bucket of at most 10 bits of aid's directory hash,
// narrowed to what the hub answers, reads every page, and opens the entry
// filed under the hash. nil when the bucket holds none for aid.
func lookUpInBucket(t *testing.T, srv *httptest.Server, aid, ip string) *dirbox.DirEntry {
	t.Helper()
	h, err := dirbox.Hash(aid)
	if err != nil {
		t.Fatal(err)
	}
	bits := 10
	code, b, _ := bucketQuery(t, srv, ip, bucketBody(t, h, bits, ""))
	if code == http.StatusBadRequest {
		var refusal struct {
			Reason  string `json:"reason"`
			MaxBits int    `json:"max_bits"`
		}
		if json.Unmarshal(b, &refusal) != nil || refusal.Reason != "bucket_too_narrow" {
			t.Fatalf("bucket: %d %s", code, b)
		}
		bits = refusal.MaxBits
		code, b, _ = bucketQuery(t, srv, ip, bucketBody(t, h, bits, ""))
	}
	for {
		out := bucketAnswer(t, code, b)
		for _, e := range out.Entries {
			eh, _ := base64.RawURLEncoding.DecodeString(e.H)
			if !bytes.Equal(eh, h) {
				continue
			}
			box, _ := base64.RawURLEncoding.DecodeString(e.Box)
			entry, err := dirbox.Open(aid, eh, box)
			if err != nil {
				t.Fatalf("the entry filed under %s's hash does not open: %v", aid, err)
			}
			return entry
		}
		if out.Next == "" {
			return nil
		}
		code, b, _ = bucketQuery(t, srv, ip, bucketBody(t, h, bits, out.Next))
	}
}

// storedEntry opens what the hub has filed for aid (nil when nothing).
func storedEntry(t *testing.T, store *aghub.Store, aid string) (*dirbox.DirEntry, []byte) {
	t.Helper()
	var h, box []byte
	if err := store.DBForTest().QueryRow(`SELECT dir_hash, dir_box FROM agent WHERE aid=?`, aid).Scan(&h, &box); err != nil {
		t.Fatal(err)
	}
	if box == nil {
		return nil, nil
	}
	e, err := dirbox.Open(aid, h, box)
	if err != nil {
		t.Fatalf("the box filed for %s does not open: %v", aid, err)
	}
	return e, box
}

// P-SS-5 (SI-12): at the dir_max_bits a hub computes, every bucket of the
// merged directory holds at least 32 entries, and one bit more would leave
// a bucket with fewer; a directory of fewer than 64 entries is answered
// whole.
func TestDirMaxBitsProperty(t *testing.T) {
	check := func(name string, prefixes []uint64) {
		t.Helper()
		b := aghub.DirMaxBitsOfForTest(prefixes)
		n := len(prefixes)
		if n < aghub.DirWholeTableBelow && b != 0 {
			t.Fatalf("%s: %d entries, max_bits %d, want 0", name, n, b)
		}
		counts := func(bits int) []int {
			c := make([]int, 1<<bits)
			for _, p := range prefixes {
				if bits == 0 {
					c[0]++
					continue
				}
				c[p>>(64-bits)]++
			}
			return c
		}
		if b > 0 {
			for i, c := range counts(b) {
				if c < aghub.DirMinBucket {
					t.Fatalf("%s: %d entries, max_bits %d, bucket %d holds %d", name, n, b, i, c)
				}
			}
		}
		if n >= aghub.DirWholeTableBelow && b < 20 {
			least := n
			for _, c := range counts(b + 1) {
				least = min(least, c)
			}
			if least >= aghub.DirMinBucket {
				t.Fatalf("%s: %d entries, max_bits %d, but every bucket at %d bits holds %d or more", name, n, b, b+1, least)
			}
		}
	}
	r := mrand.New(mrand.NewPCG(1, 2))
	for i := 0; i < 400; i++ {
		n := r.IntN(6000)
		ps := make([]uint64, n)
		for j := range ps {
			ps[j] = r.Uint64()
		}
		check(fmt.Sprintf("uniform %d", i), ps)
		// Skewed: a third of the entries in one narrow region.
		for j := 0; j < n/3; j++ {
			ps[j] = 0x7f00_0000_0000_0000 | r.Uint64()>>16
		}
		check(fmt.Sprintf("skewed %d", i), ps)
	}
	// The edges, exactly.
	split := func(lo, hi int) []uint64 {
		var ps []uint64
		for i := 0; i < lo; i++ {
			ps = append(ps, uint64(i))
		}
		for i := 0; i < hi; i++ {
			ps = append(ps, 1<<63|uint64(i))
		}
		return ps
	}
	for _, c := range []struct {
		lo, hi, want int
	}{{31, 32, 0}, {32, 31, 0}, {32, 32, 1}, {33, 31, 0}, {0, 100, 0}, {64, 64, 1}} {
		if got := aghub.DirMaxBitsOfForTest(split(c.lo, c.hi)); got != c.want {
			t.Errorf("%d and %d entries in the two halves: max_bits %d, want %d", c.lo, c.hi, got, c.want)
		}
	}
	quarters := func(n int) []uint64 {
		var ps []uint64
		for q := uint64(0); q < 4; q++ {
			for i := 0; i < n; i++ {
				ps = append(ps, q<<62|uint64(i))
			}
		}
		return ps
	}
	if got := aghub.DirMaxBitsOfForTest(quarters(32)); got != 2 {
		t.Errorf("four quarters of 32: max_bits %d, want 2", got)
	}
	if got := aghub.DirMaxBitsOfForTest(quarters(31)); got != 1 {
		t.Errorf("four quarters of 31: max_bits %d, want 1", got)
	}
}

// M31: a query narrower than dir_max_bits is refused with the width the hub
// does answer; at that width it is answered.
func TestBucketTooNarrow(t *testing.T) {
	srv, store, agents := dirHubWith(t, 3)
	h, _ := dirbox.Hash(agents[0].AID())
	code, b, _ := bucketQuery(t, srv, "", bucketBody(t, h, 1, ""))
	if code != http.StatusBadRequest || !bytes.Contains(b, []byte(`"reason":"bucket_too_narrow"`)) ||
		!bytes.Contains(b, []byte(`"max_bits":0`)) {
		t.Fatalf("one bit of a three-entry directory: %d %s, want 400 bucket_too_narrow with max_bits 0", code, b)
	}
	out := bucketOK(t, srv, bucketBody(t, h, 0, ""))
	if out.MaxBits != 0 || len(out.Entries) != 3 {
		t.Fatalf("the whole directory: %+v", out)
	}

	for i := 0; i < 253; i++ {
		agents = append(agents, dirAgent(t, store))
	}
	store.ForgetDirMaxBitsForTest()
	max, err := store.DirMaxBits()
	if err != nil {
		t.Fatal(err)
	}
	if max < 1 {
		t.Fatalf("256 entries: max_bits %d", max)
	}
	out = bucketOK(t, srv, bucketBody(t, h, max, ""))
	if int(out.MaxBits) != max || len(out.Entries) < aghub.DirMinBucket {
		t.Fatalf("a bucket of max_bits %d: max_bits %d and %d entries", max, out.MaxBits, len(out.Entries))
	}
	code, b, _ = bucketQuery(t, srv, "", bucketBody(t, h, max+1, ""))
	if code != http.StatusBadRequest || !bytes.Contains(b, []byte(`"max_bits":`+strconv.Itoa(max))) {
		t.Fatalf("one bit past max_bits: %d %s", code, b)
	}
	if code, b, _ = bucketQuery(t, srv, "", bucketBody(t, h, 256, "")); code != http.StatusBadRequest ||
		!bytes.Contains(b, []byte(`"reason":"bucket_too_narrow"`)) {
		t.Fatalf("the whole hash as the prefix: %d %s", code, b)
	}
}

// SSR-W17: an entry whose box would be larger than 192 KiB is left out of
// the directory and counted; once it fits again it is back.
func TestDirEntryTooLargeSkipped(t *testing.T) {
	srv, store, agents := dirHubWith(t, 2)
	big := agents[0]
	small, _ := storedEntry(t, store, big.AID())
	if small == nil {
		t.Fatal("no entry to start with")
	}
	before := aghub.DirEntriesTooLarge()
	// A key history no registration could store, written by hand.
	huge := bytes.Repeat([]byte{0xA7}, dirbox.MaxBoxLen)
	if _, err := store.DBForTest().Exec(`UPDATE agent SET kel=? WHERE aid=?`, huge, big.AID()); err != nil {
		t.Fatal(err)
	}
	if err := store.RefreshDirEntry(big.AID()); err != nil {
		t.Fatal(err)
	}
	if e, _ := storedEntry(t, store, big.AID()); e != nil {
		t.Fatal("an entry over 192 KiB is still filed")
	}
	if got := aghub.DirEntriesTooLarge(); got != before+1 {
		t.Errorf("dir-entry-too-large %d, want %d", got, before+1)
	}
	if lookUpInBucket(t, srv, big.AID(), "") != nil {
		t.Error("the oversized entry is in the bucket")
	}
	if lookUpInBucket(t, srv, agents[1].AID(), "") == nil {
		t.Error("the other entry went with it")
	}
	// Just under the limit is carried.
	if _, err := store.DBForTest().Exec(`UPDATE agent SET kel=? WHERE aid=?`, small.KEL, big.AID()); err != nil {
		t.Fatal(err)
	}
	if err := store.RefreshDirEntry(big.AID()); err != nil {
		t.Fatal(err)
	}
	if e := lookUpInBucket(t, srv, big.AID(), ""); e == nil || !bytes.Equal(e.KEL, small.KEL) {
		t.Fatal("the entry is not back once it fits")
	}
}

// The prefix is ceil(bits/8) bytes of base64url with the bits past bits
// zero, and the query is decoded strictly; everything else is 400 (core
// §2.12.2, CORE-E5, CORE-E7, CORE-K15). The answer holds the entries of
// that bucket and no other.
func TestBucketPrefixFormat(t *testing.T) {
	srv, store, _ := dirHubWith(t, 256)
	max, _ := store.DirMaxBits()
	if max < 1 {
		t.Fatalf("max_bits %d", max)
	}
	for _, c := range []struct {
		name, body, reason string
	}{
		{"bits past bits set", `{"prefix":"wA","bits":1}`, "bad_request"},
		{"one byte short", `{"prefix":"gA","bits":9}`, "bad_request"},
		{"one byte too many", `{"prefix":"gAA","bits":8}`, "bad_request"},
		{"a prefix for no bits", `{"prefix":"AA","bits":0}`, "bad_request"},
		{"padded", `{"prefix":"gA==","bits":1}`, "bad_request"},
		{"standard alphabet", `{"prefix":"+w","bits":8}`, "bad_request"},
		{"white space", `{"prefix":"g A","bits":1}`, "bad_request"},
		{"more bits than a hash", `{"prefix":"` + strings.Repeat("A", 44) + `","bits":257}`, "bad_request"},
		{"negative bits", `{"prefix":"","bits":-1}`, "bad_request"},
		{"fractional bits", `{"prefix":"gA","bits":1.5}`, "bad_request"},
		{"bits as text", `{"prefix":"gA","bits":"1"}`, "bad_request"},
		{"no prefix", `{"bits":0}`, "bad_request"},
		{"no bits", `{"prefix":""}`, "bad_request"},
		{"null bits", `{"prefix":"","bits":null}`, "bad_request"},
		{"an unknown member", `{"prefix":"","bits":0,"aid":"x"}`, "bad_request"},
		{"a member twice", `{"prefix":"","bits":0,"bits":0}`, "bad_request"},
		{"not JSON", `prefix=&bits=0`, "bad_request"},
		{"a cursor this hub did not give", `{"prefix":"","bits":0,"cursor":"AA"}`, "bad_request"},
	} {
		code, b, _ := bucketQuery(t, srv, "", c.body)
		if code != http.StatusBadRequest || !bytes.Contains(b, []byte(`"reason":"`+c.reason+`"`)) {
			t.Errorf("%s: %d %s, want 400 %s", c.name, code, b, c.reason)
		}
	}
	// A signed-looking request on the anonymous route: each of the three
	// headers that name a signer is refused on its own (CORE-K15).
	for _, hdr := range []string{relayauth.HeaderAID, relayauth.HeaderSeq, relayauth.HeaderSig} {
		req := newRequest(t, srv, http.MethodPost, "/directory:bucket", []byte(`{"prefix":"","bits":0}`))
		req.Header.Set(hdr, "AA")
		if code, b, _ := send(t, req); code != http.StatusBadRequest ||
			!bytes.Contains(b, []byte(`"reason":"identity_headers_not_allowed"`)) {
			t.Errorf("the identity header %s: %d %.200s, want 400 identity_headers_not_allowed", hdr, code, b)
		}
	}
	// Every prefix of every width up to max_bits answers exactly its bucket.
	all := bucketOK(t, srv, `{"prefix":"","bits":0}`)
	if len(all.Entries) != 256 {
		t.Fatalf("the whole directory: %d entries", len(all.Entries))
	}
	for bits := 1; bits <= max; bits++ {
		seen := 0
		for v := 0; v < 1<<bits; v++ {
			p := make([]byte, (bits+7)/8)
			full := uint64(v) << (64 - bits)
			for i := range p {
				p[i] = byte(full >> (56 - 8*i))
			}
			body := `{"prefix":"` + base64.RawURLEncoding.EncodeToString(p) + `","bits":` + strconv.Itoa(bits) + `}`
			out := bucketOK(t, srv, body)
			if len(out.Entries) < aghub.DirMinBucket {
				t.Errorf("bucket %x/%d holds %d entries", p, bits, len(out.Entries))
			}
			for _, e := range out.Entries {
				h, err := base64.RawURLEncoding.DecodeString(e.H)
				if err != nil {
					t.Fatal(err)
				}
				if got, _ := dirbox.Prefix(h, bits); !bytes.Equal(got, p) {
					t.Fatalf("bucket %x/%d answered an entry filed under %x", p, bits, h)
				}
			}
			seen += len(out.Entries)
		}
		if seen != 256 {
			t.Errorf("the buckets of %d bits hold %d entries together, want 256", bits, seen)
		}
	}
}

// One answer is at most 8 MiB; a larger bucket comes in pages, in hash
// order, each entry once, and a cursor works only in its own bucket.
func TestBucketPagination8MiB(t *testing.T) {
	srv, store := newHubWithStore(t)
	db := store.DBForTest()
	// 70 entries of 150 KiB, half under each first bit: about 14 MB of
	// base64url for the whole directory, which takes two pages, and a
	// directory one bit wide.
	const rows = 70
	box := make([]byte, 150<<10)
	var hashes [][]byte
	for i := 0; i < rows; i++ {
		h := make([]byte, 32)
		if _, err := rand.Read(h); err != nil {
			t.Fatal(err)
		}
		h[0] = h[0]&0x7f | byte(i%2)<<7
		if _, err := rand.Read(box); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO agent(aid, kel, registered_at, dir_hash, dir_box) VALUES(?,?,?,?,?)`,
			fmt.Sprintf("synthetic-%d", i), []byte{1}, time.Now().UTC().Format(time.RFC3339), h, box); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, h)
	}
	sort.Slice(hashes, func(i, j int) bool { return bytes.Compare(hashes[i], hashes[j]) < 0 })
	query := func(prefix string, bits int, cursor string) (int, []byte) {
		body := `{"prefix":"` + prefix + `","bits":` + strconv.Itoa(bits)
		if cursor != "" {
			body += `,"cursor":"` + cursor + `"`
		}
		code, b, _ := bucketQuery(t, srv, "", body+`}`)
		return code, b
	}
	var got [][]byte
	var firstNext string
	cursor, pages := "", 0
	for {
		code, b := query("", 0, cursor)
		if len(b) > aghub.DirPageBytes {
			t.Fatalf("page %d is %d bytes, over %d", pages, len(b), aghub.DirPageBytes)
		}
		out := bucketAnswer(t, code, b)
		pages++
		for _, e := range out.Entries {
			h, _ := base64.RawURLEncoding.DecodeString(e.H)
			got = append(got, h)
		}
		if out.Next == "" {
			break
		}
		if firstNext == "" {
			firstNext = out.Next
		}
		cursor = out.Next
		if pages > rows {
			t.Fatal("the pages do not end")
		}
	}
	if pages < 2 {
		t.Fatalf("%d entries of 150 KiB came in %d page(s)", rows, pages)
	}
	if len(got) != rows {
		t.Fatalf("%d entries over the pages, want %d", len(got), rows)
	}
	for i := range got {
		if !bytes.Equal(got[i], hashes[i]) {
			t.Fatalf("entry %d is out of hash order or repeated", i)
		}
	}
	if code, b := query("", 0, firstNext+"A"); code != http.StatusBadRequest {
		t.Fatalf("a cursor with a character added: %d %s", code, b)
	}
	// A hash of the bucket 1/1 is no cursor of the bucket 0/1.
	store.ForgetDirMaxBitsForTest()
	if max, _ := store.DirMaxBits(); max != 1 {
		t.Fatalf("max_bits %d, want 1", max)
	}
	upper := base64.RawURLEncoding.EncodeToString(hashes[rows-1])
	if code, b := query("AA", 1, upper); code != http.StatusBadRequest || !bytes.Contains(b, []byte("cursor")) {
		t.Fatalf("a cursor from another bucket: %d %s", code, b)
	}
	if code, b := query("gA", 1, upper); code != http.StatusOK || bytes.Contains(b, []byte(`"next"`)) {
		t.Fatalf("the last hash of the bucket as its cursor: %d %s, want 200 and the end of the bucket", code, b)
	}
}

// The bucket route is limited per client address: 60 a minute with a burst
// of 30, an IPv6 /64 as one address (sealed-sender §2.12, §4.2.8 item 2).
func TestBucketRateLimit(t *testing.T) {
	srv, _, _ := dirHubWith(t, 1)
	now := time.Now()
	serverOf(t, srv).SetDirLimiterClockForTest(func() time.Time { return now })
	q := func(ip string) (int, http.Header) {
		code, _, hdr := bucketQuery(t, srv, ip, `{"prefix":"","bits":0}`)
		return code, hdr
	}
	const burst = 30 // and 60 a minute: sealed-sender §2.12
	for i := 0; i < burst; i++ {
		if code, _ := q("203.0.113.7"); code != http.StatusOK {
			t.Fatalf("query %d within the burst: %d", i, code)
		}
	}
	code, hdr := q("203.0.113.7")
	if code != http.StatusTooManyRequests {
		t.Fatalf("past the burst: %d, want 429", code)
	}
	if ra, err := strconv.Atoi(hdr.Get("Retry-After")); err != nil || ra < 1 {
		t.Errorf("Retry-After = %q", hdr.Get("Retry-After"))
	}
	if code, _ := q("203.0.113.8"); code != http.StatusOK {
		t.Errorf("another address: %d, want 200", code)
	}
	// A malformed query spends a token like any other.
	for i := 0; i < burst; i++ {
		bucketQuery(t, srv, "203.0.113.9", `{"bits":0}`)
	}
	if code, _ := q("203.0.113.9"); code != http.StatusTooManyRequests {
		t.Errorf("after a burst of malformed queries: %d, want 429", code)
	}
	// Rotating addresses within one /64 does not get a new bucket.
	for i := 0; i < burst; i++ {
		if code, _ := q(fmt.Sprintf("2001:db8:1:2::%x", i+1)); code != http.StatusOK {
			t.Fatalf("IPv6 query %d within the burst: %d", i, code)
		}
	}
	if code, _ := q("2001:db8:1:2:ffff::9"); code != http.StatusTooManyRequests {
		t.Errorf("another address in the same /64: %d, want 429", code)
	}
	if code, _ := q("2001:db8:1:3::1"); code != http.StatusOK {
		t.Errorf("an address in another /64: %d, want 200", code)
	}
	// One token a second comes back, and not sooner.
	now = now.Add(900 * time.Millisecond)
	if code, _ := q("203.0.113.7"); code != http.StatusTooManyRequests {
		t.Errorf("0.9 seconds later: %d, want 429", code)
	}
	now = now.Add(200 * time.Millisecond)
	if code, _ := q("203.0.113.7"); code != http.StatusOK {
		t.Errorf("1.1 seconds later: %d, want 200", code)
	}
}

// dir_max_bits is computed again once it is an hour old, and not before:
// a directory that grew is answered narrower within the hour.
func TestDirMaxBitsIsComputedAgainHourly(t *testing.T) {
	_, store := newHubWithStore(t)
	now := time.Now()
	store.SetClockForTest(func() time.Time { return now })
	if max, err := store.DirMaxBits(); err != nil || max != 0 {
		t.Fatalf("an empty directory: %d %v", max, err)
	}
	for i := 0; i < 256; i++ {
		dirAgent(t, store)
	}
	now = now.Add(59 * time.Minute)
	if max, _ := store.DirMaxBits(); max != 0 {
		t.Fatalf("59 minutes later: max_bits %d, computed again before the hour", max)
	}
	now = now.Add(2 * time.Minute)
	if max, _ := store.DirMaxBits(); max < 1 {
		t.Fatalf("61 minutes later: max_bits %d for 256 entries, not computed again", max)
	}
}

// SSR-H17: the entry is recomputed with each of the five changes to it, in
// the same transaction, and a registration that changes nothing leaves the
// box as it was.
func TestDirBoxRecomputedOnChange(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, _ := twoAgents(t)
	hubAID := hubAIDOf(t, srv)

	// No key set: no entry.
	register(t, srv, c, "Agent", nil)
	if e, _ := storedEntry(t, store, c.AID()); e != nil {
		t.Fatal("an agent without a key set has an entry")
	}
	// 1. registration, with the key set.
	k1, _ := mintKeySet(t, c, 1)
	body := registerBody(t, c, "Agent", nil)
	withEncKeys(t, srv, body, c.AID(), k1)
	if code, b := registerFunded(t, srv, c, body); code != 200 {
		t.Fatalf("register with keys: %d %s", code, b)
	}
	e, box1 := storedEntry(t, store, c.AID())
	kel1, _ := identity.MarshalKEL(c.KEL())
	// The notice this hub signed as the agent's witness, which the
	// registration's answer carried too (KEL H-11).
	if e == nil || e.AID != c.AID() || e.Home != hubAID || !bytes.Equal(e.KEL, kel1) || !bytes.Equal(e.Keys, k1) ||
		e.Card != nil || e.Notice == nil {
		t.Fatalf("after registering: %+v", e)
	}
	if err := identity.VerifyNotice(e.Notice, c.KEL(), hubKELsOf(t, srv), uint64(time.Now().UnixMilli())); err != nil {
		t.Fatalf("the entry's notice: %v", err)
	}
	// The same registration again changes nothing, the box included.
	if code, b := registerFunded(t, srv, c, body); code != 200 {
		t.Fatalf("register again: %d %s", code, b)
	}
	if _, box := storedEntry(t, store, c.AID()); !bytes.Equal(box, box1) {
		t.Fatal("a registration that changed nothing sealed the entry again")
	}
	// 2. a key set published.
	k2, _ := mintKeySet(t, c, 2)
	if code, b := publishKeys(t, srv, c, k2); code != 200 {
		t.Fatalf("publish: %d %s", code, b)
	}
	if e, _ = storedEntry(t, store, c.AID()); !bytes.Equal(e.Keys, k2) {
		t.Fatal("the entry does not carry the new key set")
	}
	// 3. a card admitted, then withdrawn.
	card := signA2A(t, c, a2aCardFor(c, 1))
	if out := registerA2A(t, srv, c, "Agent", nil, card); out.CardStatus != aghub.CardStatusOK {
		t.Fatalf("card: %+v", out)
	}
	if e, _ = storedEntry(t, store, c.AID()); !bytes.Equal(e.Card, card) {
		t.Fatalf("the entry does not carry the card: %q", e.Card)
	}
	if out := registerA2A(t, srv, c, "Agent", nil, json.RawMessage(`null`)); out.CardStatus != aghub.CardStatusWithdrawn {
		t.Fatalf("withdraw: %+v", out)
	}
	if e, _ = storedEntry(t, store, c.AID()); e.Card != nil {
		t.Fatal("the entry still carries the withdrawn card")
	}
	card2 := signA2A(t, c, a2aCardFor(c, 2))
	if out := registerA2A(t, srv, c, "Agent", nil, card2); out.CardStatus != aghub.CardStatusOK {
		t.Fatalf("a card again: %+v", out)
	}
	if e, _ = storedEntry(t, store, c.AID()); !bytes.Equal(e.Card, card2) {
		t.Fatal("the entry does not carry the new card")
	}
	// 4. the key history extended: the card signed by the key the
	// rotation retired is delisted, and leaves the entry with it; so does
	// the key set it signed (KEL H-2), and with no key set there is no
	// entry until the agent publishes one signed with its new key.
	if err := identitytest.Rotate(c, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	kel2, _ := identity.MarshalKEL(c.KEL())
	register(t, srv, c, "Agent", nil)
	if e, _ = storedEntry(t, store, c.AID()); e != nil {
		t.Fatalf("the entry outlived the key set the rotation retired: %+v", e)
	}
	k3, _ := mintKeySet(t, c, 3)
	if code, b := publishKeys(t, srv, c, k3); code != 200 {
		t.Fatalf("publish after the rotation: %d %s", code, b)
	}
	if e, _ = storedEntry(t, store, c.AID()); e == nil || !bytes.Equal(e.KEL, kel2) || !bytes.Equal(e.Keys, k3) {
		t.Fatalf("the entry does not carry the extended key history and the new set: %+v", e)
	}
	if e.Card != nil {
		t.Fatal("the entry still carries a card that no longer verifies")
	}
	// Extended again, with the set re-signed in the registration, as a
	// daemon registers a planned rotation (KEL D-30): one registration, and
	// the entry follows it.
	if err := identitytest.Rotate(c, uint64(time.Now().UnixMilli())+1); err != nil {
		t.Fatal(err)
	}
	kel3, _ := identity.MarshalKEL(c.KEL())
	k3again := resignKeySet(t, c, k3)
	body = registerBody(t, c, "Agent", nil)
	withEncKeys(t, srv, body, c.AID(), k3again)
	if code, b := registerFunded(t, srv, c, body); code != 200 || !strings.Contains(string(b), `"keys_status":"ok"`) {
		t.Fatalf("register the rotation with the re-signed set: %d %s", code, b)
	}
	if e, _ = storedEntry(t, store, c.AID()); e == nil || !bytes.Equal(e.KEL, kel3) || !bytes.Equal(e.Keys, k3again) {
		t.Fatalf("the entry does not carry the key history a registration extended: %+v", e)
	}
	kel2 = kel3
	// 5. a new witness notice.
	notice := []byte("a notice for the tip")
	store.SetDirNoticeForTest(func(aid string) []byte {
		if aid == c.AID() {
			return notice
		}
		return nil
	})
	if err := store.RefreshDirEntry(c.AID()); err != nil {
		t.Fatal(err)
	}
	if e, _ = storedEntry(t, store, c.AID()); !bytes.Equal(e.Notice, notice) {
		t.Fatal("the entry does not carry the notice")
	}
	// And what a daemon reads from the bucket is that entry.
	if got := lookUpInBucket(t, srv, c.AID(), ""); got == nil || !bytes.Equal(got.Notice, notice) || !bytes.Equal(got.KEL, kel2) {
		t.Fatalf("the bucket serves %+v", got)
	}
	// Leaving takes the entry with the row.
	if code, b := leave(t, srv, c); code != 200 {
		t.Fatalf("leave: %d %s", code, b)
	}
	if lookUpInBucket(t, srv, c.AID(), "") != nil {
		t.Fatal("a departed agent is still in the directory")
	}
}

var (
	toTheHourRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:00:00Z$`)
	toTheDayRe  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T00:00:00Z$`)
)

// SSR-H18: the entries of /a2a/v1/agents and /agents carry the agent's KEL
// and key set in base64url, the last poll to the hour, quiet as a boolean
// only, the registration to the UTC day (and the card's verification, which
// is the last registration, to the hour).
func TestRegistryEntryPrecision(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, _ := twoAgents(t)
	k1, _ := mintKeySet(t, c, 1)
	body := registerBody(t, c, "Agent", []string{"work.do"})
	withEncKeys(t, srv, body, c.AID(), k1)
	body["a2a_card"] = signA2A(t, c, a2aCardFor(c, 1))
	if code, b := registerFunded(t, srv, c, body); code != 200 {
		t.Fatalf("register: %d %s", code, b)
	}
	kel, _ := identity.MarshalKEL(c.KEL())
	b64 := base64.RawURLEncoding.EncodeToString
	for _, quiet := range []bool{false, true} {
		seen := time.Now().Add(-17 * time.Minute)
		if quiet {
			seen = time.Now().Add(-6*time.Hour - 23*time.Minute)
		}
		backdatePoll(t, store, c.AID(), seen)

		_, raw := getJSON(t, srv.URL+"/a2a/v1/agents")
		var list struct {
			Agents []map[string]any `json:"agents"`
		}
		if err := json.Unmarshal(raw, &list); err != nil || len(list.Agents) != 1 {
			t.Fatalf("/a2a/v1/agents: %s", raw)
		}
		a := list.Agents[0]
		if a["kel"] != b64(kel) || a["keys"] != b64(k1) {
			t.Errorf("/a2a/v1/agents kel/keys: %v %v", a["kel"], a["keys"])
		}
		if s, _ := a["lastSeen"].(string); !toTheHourRe.MatchString(s) || s != seen.UTC().Truncate(time.Hour).Format(time.RFC3339) {
			t.Errorf("/a2a/v1/agents lastSeen %q, want the hour of %s", s, seen.UTC())
		}
		if s, _ := a["verifiedAt"].(string); !toTheHourRe.MatchString(s) {
			t.Errorf("/a2a/v1/agents verifiedAt %q, want an hour", s)
		}
		if a["quiet"] != quiet {
			t.Errorf("/a2a/v1/agents quiet %v, want %v", a["quiet"], quiet)
		}

		_, raw = getJSON(t, srv.URL+"/agents")
		var agents struct {
			Agents []map[string]any `json:"agents"`
		}
		if err := json.Unmarshal(raw, &agents); err != nil || len(agents.Agents) != 1 {
			t.Fatalf("/agents: %s", raw)
		}
		a = agents.Agents[0]
		if a["kel"] != b64(kel) || a["keys"] != b64(k1) {
			t.Errorf("/agents kel/keys: %v %v", a["kel"], a["keys"])
		}
		if s, _ := a["last_seen"].(string); s != seen.UTC().Truncate(time.Hour).Format(time.RFC3339) {
			t.Errorf("/agents last_seen %q, want the hour of %s", s, seen.UTC())
		}
		if s, _ := a["registered_at"].(string); !toTheDayRe.MatchString(s) ||
			s != time.Now().UTC().Truncate(24*time.Hour).Format(time.RFC3339) {
			t.Errorf("/agents registered_at %q, want today, at midnight UTC", s)
		}
		if q, ok := a["quiet"]; quiet && q != true || !quiet && ok {
			t.Errorf("/agents quiet %v (present %v), want %v", q, ok, quiet)
		}
		for _, page := range [][]byte{raw} {
			if bytes.Contains(page, []byte("quiet_for")) || bytes.Contains(page, []byte("hours")) {
				t.Errorf("a listing says how long the agent has been quiet: %s", page)
			}
		}
		_, raw = getJSON(t, srv.URL+"/agents/"+c.AID())
		var one struct {
			Agent map[string]any `json:"agent"`
		}
		_ = json.Unmarshal(raw, &one)
		if one.Agent["last_seen"] != seen.UTC().Truncate(time.Hour).Format(time.RFC3339) ||
			bytes.Contains(raw, []byte("quiet_for")) {
			t.Errorf("/agents/{aid} states the poll time more precisely than the hour: %s", raw)
		}
	}
	// The graph names who reviewed whom and carries no key material.
	_, raw := getJSON(t, srv.URL+"/graph")
	if bytes.Contains(raw, []byte(`"kel"`)) || bytes.Contains(raw, []byte(`"keys"`)) {
		t.Errorf("/graph carries key material: %s", raw)
	}
	// A poll time the hub cannot read is not repeated, at whatever
	// precision it was written.
	if _, err := store.DBForTest().Exec(`UPDATE agent SET last_seen_at='2026-10-04 12:34:56.789' WHERE aid=?`, c.AID()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/agents", "/agents/" + c.AID(), "/a2a/v1/agents"} {
		if _, raw := getJSON(t, srv.URL+path); bytes.Contains(raw, []byte("12:34")) {
			t.Errorf("%s repeats an unreadable poll time: %s", path, raw)
		}
	}
}

// The routes that named an agent for a sender, or published where to dial
// it, are gone (sealed-sender §2.7): 404 not_found in the wire-3 error body,
// whatever the body. GET /agents/{aid}/keys stays, for an agent registered
// here only.
func TestDeletedLookupRoutes404(t *testing.T) {
	srv, store, agents := dirHubWith(t, 1)
	a := agents[0]
	stranger, _ := twoAgents(t)
	lookup := []byte(`{"aid":"` + a.AID() + `"}`)
	for _, r := range []struct {
		method, path string
		body         []byte
	}{
		{http.MethodPost, "/agents/keys:lookup", lookup},
		{http.MethodPost, "/agents/kel:lookup", lookup},
		{http.MethodPost, "/a2a/v1/agents/card:lookup", lookup},
		{http.MethodPost, "/agents/" + a.AID() + "/p2p", []byte(`{"addr":"tcp://192.0.2.7:4001"}`)},
		{http.MethodGet, "/agents/" + a.AID() + "/p2p", nil},
		{http.MethodGet, "/p2p/peers", nil},
		{http.MethodGet, "/agents/" + a.AID() + "/card", nil},
	} {
		code, b, _ := send(t, newRequest(t, srv, r.method, r.path, r.body))
		if code != http.StatusNotFound || !bytes.Contains(b, []byte(`"reason":"not_found"`)) {
			t.Errorf("%s %s: %d %s, want 404 not_found", r.method, r.path, code, b)
		}
	}
	if code, b := getJSON(t, srv.URL+"/agents/"+a.AID()+"/keys"); code != http.StatusOK {
		t.Errorf("the keys of an agent registered here: %d %s", code, b)
	}
	if code, b := getJSON(t, srv.URL+"/agents/"+stranger.AID()+"/keys"); code != http.StatusNotFound {
		t.Errorf("the keys of an agent registered elsewhere: %d %s, want 404", code, b)
	}
	var tables int
	if err := store.DBForTest().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='p2p_addr'`).Scan(&tables); err != nil || tables != 0 {
		t.Errorf("the hub still has a p2p address table (%d, %v)", tables, err)
	}
}

// M20 (hub side): every entry the hub serves is sealed under the agent's AID
// and filed under the labeled hash: the bucket carries no AID, key history
// or key set in the clear, an entry does not open under another AID, and
// the hash is not the plain SHA-256 of the AID.
func TestDirectoryHidesEveryEntry(t *testing.T) {
	srv, store, agents := dirHubWith(t, 4)
	_, raw, _ := bucketQuery(t, srv, "", `{"prefix":"","bits":0}`)
	out := bucketAnswer(t, http.StatusOK, raw)
	if len(out.Entries) != len(agents) {
		t.Fatalf("%d entries for %d agents", len(out.Entries), len(agents))
	}
	byHash := map[string]*identity.Controller{}
	for _, c := range agents {
		h, _ := dirbox.Hash(c.AID())
		byHash[string(h)] = c
		plain := sha256.Sum256([]byte(c.AID()))
		if bytes.Contains(raw, []byte(base64.RawURLEncoding.EncodeToString(plain[:]))) {
			t.Error("an entry is filed under the unlabeled hash of the AID")
		}
	}
	for i, e := range out.Entries {
		h, _ := base64.RawURLEncoding.DecodeString(e.H)
		box, _ := base64.RawURLEncoding.DecodeString(e.Box)
		c := byHash[string(h)]
		if c == nil {
			t.Fatalf("entry %d is filed under no agent's labeled hash", i)
		}
		keys, kel, _, _ := store.LocalKeys(c.AID())
		for _, clear := range [][]byte{[]byte(c.AID()), kel, keys} {
			if bytes.Contains(box, clear) {
				t.Errorf("entry %d carries its agent's AID, key history or key set in the clear", i)
			}
		}
		if _, err := dirbox.Open(c.AID(), h, box); err != nil {
			t.Errorf("entry %d does not open under its AID: %v", i, err)
		}
		other := agents[(indexOf(agents, c)+1)%len(agents)]
		oh, _ := dirbox.Hash(other.AID())
		if _, err := dirbox.Open(other.AID(), oh, box); err == nil {
			t.Errorf("entry %d opens under another AID", i)
		}
	}
	for _, c := range agents {
		if bytes.Contains(raw, []byte(c.AID())) {
			t.Error("the bucket answer names an AID")
		}
	}
}

func indexOf(cs []*identity.Controller, c *identity.Controller) int {
	for i := range cs {
		if cs[i] == c {
			return i
		}
	}
	return -1
}

// SSR-W18, SSR-W19: the agents a peer's card stream taught this hub count
// towards dir_max_bits (the merged directory), but a bucket here answers
// this hub's own entries only (the peer answers for its own). A card that
// came without a key set does not count: its agent is in no bucket
// (SSR-H18), and counting it would make the buckets narrower than they are.
func TestMaxBitsCountsPeerCardsButBucketsDoNot(t *testing.T) {
	srv, store, agents := dirHubWith(t, 2)
	db := store.DBForTest()
	insert := func(n int, keys []byte) {
		for i := 0; i < n; i++ {
			c, _ := twoAgents(t)
			if _, err := db.Exec(`INSERT INTO fed_a2a_card(aid, seq, payload_hash, card, kel, keys, home, peer_aid, verified_at, stored_at)
			    VALUES(?, 1, x'00', '{}', x'00', ?, 'https://peer.example', 'peer', ?, ?)`,
				c.AID(), keys, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
		}
	}
	insert(300, nil)
	store.ForgetDirMaxBitsForTest()
	if max, err := store.DirMaxBits(); err != nil || max != 0 {
		t.Fatalf("2 entries and 300 peer cards without a key set: max_bits %d (%v), want 0", max, err)
	}
	insert(300, []byte{0})
	store.ForgetDirMaxBitsForTest()
	max, err := store.DirMaxBits()
	if err != nil {
		t.Fatal(err)
	}
	if max < 1 {
		t.Fatalf("302 entries in the merged directory: max_bits %d", max)
	}
	total := 0
	for v := 0; v < 1<<max; v++ {
		p := make([]byte, (max+7)/8)
		full := uint64(v) << (64 - max)
		for i := range p {
			p[i] = byte(full >> (56 - 8*i))
		}
		body := `{"prefix":"` + base64.RawURLEncoding.EncodeToString(p) + `","bits":` + strconv.Itoa(max) + `}`
		total += len(bucketOK(t, srv, body).Entries)
	}
	if total != len(agents) {
		t.Fatalf("the buckets hold %d entries, want this hub's %d", total, len(agents))
	}
}

// SSR-H17, the key set: a rotation takes the key set its retired key signed
// out of the entry with it (KEL H-2: no entry until a set signed with the
// new key), and the same set re-signed after it is stored, and the entry
// carries the new signature, the one that verifies against the extended KEL.
// An entry left with the old signature would hand every reader a key set it
// refuses.
func TestDirEntryCarriesTheResignedKeySet(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, _ := twoAgents(t)
	register(t, srv, c, "Agent", nil)
	now := uint64(time.Now().UnixMilli())
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
	if err != nil {
		t.Fatal(err)
	}
	set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: c.AID(), Seq: 3, Keys: []seal.EncKey{kp.Public},
		IssuedAt: now, Mbox: testMbox(t)}
	before := signSet(t, c, set)
	if code, b := publishKeys(t, srv, c, before); code != http.StatusOK {
		t.Fatalf("publish: %d %s", code, b)
	}
	if e, _ := storedEntry(t, store, c.AID()); e == nil || !bytes.Equal(e.Keys, before) {
		t.Fatal("the entry does not carry the key set")
	}
	if err := identitytest.Rotate(c, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if code, b := registerCode(t, srv, c, "Agent", nil); code != http.StatusOK {
		t.Fatalf("register after the rotation: %d %s", code, b)
	}
	if e, _ := storedEntry(t, store, c.AID()); e != nil {
		t.Fatal("the entry still carries the key set the rotation retired")
	}
	after := signSet(t, c, set)
	if bytes.Equal(after, before) {
		t.Fatal("setup: the re-signed set has the same bytes")
	}
	code, b := publishKeys(t, srv, c, after)
	var out aghub.KeysPublishResponse
	if code != http.StatusOK || json.Unmarshal(b, &out) != nil || out.KeysStatus != aghub.KeysStatusOK {
		t.Fatalf("the same set re-signed: %d %s, want 200 ok", code, b)
	}
	kel, _ := identity.MarshalKEL(c.KEL())
	if e, _ := storedEntry(t, store, c.AID()); e == nil || !bytes.Equal(e.Keys, after) || !bytes.Equal(e.KEL, kel) {
		t.Fatal("the entry does not carry the re-signed key set over the extended KEL")
	}
}

// SSR-H17, the card: a card that was delisted and is listed again in the
// same bytes (AdmitA2ACard's unchanged path) is back in the entry.
func TestDirEntryCarriesACardListedAgain(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, _ := twoAgents(t)
	k1, _ := mintKeySet(t, c, 1)
	body := registerBody(t, c, "Agent", nil)
	withEncKeys(t, srv, body, c.AID(), k1)
	if code, b := registerFunded(t, srv, c, body); code != http.StatusOK {
		t.Fatalf("register: %d %s", code, b)
	}
	card := signA2A(t, c, a2aCardFor(c, 1))
	if out := registerA2A(t, srv, c, "Agent", nil, card); out.CardStatus != aghub.CardStatusOK {
		t.Fatalf("card: %+v", out)
	}
	if e, _ := storedEntry(t, store, c.AID()); e == nil || !bytes.Equal(e.Card, card) {
		t.Fatal("the entry does not carry the card")
	}
	// Delisted, as recheckA2ACard leaves a card that stopped verifying.
	if _, err := store.DBForTest().Exec(`UPDATE agent_a2a_card SET verified_at=NULL WHERE aid=?`, c.AID()); err != nil {
		t.Fatal(err)
	}
	if err := store.RefreshDirEntry(c.AID()); err != nil {
		t.Fatal(err)
	}
	if e, _ := storedEntry(t, store, c.AID()); e == nil || e.Card != nil {
		t.Fatal("setup: the entry still carries the delisted card")
	}
	if out := registerA2A(t, srv, c, "Agent", nil, card); out.CardStatus != aghub.CardStatusUnchanged {
		t.Fatalf("the same card again: %+v", out)
	}
	if e, _ := storedEntry(t, store, c.AID()); e == nil || !bytes.Equal(e.Card, card) {
		t.Fatal("the card listed again is not back in the entry")
	}
}

// SSR-W17 at the bound: an entry whose box is exactly 192 KiB is carried,
// one byte more is left out and counted.
func TestDirEntryTooLargeBoundary(t *testing.T) {
	_, store, agents := dirHubWith(t, 1)
	aid := agents[0].AID()
	e, _ := storedEntry(t, store, aid)
	if e == nil {
		t.Fatal("no entry to start with")
	}
	boxLen := func(kelLen int) int {
		x := *e
		x.KEL = make([]byte, kelLen)
		pt, err := x.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return len(pt) + dirbox.Overhead
	}
	// A KEL of 64 KiB and more has a byte string head of the same length,
	// so the box grows byte for byte with it.
	n := 100 << 10
	n += dirbox.MaxBoxLen - boxLen(n)
	if boxLen(n) != dirbox.MaxBoxLen || boxLen(n+1) != dirbox.MaxBoxLen+1 {
		t.Fatalf("setup: boxes of %d and %d bytes", boxLen(n), boxLen(n+1))
	}
	for _, c := range []struct {
		kelLen  int
		carried bool
	}{{n, true}, {n + 1, false}, {n, true}} {
		before := aghub.DirEntriesTooLarge()
		if _, err := store.DBForTest().Exec(`UPDATE agent SET kel=? WHERE aid=?`,
			bytes.Repeat([]byte{0xA7}, c.kelLen), aid); err != nil {
			t.Fatal(err)
		}
		if err := store.RefreshDirEntry(aid); err != nil {
			t.Fatal(err)
		}
		got, box := storedEntry(t, store, aid)
		counted := aghub.DirEntriesTooLarge() - before
		switch {
		case c.carried && (got == nil || len(box) != c.kelLen-n+dirbox.MaxBoxLen || counted != 0):
			t.Errorf("a box of %d bytes: filed %v (%d bytes), counted %d; want it filed", boxLen(c.kelLen), got != nil, len(box), counted)
		case !c.carried && (got != nil || counted != 1):
			t.Errorf("a box of %d bytes: filed %v, counted %d; want it left out and counted once", boxLen(c.kelLen), got != nil, counted)
		}
	}
}

// SSR-W18: the merged directory holds each agent once. A peer's card for an
// agent registered here is the same entry, and counting it twice would
// state buckets twice as full as they are.
func TestMaxBitsCountsAnAgentOnce(t *testing.T) {
	_, store, agents := dirHubWith(t, 60)
	db := store.DBForTest()
	for _, c := range agents {
		if _, err := db.Exec(`INSERT INTO fed_a2a_card(aid, seq, payload_hash, card, kel, home, peer_aid, verified_at, stored_at)
		    VALUES(?, 1, x'00', '{}', x'00', 'https://peer.example', 'peer', ?, ?)`,
			c.AID(), time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	store.ForgetDirMaxBitsForTest()
	if max, err := store.DirMaxBits(); err != nil || max != 0 {
		t.Fatalf("60 agents, each also known from a peer: max_bits %d (%v), want 0", max, err)
	}
}

// resignKeySet is the key set raw carries signed again under c's current
// key state, as a daemon re-signs its set for a planned rotation
// (forward-secrecy FS-K17): the same set, a new signature.
func resignKeySet(t *testing.T, c *identity.Controller, raw []byte) []byte {
	t.Helper()
	es := keySetOf(t, raw)
	return signSet(t, c, &es)
}
