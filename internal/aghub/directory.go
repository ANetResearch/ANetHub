package aghub

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// The directory (sealed-sender §2.9, §4.2.8; core §2.8, L9, L10).
//
// Every agent registered here with a key set has one directory entry: its
// AID, this hub's AID as its home, its key history, its key set, its A2A
// card when one is listed, and the witness notice of its key history's tip
// when there is one (dirbox.DirEntry). The hub seals the entry under the
// agent's AID (dirbox.Seal) and files the box under the AID's directory
// hash h. Only a party that already knows the AID opens the box; the hub
// publishes h and the box and nothing else of the entry. There is no
// browsable or hidden entry: every one is sealed the same way (SSR-W17).
//
// A daemon looks an agent up without naming it (SSR-D14): it asks
// POST /directory:bucket for every entry whose h starts with a short
// prefix of the h it wants, a bucket, and opens the one it can. The hub
// answers buckets no narrower than dir_max_bits bits, the widest prefix at
// which every bucket of the merged directory holds at least DirMinBucket
// entries (SSR-W18), so the hub learns a bucket and never the agent.
//
// The entry is recomputed in the transaction that changes any part of it
// (SSR-H17): a registration (which may extend the key history), a key set,
// a card admitted, delisted or withdrawn, and a new witness notice
// (RefreshDirEntry). An entry whose plaintext did not change keeps its box,
// so the bytes a bucket serves do not tell anyone that an agent restarted
// and registered again.
//
// An entry larger than dirbox.MaxBoxLen is left out of the directory and
// counted (DirEntriesTooLarge). Within the limits /register applies to a
// key history, a key set and a card, no entry reaches it.

// The directory's constants (sealed-sender §2.12). None of them is a flag.
const (
	// DirMinBucket (k) is the fewest entries a bucket at dir_max_bits holds.
	DirMinBucket = 32
	// DirWholeTableBelow is the size of the merged directory below which
	// dir_max_bits is 0: a query asks for the whole directory.
	DirWholeTableBelow = 64
	// DirMaxBitsEvery is how old dir_max_bits may get before it is
	// computed again.
	DirMaxBitsEvery = time.Hour
	// DirPageBytes bounds one bucket answer; a larger bucket is answered in
	// pages (next).
	DirPageBytes = 8 << 20
	// DirBucketPerMinute and DirBucketBurst bound /directory:bucket per
	// client address (limits.go clientIP: an IPv4 address, an IPv6 /64).
	DirBucketPerMinute = 60
	DirBucketBurst     = 30
)

// dirBucketBodyLimit bounds a /directory:bucket body: a prefix and a cursor
// of at most 43 characters each, in JSON.
const dirBucketBodyLimit = 4 << 10

// DirBucketRequest is the POST /directory:bucket body (core §2.12.2):
// prefix, the first ceil(bits/8) bytes of a directory hash with the bits
// past bits set to zero, in base64url; bits, at most dir_max_bits; and
// cursor, the next of the previous page of the same bucket.
type DirBucketRequest struct {
	Prefix *string `json:"prefix"`
	Bits   *uint   `json:"bits"`
	Cursor string  `json:"cursor,omitempty"`
}

// DirBucketEntry is one entry of a bucket: the directory hash and the box,
// both base64url.
type DirBucketEntry struct {
	H   string `json:"h"`
	Box string `json:"box"`
}

// DirBucketResponse is the /directory:bucket answer. Next is set when the
// bucket continues on another page. Partial is set (only ever true) when a
// peer hub's part of the bucket is missing from it, which a reader must not
// take for "no such agent" (SSR-W21); a hub answers partial only once it
// merges its peers' buckets (federation v3).
type DirBucketResponse struct {
	MaxBits uint             `json:"max_bits"`
	Entries []DirBucketEntry `json:"entries"`
	Next    string           `json:"next,omitempty"`
	Partial bool             `json:"partial,omitempty"`
}

// dirEntriesTooLarge counts the entries left out of the directory for being
// larger than dirbox.MaxBoxLen (dir-entry-too-large).
var dirEntriesTooLarge atomic.Int64

// DirEntriesTooLarge is how many times this process left an entry out of
// the directory because its box would be larger than dirbox.MaxBoxLen.
func DirEntriesTooLarge() int64 { return dirEntriesTooLarge.Load() }

// dirNoticeOf returns the witness notice (NoticeWire) aid's directory entry
// carries, or nil for none.
// v030-todo(KEL-5): read the notice the hub keeps for aid's KEL tip
// (notice_cache), and call RefreshDirEntry when it changes (at most once
// every 10 minutes per AID, KEL H-11).
func (s *Store) dirNoticeOf(q rowQuerier, aid string) ([]byte, error) {
	if s.dirNotice == nil {
		return nil, nil
	}
	return s.dirNotice(q, aid)
}

// RefreshDirEntry recomputes aid's directory entry (SSR-H17), for a change
// to it that is not written by the store itself: a new witness notice.
func (s *Store) RefreshDirEntry(aid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.refreshDirTx(tx, aid); err != nil {
		return err
	}
	return tx.Commit()
}

// refreshDirTx recomputes aid's directory entry in tx, from what tx sees:
// the key history of the agent row, the key set, the listed A2A card and the
// witness notice, with this hub as the home. An agent without a key set has
// no entry (nobody could write to it), nor has one whose entry would be
// larger than dirbox.MaxBoxLen. An AID with no agent row is left alone.
func (s *Store) refreshDirTx(tx *sql.Tx, aid string) error {
	var kel, keys, card, oldH, oldBox []byte
	err := tx.QueryRow(
		`SELECT a.kel, k.keyset, c.card, a.dir_hash, a.dir_box FROM agent a
		   LEFT JOIN agent_keys k ON k.aid = a.aid
		   LEFT JOIN agent_a2a_card c ON c.aid = a.aid AND c.verified_at IS NOT NULL
		  WHERE a.aid = ?`, aid).Scan(&kel, &keys, &card, &oldH, &oldBox)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	notice, err := s.dirNoticeOf(tx, aid)
	if err != nil {
		return err
	}
	h, box := sealDirEntry(aid, oldH, oldBox, &dirbox.DirEntry{
		AID: aid, Home: s.hubAID, KEL: kel, Keys: keys, Card: card, Notice: notice})
	if bytes.Equal(h, oldH) && bytes.Equal(box, oldBox) {
		return nil
	}
	_, err = tx.Exec(`UPDATE agent SET dir_hash=?, dir_box=? WHERE aid=?`, h, box, aid)
	return err
}

// sealDirEntry returns the hash and box e is filed under, or nil, nil when
// aid has no entry: no key set, no home (a store without a hub identity,
// as in a test), an AID or a field the directory cannot carry, or a box over
// dirbox.MaxBoxLen. When the box filed now (oldH, oldBox) opens to the same
// entry, it is kept.
func sealDirEntry(aid string, oldH, oldBox []byte, e *dirbox.DirEntry) (h, box []byte) {
	if len(e.Keys) == 0 || e.Home == "" {
		return nil, nil
	}
	pt, err := e.Marshal()
	if err != nil {
		log.Printf("hub: the directory entry of %s cannot be made and is left out of the directory: %v", aid, err)
		return nil, nil
	}
	if n := len(pt) + dirbox.Overhead; n > dirbox.MaxBoxLen {
		dirEntriesTooLarge.Add(1)
		log.Printf("hub: the directory entry of %s is %d bytes, over the %d a directory carries; it is left out of the directory",
			aid, n, dirbox.MaxBoxLen)
		return nil, nil
	}
	if oldBox != nil {
		if was, err := dirbox.Open(aid, oldH, oldBox); err == nil {
			if again, err := was.Marshal(); err == nil && bytes.Equal(again, pt) {
				return oldH, oldBox
			}
		}
	}
	if h, err = dirbox.Hash(aid); err != nil {
		log.Printf("hub: the directory entry of %s cannot be made and is left out of the directory: %v", aid, err)
		return nil, nil
	}
	if box, err = dirbox.Seal(aid, e, nil); err != nil {
		if errors.Is(err, dirbox.ErrTooLarge) {
			dirEntriesTooLarge.Add(1)
		}
		log.Printf("hub: the directory entry of %s is left out of the directory: %v", aid, err)
		return nil, nil
	}
	return h, box
}

// ---- dir_max_bits ----

// dirBitsCache holds dir_max_bits and when it was computed.
type dirBitsCache struct {
	mu    sync.Mutex
	bits  int
	at    time.Time
	valid bool
}

// DirMaxBits is dir_max_bits: the widest bucket prefix, in bits, at which
// every bucket of the merged directory (the entries of agents registered
// here and the listed A2A cards learned from peers) holds at least
// DirMinBucket entries; 0 below DirWholeTableBelow entries (SSR-W18). It is
// computed again when it is DirMaxBitsEvery old.
//
// This is the hub's report. A daemon cannot check it, and caps the bits it
// asks for at a constant of its own whatever this says (SSR-D15a).
func (s *Store) DirMaxBits() (int, error) {
	c := &s.dirBits
	c.mu.Lock()
	defer c.mu.Unlock()
	now := s.now()
	if c.valid && now.Sub(c.at) < DirMaxBitsEvery && !now.Before(c.at) {
		return c.bits, nil
	}
	prefixes, err := s.dirPrefixes()
	if err != nil {
		return 0, err
	}
	c.bits, c.at, c.valid = dirMaxBits(prefixes), now, true
	return c.bits, nil
}

// dirPrefixes returns the first 64 bits of the directory hash of every entry
// of the merged directory.
func (s *Store) dirPrefixes() ([]uint64, error) {
	var out []uint64
	rows, err := s.db.Query(`SELECT dir_hash FROM agent WHERE dir_box IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return nil, err
		}
		if len(h) == dirbox.HashLen {
			out = append(out, prefix64(h))
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.db.Query(`SELECT f.aid FROM fed_a2a_card f WHERE f.verified_at IS NOT NULL
	    AND NOT EXISTS (SELECT 1 FROM agent a WHERE a.aid = f.aid)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var aid string
		if err := rows.Scan(&aid); err != nil {
			return nil, err
		}
		if h, err := dirbox.Hash(aid); err == nil {
			out = append(out, prefix64(h))
		}
	}
	return out, rows.Err()
}

// prefix64 is the first 64 bits of h, big-endian.
func prefix64(h []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(h[i])
	}
	return v
}

// dirMaxBits is the largest b such that each of the 2^b buckets of b-bit
// prefixes holds at least DirMinBucket of the hashes (given by their first
// 64 bits), and 0 for fewer than DirWholeTableBelow hashes. A bucket that
// holds k entries at b+1 bits holds 2k at b, so the b that qualify are
// 0..max and the search stops at the first that does not.
func dirMaxBits(prefixes []uint64) int {
	n := len(prefixes)
	if n < DirWholeTableBelow {
		return 0
	}
	best := 0
	for b := 1; b < 64 && n>>b >= DirMinBucket; b++ {
		counts := make([]int, 1<<b)
		for _, p := range prefixes {
			counts[p>>(64-b)]++
		}
		for _, c := range counts {
			if c < DirMinBucket {
				return best
			}
		}
		best = b
	}
	return best
}

// ---- buckets ----

// dirBucketEntryOverhead is what one entry adds to an answer besides its two
// base64url strings: {"h":"","box":""} and a comma.
const dirBucketEntryOverhead = len(`{"h":"","box":""},`)

// dirBucketAnswerOverhead is room for the rest of an answer: max_bits, next,
// partial and the braces around them.
const dirBucketAnswerOverhead = 1 << 10

// DirBucket returns the entries of agents registered here whose directory
// hash starts with prefix (bits bits; dirbox.CheckPrefix), in hash order and
// after the hash after when after is not nil, as many as fit in one answer
// of DirPageBytes. next is the hash the next page starts after, nil when the
// bucket ends on this page.
//
// Only this hub's own entries are in it: an agent learned from a peer is in
// that peer's bucket (SSR-W19, SSR-W20).
func (s *Store) DirBucket(prefix []byte, bits int, after []byte) (entries []DirBucketEntry, next []byte, err error) {
	if err := dirbox.CheckPrefix(prefix, bits); err != nil {
		return nil, nil, err
	}
	lo, hi := bucketRange(prefix, bits)
	from := `dir_hash >= ?`
	if after != nil {
		if bytes.Compare(after, lo) < 0 || bytes.Compare(after, hi) > 0 {
			return nil, nil, fmt.Errorf("hub: the cursor is outside the bucket")
		}
		from, lo = `dir_hash > ?`, after
	}
	rows, err := s.db.Query(`SELECT dir_hash, dir_box FROM agent
	    WHERE dir_box IS NOT NULL AND `+from+` AND dir_hash <= ? ORDER BY dir_hash`, lo, hi)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	entries = []DirBucketEntry{}
	size := dirBucketAnswerOverhead
	for rows.Next() {
		var h, box []byte
		if err := rows.Scan(&h, &box); err != nil {
			return nil, nil, err
		}
		e := DirBucketEntry{H: wire3.EncodeB64URL(h), Box: wire3.EncodeB64URL(box)}
		n := len(e.H) + len(e.Box) + dirBucketEntryOverhead
		if size+n > DirPageBytes && len(entries) > 0 {
			last, err := wire3.DecodeB64URL("h", entries[len(entries)-1].H)
			if err != nil {
				return nil, nil, err
			}
			return entries, last, nil
		}
		size += n
		entries = append(entries, e)
	}
	return entries, nil, rows.Err()
}

// bucketRange is the lowest and the highest directory hash with the bits-bit
// prefix prefix.
func bucketRange(prefix []byte, bits int) (lo, hi []byte) {
	lo = make([]byte, dirbox.HashLen)
	hi = bytes.Repeat([]byte{0xff}, dirbox.HashLen)
	copy(lo, prefix)
	copy(hi, prefix)
	if r := bits % 8; r != 0 {
		hi[len(prefix)-1] |= 0xff >> r
	}
	return lo, hi
}

// hasIdentityHeaders reports whether r carries any of the headers that name
// a signer (X-ANet-AID, X-ANet-Seq, X-ANet-Sig), which an anonymous route
// refuses (core CORE-K15).
func hasIdentityHeaders(r *http.Request) bool {
	for _, h := range []string{relayauth.HeaderAID, relayauth.HeaderSeq, relayauth.HeaderSig} {
		if _, ok := r.Header[http.CanonicalHeaderKey(h)]; ok {
			return true
		}
	}
	return false
}

// hDirectoryBucket serves POST /directory:bucket (core §2.12.2; sealed-
// sender §2.9, §4.2.8), in this order:
//
//  1. the client address's bucket (DirBucketPerMinute, DirBucketBurst):
//     429 rate_limited with Retry-After. Every query spends a token, refused
//     or not;
//  2. no identity header: 400 identity_headers_not_allowed;
//  3. the body, decoded strictly, with prefix and bits: 400 bad_request,
//     413 too_large;
//  4. prefix in base64url, ceil(bits/8) bytes, the bits past bits zero,
//     bits at most 256: 400 bad_request;
//  5. bits at most dir_max_bits: 400 bucket_too_narrow with max_bits;
//  6. a cursor this hub gave for this bucket: 400 bad_request;
//  7. 200 with the bucket's entries, a page at a time.
func (s *Server) hDirectoryBucket(w http.ResponseWriter, r *http.Request) {
	if ok, wait := s.dirLimiter.allow(clientIP(r)); !ok {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait,
			Error: "Too many directory queries from this address; query again after the seconds in Retry-After."})
		return
	}
	if hasIdentityHeaders(r) {
		wire3.Refuse(w, wire3.ReasonIdentityHeadersNotAllowed)
		return
	}
	var req DirBucketRequest
	if !wire3.ReadStrict(w, r, dirBucketBodyLimit, &req) {
		return
	}
	if req.Prefix == nil || req.Bits == nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "A directory query carries prefix and bits; add them and send again."})
		return
	}
	prefix, err := wire3.DecodeB64URL("prefix", *req.Prefix)
	if err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	if *req.Bits > dirbox.HashBits || dirbox.CheckPrefix(prefix, int(*req.Bits)) != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The member \"prefix\" must be the first ceil(bits/8) bytes of a directory hash with the bits past bits set to zero; send that prefix and send again."})
		return
	}
	bits := int(*req.Bits)
	maxBits, err := s.store.DirMaxBits()
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	if bits > maxBits {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBucketTooNarrow, Extra: map[string]any{"max_bits": maxBits}})
		return
	}
	var after []byte
	if req.Cursor != "" {
		after, err = wire3.DecodeB64URL("cursor", req.Cursor)
		lo, hi := bucketRange(prefix, bits)
		if err != nil || len(after) != dirbox.HashLen || bytes.Compare(after, lo) < 0 || bytes.Compare(after, hi) > 0 {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
				Error: "The member \"cursor\" is not one this hub gave for this bucket; query the bucket again without it."})
			return
		}
	}
	entries, next, err := s.store.DirBucket(prefix, bits, after)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	out := DirBucketResponse{MaxBits: uint(maxBits), Entries: entries}
	if next != nil {
		out.Next = wire3.EncodeB64URL(next)
	}
	writeJSON(w, http.StatusOK, out)
}

// DirMaxBits is the store's dir_max_bits for GET /hub/identity. A failure
// to compute it is logged and reported as 0, the whole directory, which
// is never narrower than the hub's real answer.
func (s *Server) DirMaxBits() int {
	n, err := s.store.DirMaxBits()
	if err != nil {
		log.Printf("hub: computing dir_max_bits: %v", err)
		return 0
	}
	return n
}
