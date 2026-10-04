package aghub

import (
	"container/list"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Revoking delivery credentials (sealed-sender §4.2.5, SSR-H10, SSR-H11).
//
// A recipient hands out delivery credentials (capabilities) signed with its
// mailbox key; the hub admits a credentialed send only if the credential is
// signed by the recipient's current mailbox key and not revoked. The owner
// revokes credentials it issued with POST /mailbox/revoke, under its own
// signature (relayauth "revoke"); the hub keeps the revoked ids for 31 days,
// one day longer than any credential lives, plus clock margin.
//
// What the hub keeps is (owner, cap_id, revoked_at): the owner, and an id that
// is 16 random bytes. It never learns who holds a credential, and nothing
// here is logged with the owner or the id (SSR-H19).
//
// A list is bounded per owner. An owner that would go past the bound is told
// revocation_list_full and nothing of the batch is written; its daemon then
// starts a new mailbox key epoch instead, which invalidates every credential
// the old key signed at once (sealed-sender §4.3.8 item 4).
//
// The table is in the weekly backup (deploy/hub-db-roll.sh): a hub restored
// from it still refuses what was revoked. What the backup misses, the owner's
// daemon pushes again when it next registers, comparing its own count with
// the revocations the registration answer carries (SSR-D21).

// The bounds of revocation (sealed-sender §2.12).
const (
	// RevocationKeep is how long a revocation is kept: credentials live at
	// most 30 days, and a day of margin covers the clocks.
	RevocationKeep = 31 * 24 * time.Hour
	// MaxRevocationsPerOwner is how many unexpired revocations one owner may
	// have here.
	MaxRevocationsPerOwner = 100_000
	// MaxRevokeBatch is how many ids one POST /mailbox/revoke carries.
	MaxRevokeBatch = 1000
)

// revokeBodyLimit bounds a /mailbox/revoke body: a thousand 22-character ids
// in JSON are about 25 KiB.
const revokeBodyLimit = 64 << 10

// MailboxRevokeRequest is the POST /mailbox/revoke body (core §2.12.2):
// 1 to MaxRevokeBatch capability ids, each 16 bytes in base64url. An id given
// twice counts once.
type MailboxRevokeRequest struct {
	CapIDs []string `json:"cap_ids"`
}

// MailboxRevokeResponse is the answer: revoked is how many of the ids were not
// revoked before, total how many unexpired revocations the owner now has
// here (the revocations of a /register answer).
type MailboxRevokeResponse struct {
	Revoked uint64 `json:"revoked"`
	Total   uint64 `json:"total"`
}

// ErrRevocationListFull is RevokeCaps's refusal of a batch that would take
// the owner past MaxRevocationsPerOwner. Nothing of the batch is written.
var ErrRevocationListFull = errors.New("hub: the revocation list of this mailbox is full")

// revocationCutoff is the revoked_at at or before which a revocation has
// expired at now: one is kept while now - revoked_at < RevocationKeep.
func revocationCutoff(now time.Time) int64 { return now.Add(-RevocationKeep).UnixMilli() }

// RevokeCaps revokes the capability ids ids (each seal.CapIDLen bytes) that
// owner issued, in one transaction. An id already revoked and not expired is
// left as it is (its 31 days run from the first revocation); one whose
// revocation expired is revoked again from now. When the new ones would take
// the owner past MaxRevocationsPerOwner unexpired revocations, nothing is
// written and the error is ErrRevocationListFull. It returns how many ids
// were newly revoked and the owner's unexpired total afterwards.
func (s *Store) RevokeCaps(owner string, ids [][]byte) (revoked, total int, err error) {
	for _, id := range ids {
		if len(id) != seal.CapIDLen {
			return 0, 0, fmt.Errorf("hub: a capability id is %d bytes, want %d", len(id), seal.CapIDLen)
		}
	}
	now := s.now()
	cutoff := revocationCutoff(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	if err := tx.QueryRow(`SELECT COUNT(*) FROM cap_revocation WHERE owner=? AND revoked_at>?`,
		owner, cutoff).Scan(&total); err != nil {
		return 0, 0, err
	}
	seen := map[string]bool{}
	var fresh [][]byte
	for _, id := range ids {
		if seen[string(id)] {
			continue
		}
		seen[string(id)] = true
		var live int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM cap_revocation WHERE owner=? AND cap_id=? AND revoked_at>?`,
			owner, id, cutoff).Scan(&live); err != nil {
			return 0, 0, err
		}
		if live == 0 {
			fresh = append(fresh, id)
		}
	}
	if total+len(fresh) > MaxRevocationsPerOwner {
		return 0, total, ErrRevocationListFull
	}
	at := now.UnixMilli()
	for _, id := range fresh {
		if _, err := tx.Exec(`INSERT INTO cap_revocation(owner, cap_id, revoked_at) VALUES(?,?,?)
		    ON CONFLICT(owner, cap_id) DO UPDATE SET revoked_at=excluded.revoked_at`, owner, id, at); err != nil {
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	s.revoked.add(owner, fresh, at)
	return len(fresh), total + len(fresh), nil
}

// RevocationCount is how many unexpired revocations owner has here: the
// total of /mailbox/revoke and the revocations of /register (SSR-D21).
func (s *Store) RevocationCount(owner string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM cap_revocation WHERE owner=? AND revoked_at>?`,
		owner, revocationCutoff(s.now())).Scan(&n)
	return n, err
}

// CapRevoked reports whether owner revoked the capability capID and the
// revocation has not expired. It is the revocation check of /relay/send
// step 2 and /fed/v3/forward step 6, for an owner registered here
// (sealed-sender §4.2.1, §4.2.5). Answers come from an in-process cache in
// front of the table's primary key; RevokeCaps keeps it current.
func (s *Store) CapRevoked(owner string, capID []byte) (bool, error) {
	now := s.now()
	if v, ok := s.revoked.get(owner, capID, now); ok {
		return v, nil
	}
	gen := s.revoked.generation()
	var at int64
	err := s.db.QueryRow(`SELECT revoked_at FROM cap_revocation WHERE owner=? AND cap_id=?`, owner, capID).Scan(&at)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		s.revoked.put(gen, owner, capID, 0)
		return false, nil
	case err != nil:
		return false, err
	}
	s.revoked.put(gen, owner, capID, at)
	return at > revocationCutoff(now), nil
}

// PurgeExpiredRevocations deletes the revocations that have expired at now
// (kept RevocationKeep) and returns how many.
func (s *Store) PurgeExpiredRevocations() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM cap_revocation WHERE revoked_at<=?`, revocationCutoff(s.now()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RunRevocationJanitor deletes expired revocations once at start and then
// every interval, until ctx ends. The hub process runs it hourly.
func (s *Store) RunRevocationJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, err := s.PurgeExpiredRevocations(); err != nil {
			log.Printf("hub: purging expired revocations: %v", err)
		} else if n > 0 {
			log.Printf("hub: purged %d revocation(s) older than %s", n, RevocationKeep)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// hMailboxRevoke is POST /mailbox/revoke: the owner revokes credentials it
// issued (relayauth "revoke", sealed-sender SSR-H10, SSR-H11).
//
//	the signature of a registered agent (401 otherwise)
//	the body: strict JSON, 1 to MaxRevokeBatch ids, each 16 bytes of base64url (400 bad_request)
//	the list: past MaxRevocationsPerOwner, 429 revocation_list_full, nothing written
//	200 {revoked, total}
func (s *Server) hMailboxRevoke(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authRegistered(w, r, relayauth.ActionRevoke, revokeBodyLimit)
	if !ok {
		return
	}
	var req MailboxRevokeRequest
	if err := wire3.DecodeStrict(a.Body, &req); err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	if len(req.CapIDs) == 0 || len(req.CapIDs) > MaxRevokeBatch {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The member \"cap_ids\" holds 1 to " + strconv.Itoa(MaxRevokeBatch) +
				" capability ids; send them in batches of that size."})
		return
	}
	ids := make([][]byte, len(req.CapIDs))
	for i, c := range req.CapIDs {
		id, err := wire3.DecodeB64URLSize("cap_ids["+strconv.Itoa(i)+"]", c, seal.CapIDLen)
		if err != nil {
			wire3.RefuseDecode(w, err)
			return
		}
		ids[i] = id
	}
	revoked, total, err := s.store.RevokeCaps(a.AID, ids)
	switch {
	case errors.Is(err, ErrRevocationListFull):
		wire3.Refuse(w, wire3.ReasonRevocationListFull)
		return
	case err != nil:
		wire3.Internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, MailboxRevokeResponse{Revoked: uint64(revoked), Total: uint64(total)})
}

// ---- the in-process cache in front of cap_revocation ----

// revokedCacheSize bounds the cache: entries are (owner, cap_id) pairs that
// a send has asked about recently.
const revokedCacheSize = 1 << 16

// revokedCache remembers, per (owner, cap_id), the revoked_at the table holds
// (0 for none), so that a send checks the table only for a credential it has
// not seen lately. RevokeCaps writes through it after committing. A read
// that raced with a revocation is not cached: put compares the generation
// the reader saw before reading the table with the current one, which every
// revocation and every deregistration advances.
type revokedCache struct {
	mu      sync.Mutex
	gen     uint64
	order   *list.List // front: most recently used; values are *revokedEntry
	entries map[string]*list.Element
}

type revokedEntry struct {
	key string
	at  int64 // revoked_at, unix ms; 0: not revoked
}

func revokedKey(owner string, capID []byte) string {
	return owner + "\x00" + string(capID)
}

func (c *revokedCache) init() {
	if c.entries == nil {
		c.entries = map[string]*list.Element{}
		c.order = list.New()
	}
}

// get is the cached answer for (owner, capID) at now, if there is one.
func (c *revokedCache) get(owner string, capID []byte, now time.Time) (revoked, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	el, ok := c.entries[revokedKey(owner, capID)]
	if !ok {
		return false, false
	}
	c.order.MoveToFront(el)
	at := el.Value.(*revokedEntry).at
	return at != 0 && at > revocationCutoff(now), true
}

// generation is what a reader passes to put after reading the table.
func (c *revokedCache) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// put caches what a reader read, unless a revocation or deregistration
// happened since it took gen.
func (c *revokedCache) put(gen uint64, owner string, capID []byte, at int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return
	}
	c.set(revokedKey(owner, capID), at)
}

// set stores one entry; the caller holds mu.
func (c *revokedCache) set(key string, at int64) {
	c.init()
	if el, ok := c.entries[key]; ok {
		el.Value.(*revokedEntry).at = at
		c.order.MoveToFront(el)
		return
	}
	c.entries[key] = c.order.PushFront(&revokedEntry{key: key, at: at})
	for c.order.Len() > revokedCacheSize {
		last := c.order.Back()
		delete(c.entries, last.Value.(*revokedEntry).key)
		c.order.Remove(last)
	}
}

// add records committed revocations of owner, revoked at at (unix ms). An
// id the cache holds is marked revoked; one it does not hold is left for the
// next reader, who reads the committed row.
func (c *revokedCache) add(owner string, ids [][]byte, at int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	for _, id := range ids {
		if el, ok := c.entries[revokedKey(owner, id)]; ok {
			el.Value.(*revokedEntry).at = max(at, 1)
		}
	}
}

// forget drops every entry: the table changed in a way the cache does not
// follow (an owner deregistered, its revocations with it).
func (c *revokedCache) forget() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.entries = nil
	c.order = nil
}
