package aghub

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ANetResearch/ANetCore/seal"
)

// Relay storage, wire 3 (sealed-sender §3.1, core §2.16, SI-2).
//
// A relay row is a sealed envelope waiting for its recipient: the recipient,
// the envelope's digest, the class of the credential it came under and, for a
// delivery credential, that credential's id, its size, when it was queued,
// its outer expiry and the envelope bytes. It has no sender, no message kind,
// no interaction id and no key id: the sender of a first contact is known to
// this hub only for the length of the request (the session), and a send
// under a delivery credential names no sender at all.
//
// Two ids, for two readers: id is the recipient's cursor and what it acks;
// rid, sixteen random bytes, is what the sender is told and later asks about
// (/relay/status). Neither can be derived from the other.
//
// A row exists only while it is undelivered. Ack deletes it, and rows that
// nobody collects are deleted after the undelivered TTL. The store is opened
// with PRAGMA secure_delete=ON, so SQLite overwrites deleted row content and
// freed pages with zeros instead of leaving them in the file.
//
// relay_redelivery counts how often one env_digest was queued within a day
// (§4.2.1 step 9): a sender retrying an envelope its recipient already took
// is answered as a new message, but only three times a day.

// RelayMessage is one queued envelope.
type RelayMessage struct {
	ID        int64
	ToAID     string
	Size      int64
	CreatedAt int64 // unix milliseconds
	Payload   []byte
}

// ErrMailboxFull is RelayEnqueue's refusal when the recipient's undelivered
// messages have reached the message or byte quota of the whole mailbox
// (§4.2.2). The HTTP layer answers 507 mailbox_full.
var ErrMailboxFull = errors.New("hub: recipient mailbox full")

// ErrStrangersBusy is RelayEnqueue's refusal of a non-contact envelope when
// the recipient's non-contact share is full, or the delivery credential it
// came under already has MaxStrangerCapRows rows waiting (§4.2.2). Contact
// mail still fits. The HTTP layer answers 429 strangers_busy.
var ErrStrangersBusy = errors.New("hub: the recipient's share for non-contacts is full")

// ErrBadEnvelope is the refusal of bytes that are not a structurally valid
// sealed envelope addressed to the recipient (QueueEnvelope). The HTTP layer
// answers 400.
var ErrBadEnvelope = errors.New("hub: not a sealed envelope for this recipient")

// RedeliveryLimitedError is RelayEnqueue's refusal of an env_digest already
// queued MaxRedeliveries times in its RedeliveryWindow (§4.2.1 step 9). Wait
// is what is left of the window. The HTTP layer answers 429
// redelivery_limited.
type RedeliveryLimitedError struct{ Wait time.Duration }

func (e *RedeliveryLimitedError) Error() string {
	return fmt.Sprintf("hub: this envelope was queued %d times in %s", MaxRedeliveries, RedeliveryWindow)
}

// relayQuota is the per-recipient bound on undelivered messages, of the
// whole mailbox (Limits).
type relayQuota struct {
	messages int
	bytes    int64
}

// RelayItem is one envelope to queue (§4.2.1 step 10).
type RelayItem struct {
	To       string
	Envelope []byte
	// Digest is env_digest (core L4), the key of deduplication and of the
	// redelivery count.
	Digest [32]byte
	// Class is seal.CapClassContact or seal.CapClassStranger: the class of
	// the delivery credential, and stranger for a first contact (kind 0).
	Class uint64
	// CapID is the delivery credential's id; nil for a first contact.
	CapID []byte
	// Exp is outer key 8, nil when absent.
	Exp *uint64
}

// Queued is what RelayEnqueue did: queued a new row, or found the same
// envelope already waiting (Duplicate) and queued nothing.
type Queued struct {
	ID        int64
	RID       []byte
	Duplicate bool
}

// RIDLen is the length of a relay id (core §2.16).
const RIDLen = 16

// CheckEnvelope is the hub's structural check on an envelope it did not take
// through /relay/send: seal.ParseOuter (v2, a known suite, a 16-byte kid, an
// enc of the suite's length, a non-empty ct, a well-formed access) and
// outer.to == toAID. The hub does not open the envelope and cannot.
func CheckEnvelope(toAID string, envelope []byte) (*seal.SealedEnvelope, error) {
	outer, err := seal.ParseOuter(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadEnvelope, err)
	}
	if outer.To != toAID {
		return nil, fmt.Errorf("%w: the envelope is addressed to another recipient than the request names", ErrBadEnvelope)
	}
	return outer, nil
}

// SetRelayQuota sets the per-recipient bound on undelivered messages.
// Non-positive values keep the current bound.
func (s *Store) SetRelayQuota(messages int, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if messages > 0 {
		s.quota.messages = messages
	}
	if bytes > 0 {
		s.quota.bytes = bytes
	}
}

// RelayQueued is step 7 of /relay/send: the rid of the undelivered row of
// (to, digest), if there is one. It writes nothing.
func (s *Store) RelayQueued(to string, digest [32]byte) (rid []byte, ok bool, err error) {
	err = s.db.QueryRow(`SELECT rid FROM relay_message WHERE to_aid=? AND env_digest=?`, to, digest[:]).Scan(&rid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return rid, true, nil
}

// RelayEnqueue is steps 9 and 10 of /relay/send, in one write transaction:
//
//  1. the same envelope already waiting for the recipient (step 7 again, for
//     a send that raced this one): Duplicate, nothing written;
//  2. the envelope queued MaxRedeliveries times within RedeliveryWindow:
//     *RedeliveryLimitedError;
//  3. the kid (FS-H1): v030-todo(FS-3);
//  4. the mailbox: the whole of it (ErrMailboxFull), then for a non-contact
//     envelope the non-contact share and the credential's rows
//     (ErrStrangersBusy);
//  5. the row, with a new random rid, and the redelivery count.
//
// Contact mail counts only against the whole mailbox: a full non-contact
// share never keeps it out (SSR-H4, SI-14).
func (s *Store) RelayEnqueue(it RelayItem) (Queued, error) {
	if it.To == "" || len(it.Envelope) == 0 {
		return Queued{}, fmt.Errorf("%w: a recipient and an envelope are required", ErrBadEnvelope)
	}
	if it.Class != seal.CapClassContact && it.Class != seal.CapClassStranger {
		return Queued{}, fmt.Errorf("hub: class %d is neither contact nor stranger", it.Class)
	}
	if it.Class == seal.CapClassContact && it.CapID == nil {
		return Queued{}, errors.New("hub: contact mail comes only under a delivery credential")
	}
	q := s.QuotaFor(it.To)
	rid := make([]byte, RIDLen)
	if _, err := rand.Read(rid); err != nil {
		return Queued{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return Queued{}, err
	}
	defer tx.Rollback()
	// The time the row is accepted at is read inside the transaction
	// (core §2.16 created_at).
	now := s.now()
	nowMS := now.UnixMilli()
	var held []byte
	switch err := tx.QueryRow(`SELECT rid FROM relay_message WHERE to_aid=? AND env_digest=?`,
		it.To, it.Digest[:]).Scan(&held); {
	case err == nil:
		return Queued{RID: held, Duplicate: true}, nil
	case !errors.Is(err, sql.ErrNoRows):
		return Queued{}, err
	}
	var count, windowStart int64
	inWindow := false
	switch err := tx.QueryRow(`SELECT count, window_start FROM relay_redelivery WHERE env_digest=?`,
		it.Digest[:]).Scan(&count, &windowStart); {
	case err == nil:
		end := windowStart + RedeliveryWindow.Milliseconds()
		if nowMS < end {
			inWindow = true
			if count >= MaxRedeliveries {
				return Queued{}, &RedeliveryLimitedError{Wait: time.Duration(end-nowMS) * time.Millisecond}
			}
		}
	case !errors.Is(err, sql.ErrNoRows):
		return Queued{}, err
	}
	// v030-todo(FS-3): the kid of the envelope against the recipient's key
	// set (FS-H1, 409 kid_stale), here: after the duplicate check, before
	// the capacity (core G23).
	size := int64(len(it.Envelope))
	var n int
	var total int64
	if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size),0) FROM relay_message WHERE to_aid=?`,
		it.To).Scan(&n, &total); err != nil {
		return Queued{}, err
	}
	if n+1 > s.quota.messages || total+size > s.quota.bytes {
		return Queued{}, fmt.Errorf("%w: %d messages / %d bytes undelivered, limit %d messages / %d bytes",
			ErrMailboxFull, n, total, s.quota.messages, s.quota.bytes)
	}
	if it.Class == seal.CapClassStranger {
		if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size),0) FROM relay_message WHERE to_aid=? AND class=?`,
			it.To, seal.CapClassStranger).Scan(&n, &total); err != nil {
			return Queued{}, err
		}
		if int64(n)+1 > q.NonContactMsgs || total+size > q.NonContactBytes {
			return Queued{}, fmt.Errorf("%w: %d messages / %d bytes from non-contacts undelivered, share %d messages / %d bytes",
				ErrStrangersBusy, n, total, q.NonContactMsgs, q.NonContactBytes)
		}
		if it.CapID != nil {
			if err := tx.QueryRow(`SELECT COUNT(*) FROM relay_message WHERE to_aid=? AND cap_id=?`,
				it.To, it.CapID).Scan(&n); err != nil {
				return Queued{}, err
			}
			if n+1 > MaxStrangerCapRows {
				return Queued{}, fmt.Errorf("%w: %d messages undelivered under one credential, at most %d",
					ErrStrangersBusy, n, MaxStrangerCapRows)
			}
		}
	}
	var exp any
	if it.Exp != nil {
		if *it.Exp > uint64(1<<63-1) {
			return Queued{}, fmt.Errorf("%w: exp %d is beyond what this hub stores", ErrBadEnvelope, *it.Exp)
		}
		exp = int64(*it.Exp)
	}
	var capID any
	if it.CapID != nil {
		capID = it.CapID
	}
	res, err := tx.Exec(`INSERT INTO relay_message(rid, to_aid, env_digest, class, cap_id, size, created_at, exp, payload)
	                     VALUES(?,?,?,?,?,?,?,?,?)`,
		rid, it.To, it.Digest[:], it.Class, capID, size, nowMS, exp, it.Envelope)
	if err != nil {
		return Queued{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Queued{}, err
	}
	if inWindow {
		_, err = tx.Exec(`UPDATE relay_redelivery SET count=count+1 WHERE env_digest=?`, it.Digest[:])
	} else {
		_, err = tx.Exec(`INSERT INTO relay_redelivery(env_digest, count, window_start) VALUES(?,1,?)
		                  ON CONFLICT(env_digest) DO UPDATE SET count=1, window_start=excluded.window_start`,
			it.Digest[:], nowMS)
	}
	if err != nil {
		return Queued{}, err
	}
	if enqueueFault != nil {
		if err := enqueueFault(); err != nil {
			return Queued{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Queued{}, err
	}
	return Queued{ID: id, RID: rid}, nil
}

// enqueueFault, when a test sets it, runs after RelayEnqueue wrote the row
// and the redelivery count and before it commits: an error stands for the
// process dying there (P-SS-1). Nil outside tests.
var enqueueFault func() error

// QueueEnvelope queues an envelope for toAID that reached this hub without
// a credential checked here: the federation v2 forward of a peer hub
// (v030-todo(SS-6): /fed/v3/forward checks the credential and calls
// RelayEnqueue), an operator tool, a test. It is checked structurally
// (CheckEnvelope) and queued as non-contact mail, the class that cannot
// crowd out the recipient's contacts.
func (s *Store) QueueEnvelope(toAID string, envelope []byte) (Queued, error) {
	outer, err := CheckEnvelope(toAID, envelope)
	if err != nil {
		return Queued{}, err
	}
	digest, err := seal.EnvDigest(envelope)
	if err != nil {
		return Queued{}, fmt.Errorf("%w: %v", ErrBadEnvelope, err)
	}
	return s.RelayEnqueue(RelayItem{To: toAID, Envelope: envelope, Digest: digest,
		Class: seal.CapClassStranger, Exp: outer.Exp})
}

// RelayPoll returns undelivered envelopes for toAID with an id above
// afterID, oldest first. afterID 0 is the whole mailbox.
// limit <= 0 means 100. budget bounds the cumulative envelope bytes of one
// response; the first message is always returned, even when it alone
// exceeds the budget, so that one large message is still deliverable.
//
// afterID is the recipient's cursor (A2A-DESIGN §3.7, decision Q1). A
// daemon leaves an envelope it could not process yet in the mailbox (§3.6,
// class T), and without a cursor the oldest such envelopes fill every
// answer: anyone could hold back a node's newer mail by sending it a page
// of messages for interactions it does not know. With afterID the daemon
// reads on past them and returns to the head later. Ids only grow
// (AUTOINCREMENT), so "above afterID" is "queued after it".
func (s *Store) RelayPoll(toAID string, afterID int64, limit int, budget int64) ([]RelayMessage, error) {
	if limit <= 0 {
		limit = 100
	}
	if afterID < 0 {
		afterID = 0
	}
	rows, err := s.db.Query(
		`SELECT id, to_aid, size, created_at, payload FROM relay_message
		  WHERE to_aid=? AND id>? ORDER BY id LIMIT ?`, toAID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RelayMessage
	var acc int64
	for rows.Next() {
		var m RelayMessage
		if err := rows.Scan(&m.ID, &m.ToAID, &m.Size, &m.CreatedAt, &m.Payload); err != nil {
			return nil, err
		}
		if len(out) > 0 && acc+int64(len(m.Payload)) > budget {
			break
		}
		acc += int64(len(m.Payload))
		out = append(out, m)
	}
	return out, rows.Err()
}

// RelayAck deletes delivered envelopes, scoped to toAID so that a caller
// can only remove rows from its own mailbox. Returns how many rows were
// deleted. An id that is not in the mailbox (already acked, expired, or
// somebody else's) is skipped.
//
// relay_message uses AUTOINCREMENT, so a deleted id is never reused: a
// repeated ack for an id that was already deleted cannot remove a later
// message.
func (s *Store) RelayAck(toAID string, ids []int64) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	total := 0
	for _, id := range ids {
		res, err := tx.Exec(`DELETE FROM relay_message WHERE id=? AND to_aid=?`, id, toAID)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			total++
		}
	}
	return total, tx.Commit()
}

// RelayPending counts the undelivered envelopes queued for toAID.
func (s *Store) RelayPending(toAID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM relay_message WHERE to_aid=?`, toAID).Scan(&n)
	return n, err
}

// PurgeExpiredRelay deletes envelopes queued before now - ttl and returns
// how many were deleted. A message that nobody collected within the TTL is
// not going to be opened: the sender sets exp = ts + 14 days, and the
// recipient refuses an inner past exp. It also deletes the redelivery
// counts whose window has closed.
func (s *Store) PurgeExpiredRelay(ttl time.Duration, now time.Time) (int, error) {
	if ttl <= 0 {
		return 0, fmt.Errorf("hub: relay TTL must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM relay_message WHERE created_at < ?`,
		now.Add(-ttl).UnixMilli())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := s.db.Exec(`DELETE FROM relay_redelivery WHERE window_start <= ?`,
		now.Add(-RedeliveryWindow).UnixMilli()); err != nil {
		return int(n), err
	}
	return int(n), nil
}

// relayTables are the wire-3 relay tables (core §2.16). The small columns
// of relay_message come before payload on purpose: SQLite stores the tail
// of a large record in overflow pages, and a column placed after a
// multi-megabyte payload can only be read by walking that overflow chain.
// The capacity checks read size and class for every queued message of a
// recipient, so they must sit in the local part of the record.
var relayTables = []string{
	`CREATE TABLE IF NOT EXISTS relay_message (
	   id INTEGER PRIMARY KEY AUTOINCREMENT,
	   rid BLOB NOT NULL UNIQUE,
	   to_aid TEXT NOT NULL,
	   env_digest BLOB NOT NULL,
	   class INTEGER NOT NULL,
	   cap_id BLOB,
	   size INTEGER NOT NULL,
	   created_at INTEGER NOT NULL,
	   exp INTEGER,
	   payload BLOB NOT NULL,
	   UNIQUE(to_aid, env_digest)
	 )`,
	`CREATE TABLE IF NOT EXISTS relay_redelivery (
	   env_digest BLOB PRIMARY KEY,
	   count INTEGER NOT NULL,
	   window_start INTEGER NOT NULL
	 ) WITHOUT ROWID`,
}

// relayIndexes are created after relayTables.
var relayIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_relay_to ON relay_message(to_aid, id)`,
	`CREATE INDEX IF NOT EXISTS idx_relay_created ON relay_message(created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_relay_exp ON relay_message(exp) WHERE exp IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_relay_cap ON relay_message(to_aid, cap_id) WHERE cap_id IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_relay_redelivery ON relay_redelivery(window_start)`,
}

// Meta returns a hub_meta value and whether it is set.
func (s *Store) Meta(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM hub_meta WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// tableColumns returns the column names of a table (empty when the table
// does not exist).
func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

// agentRegistered reports whether aid has a registration here.
func (s *Store) agentRegistered(aid string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM agent WHERE aid=?`, aid).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ownerMbox is the mailbox signing key of the key set an agent registered
// here published (sealed-sender §2.4): found is false when aid is not
// registered here or has published no key set.
func (s *Store) ownerMbox(aid string) (mbox seal.Mbox, found bool, err error) {
	keyset, _, registered, err := s.LocalKeys(aid)
	if err != nil || !registered || keyset == nil {
		return seal.Mbox{}, false, err
	}
	signed, err := seal.UnmarshalSignedEncKeySet(keyset)
	if err != nil {
		return seal.Mbox{}, false, fmt.Errorf("hub: a stored key set does not decode: %w", err)
	}
	m, err := mboxOf(signed.Set)
	if err != nil {
		return seal.Mbox{}, false, fmt.Errorf("hub: a stored key set does not decode: %w", err)
	}
	return *m, true, nil
}
