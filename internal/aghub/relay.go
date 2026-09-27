package aghub

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/seal"
)

// Relay storage, wire 2 (A2A-DESIGN §3.7, §9 row "relay 存储", SI-2).
//
// A relay row is a sealed envelope waiting for its recipient and nothing
// else: id, to_aid, size, created_at and the envelope bytes. The sender,
// the message kind and the interaction id are inside the ciphertext and
// are not stored here; the hub learns the sender at send time from the
// authentication header and uses it only for rate limiting (§2 X1).
//
// A row exists only while it is undelivered. Ack deletes it, and rows
// that nobody collects are deleted after the undelivered TTL. The store is
// opened with PRAGMA secure_delete=ON, so SQLite overwrites deleted row
// content and freed pages with zeros instead of leaving them in the file.

// RelayMessage is one queued envelope.
type RelayMessage struct {
	ID        int64
	ToAID     string
	Size      int64
	CreatedAt int64 // unix milliseconds
	Payload   []byte
}

// ErrMailboxFull is returned by RelayEnqueue when the recipient's
// undelivered messages have reached the message or byte quota. The HTTP
// layer answers 507.
var ErrMailboxFull = errors.New("hub: recipient mailbox full")

// ErrBadEnvelope is returned by RelayEnqueue when the bytes are not a
// structurally valid sealed envelope addressed to the recipient. The HTTP
// layer answers 400.
var ErrBadEnvelope = errors.New("hub: not a sealed envelope for this recipient")

// relayQuota is the per-recipient bound on undelivered messages.
type relayQuota struct {
	messages int
	bytes    int64
}

// CheckEnvelope is the hub's structural check on an envelope before it is
// relayed (§3.7): seal.ParseOuter (v == 1, a known suite, a 16-byte kid,
// an enc of the suite's length, a non-empty ct) and outer.to == toAID.
// The hub does not open the envelope and cannot; this only refuses bytes
// that no recipient could open, so that plaintext or misaddressed payloads
// are not stored.
func CheckEnvelope(toAID string, envelope []byte) error {
	outer, err := seal.ParseOuter(envelope)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadEnvelope, err)
	}
	if outer.To != toAID {
		return fmt.Errorf("%w: envelope is addressed to %s, the request names %s",
			ErrBadEnvelope, outer.To, toAID)
	}
	return nil
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

// RelayEnqueue queues a sealed envelope for toAID and returns its id.
//
// The envelope is checked structurally (CheckEnvelope) and against the
// recipient's quota in the same transaction as the insert, so two
// concurrent sends cannot both pass a quota that only one of them fits
// under.
func (s *Store) RelayEnqueue(toAID string, envelope []byte) (int64, error) {
	if toAID == "" || len(envelope) == 0 {
		return 0, fmt.Errorf("%w: to_aid and envelope are required", ErrBadEnvelope)
	}
	if err := CheckEnvelope(toAID, envelope); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var n int
	var total int64
	if err := tx.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(size),0) FROM relay_message WHERE to_aid=?`,
		toAID).Scan(&n, &total); err != nil {
		return 0, err
	}
	size := int64(len(envelope))
	if n+1 > s.quota.messages || total+size > s.quota.bytes {
		return 0, fmt.Errorf("%w: %d messages / %d bytes undelivered, limit %d messages / %d bytes",
			ErrMailboxFull, n, total, s.quota.messages, s.quota.bytes)
	}
	res, err := tx.Exec(
		`INSERT INTO relay_message(to_aid, size, created_at, payload) VALUES(?,?,?,?)`,
		toAID, size, time.Now().UnixMilli(), envelope)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
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
// answer: anyone registered could hold back a node's newer mail by sending
// it a page of messages for interactions it does not know. With afterID
// the daemon reads on past them and returns to the head later. Ids only
// grow (AUTOINCREMENT), so "above afterID" is "queued after it".
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
// not going to be opened: the sender sets exp = ts + 14 days (§3.5), and
// the recipient refuses an inner past exp.
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
	return int(n), nil
}

// relayTableV2 is the wire-2 relay table. The small columns come before
// payload on purpose: SQLite stores the tail of a large record in overflow
// pages, and a column placed after a multi-megabyte payload can only be
// read by walking that overflow chain. The quota check reads size for
// every queued message of a recipient, so size must sit in the local part
// of the record.
const relayTableV2 = `CREATE TABLE IF NOT EXISTS relay_message (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   to_aid TEXT NOT NULL,
   size INTEGER NOT NULL,
   created_at INTEGER NOT NULL,
   payload BLOB NOT NULL
 )`

// relayIndexesV2 are created after migrateRelayV2, because the wire-1
// table had an index of the same purpose over columns that no longer
// exist.
var relayIndexesV2 = []string{
	`CREATE INDEX IF NOT EXISTS idx_relay_to ON relay_message(to_aid, id)`,
	`CREATE INDEX IF NOT EXISTS idx_relay_created ON relay_message(created_at)`,
}

// migrateRelayV2 rebuilds a wire-1 relay_message table into the wire-2
// shape.
//
// Only undelivered rows are copied; from_aid, kind, interaction_id and
// delivered_at are dropped. The old table is dropped in the same
// transaction, and with secure_delete=ON its pages are overwritten with
// zeros as they are freed. The WAL is then checkpointed and truncated, so
// the old page images do not remain in hub.db-wal either.
//
// The copied rows are wire-1 plaintext payloads, not sealed envelopes. A
// wire-2 daemon refuses them as undecodable (§3.6 step 1, class P), acks
// them, and the ack deletes them. They are copied rather than dropped
// because the migration rule is "keep what is still undelivered"; the
// production cleanup of §9 removes wire-1 content by a separate,
// operator-approved script.
//
// The AUTOINCREMENT counter is carried over, so no new envelope receives
// an id that a daemon may still hold from before the upgrade.
//
// Cost: with secure_delete=ON, dropping the old table writes every page it
// occupied once more, as zeros, through the WAL, and the checkpoint then
// writes them into hub.db. The WAL therefore grows to about the size of
// the old table before it is truncated, and the first start of a wire-2
// hub on a large wire-1 database needs that much free disk and the time
// to write it twice.
func (s *Store) migrateRelayV2() error {
	cols, err := tableColumns(s.db, "relay_message")
	if err != nil {
		return err
	}
	if !cols["from_aid"] && !cols["delivered_at"] {
		return nil
	}
	var lastSeq int64
	_ = s.db.QueryRow(`SELECT COALESCE(MAX(seq),0) FROM sqlite_sequence WHERE name='relay_message'`).Scan(&lastSeq)
	var maxID int64
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(id),0) FROM relay_message`).Scan(&maxID); err != nil {
		return fmt.Errorf("hub: migrate relay: %w", err)
	}
	if maxID > lastSeq {
		lastSeq = maxID
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmts := []string{
		strings.Replace(relayTableV2, "relay_message", "relay_message_v2", 1),
		// created_at was RFC 3339 text; strftime('%s') reads it (fractional
		// seconds and the Z suffix included). A value it cannot read gets
		// the migration time, so the TTL still applies to the row.
		`INSERT INTO relay_message_v2(id, to_aid, size, created_at, payload)
		   SELECT id, to_aid, length(payload),
		          COALESCE(CAST(strftime('%s', created_at) AS INTEGER) * 1000, ?),
		          payload
		     FROM relay_message WHERE delivered_at IS NULL`,
		`DROP TABLE relay_message`,
		`ALTER TABLE relay_message_v2 RENAME TO relay_message`,
	}
	for _, q := range stmts {
		var err error
		if strings.Contains(q, "?") {
			_, err = tx.Exec(q, time.Now().UnixMilli())
		} else {
			_, err = tx.Exec(q)
		}
		if err != nil {
			return fmt.Errorf("hub: migrate relay: %w", err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM sqlite_sequence WHERE name IN ('relay_message','relay_message_v2')`); err != nil {
		return fmt.Errorf("hub: migrate relay: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO sqlite_sequence(name, seq) VALUES('relay_message', ?)`, lastSeq); err != nil {
		return fmt.Errorf("hub: migrate relay: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("hub: migrate relay: %w", err)
	}
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("hub: migrate relay: checkpoint: %w", err)
	}
	return nil
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
