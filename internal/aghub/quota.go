package aghub

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"
)

// What one recipient takes from senders that are not yet its contacts
// (sealed-sender §2.12, §4.2.2, SSR-H5, SSR-H22).
//
// Every recipient gets the same defaults: first contacts at 30 a minute
// (bursts of 60), and a non-contact part of its mailbox of 500 messages or
// 64 MiB, inside the mailbox's total. They are constants, not flags (SSR-H21).
// The one thing an operator can do is raise them for one AID, with anet-hub
// quota <AID> (for an agent that strangers are expected to call a lot, say).
// Lowering below the defaults is refused: a recipient could otherwise be cut
// off from every new contact without knowing why. Setting a value back to its
// default is how a raise is undone.
//
// The raised values live in quota_override, in the weekly backup. anet-hub
// quota runs beside the hub, in another process; the hub process reads the
// table again at least every quotaRefresh, so a change takes effect within a
// minute.

// The defaults (sealed-sender §2.12).
const (
	DefaultFirstContactsPerMin = 30
	DefaultNonContactMsgs      = 500
	DefaultNonContactBytes     = 64 << 20
)

// maxQuotaValue bounds a raised value: anything above is not a quota but a
// typing error, and the bytes of a MiB value stay far from overflowing.
const maxQuotaValue = 1<<31 - 1

// quotaRefresh is how long the hub process uses what it last read of
// quota_override.
const quotaRefresh = 30 * time.Second

// Quota is what one recipient takes from senders that are not its contacts.
type Quota struct {
	// FirstContactsPerMin is the recipient's first-contact bucket, refilled
	// per minute; it holds FirstContactsBurst.
	FirstContactsPerMin int64
	// NonContactMsgs and NonContactBytes bound the mailbox rows of class 2
	// (every first contact included), inside the mailbox's total.
	NonContactMsgs  int64
	NonContactBytes int64
}

// DefaultQuota is the quota of every recipient the operator did not raise.
func DefaultQuota() Quota {
	return Quota{FirstContactsPerMin: DefaultFirstContactsPerMin,
		NonContactMsgs: DefaultNonContactMsgs, NonContactBytes: DefaultNonContactBytes}
}

// FirstContactsBurst is how many first contacts the bucket holds: two
// minutes' worth (30 a minute, bursts of 60).
func (q Quota) FirstContactsBurst() int64 { return 2 * q.FirstContactsPerMin }

// QuotaChange is what anet-hub quota sets: nil leaves a value as it is.
// NonContactMiB is in MiB, as the operator types it.
type QuotaChange struct {
	FirstContactsPerMin *int64
	NonContactMsgs      *int64
	NonContactMiB       *int64
}

// QuotaBelowDefaultError is SetQuota's refusal of a value under its default
// (quota_below_default). Field names the value as the command line does
// (first-contacts-per-min, non-contact-msgs, non-contact-mib) and Default is
// its default in the same unit. Nothing was written.
type QuotaBelowDefaultError struct {
	Field   string
	Default int64
}

func (e *QuotaBelowDefaultError) Error() string {
	return fmt.Sprintf("hub: %s cannot be below its default %d", e.Field, e.Default)
}

// ErrQuotaTooLarge is SetQuota's refusal of a value above maxQuotaValue.
var ErrQuotaTooLarge = errors.New("hub: a quota value is out of range")

// The names of the values, as anet-hub quota spells its options.
const (
	QuotaFirstContactsPerMin = "first-contacts-per-min"
	QuotaNonContactMsgs      = "non-contact-msgs"
	QuotaNonContactMiB       = "non-contact-mib"
)

// QuotaOf reads aid's quota from the database: what the operator raised, and
// the defaults for the rest. It is what anet-hub quota shows.
func (s *Store) QuotaOf(aid string) (Quota, error) {
	q := DefaultQuota()
	err := s.db.QueryRow(`SELECT first_contacts_per_min, non_contact_msgs, non_contact_bytes
	    FROM quota_override WHERE aid=?`, aid).Scan(&q.FirstContactsPerMin, &q.NonContactMsgs, &q.NonContactBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultQuota(), nil
	}
	return q, err
}

// Check refuses a change that SetQuota would refuse: a value below its
// default (*QuotaBelowDefaultError, the first such in the order of the
// options) or above the largest a quota takes (ErrQuotaTooLarge).
func (ch QuotaChange) Check() error {
	def := DefaultQuota()
	for _, c := range []struct {
		name  string
		v     *int64
		least int64
	}{
		{QuotaFirstContactsPerMin, ch.FirstContactsPerMin, def.FirstContactsPerMin},
		{QuotaNonContactMsgs, ch.NonContactMsgs, def.NonContactMsgs},
		{QuotaNonContactMiB, ch.NonContactMiB, def.NonContactBytes >> 20},
	} {
		switch {
		case c.v == nil:
		case *c.v < c.least:
			return &QuotaBelowDefaultError{Field: c.name, Default: c.least}
		case *c.v > maxQuotaValue:
			return ErrQuotaTooLarge
		}
	}
	return nil
}

// SetQuota changes the values ch names for aid and returns the quota now in
// the database. A change Check refuses writes nothing; a value equal to its
// default is that default again, and a quota back at every default leaves no
// row.
func (s *Store) SetQuota(aid string, ch QuotaChange) (Quota, error) {
	if err := ch.Check(); err != nil {
		return Quota{}, err
	}
	def := DefaultQuota()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return Quota{}, err
	}
	defer tx.Rollback()
	q := def
	err = tx.QueryRow(`SELECT first_contacts_per_min, non_contact_msgs, non_contact_bytes
	    FROM quota_override WHERE aid=?`, aid).Scan(&q.FirstContactsPerMin, &q.NonContactMsgs, &q.NonContactBytes)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Quota{}, err
	}
	if ch.FirstContactsPerMin != nil {
		q.FirstContactsPerMin = *ch.FirstContactsPerMin
	}
	if ch.NonContactMsgs != nil {
		q.NonContactMsgs = *ch.NonContactMsgs
	}
	if ch.NonContactMiB != nil {
		q.NonContactBytes = *ch.NonContactMiB << 20
	}
	if q == def {
		_, err = tx.Exec(`DELETE FROM quota_override WHERE aid=?`, aid)
	} else {
		_, err = tx.Exec(`INSERT INTO quota_override(aid, first_contacts_per_min, non_contact_msgs, non_contact_bytes)
		    VALUES(?,?,?,?) ON CONFLICT(aid) DO UPDATE SET first_contacts_per_min=excluded.first_contacts_per_min,
		    non_contact_msgs=excluded.non_contact_msgs, non_contact_bytes=excluded.non_contact_bytes`,
			aid, q.FirstContactsPerMin, q.NonContactMsgs, q.NonContactBytes)
	}
	if err != nil {
		return Quota{}, err
	}
	if err := tx.Commit(); err != nil {
		return Quota{}, err
	}
	s.quotas.invalidate()
	return q, nil
}

// QuotaFor is aid's quota in force in the hub process: the raised values as
// last read from quota_override, at most quotaRefresh ago, and the defaults
// for the rest. The relay reads it for every send to aid that is not from a
// contact. If the table cannot be read, the last values read stay in force.
func (s *Store) QuotaFor(aid string) Quota {
	return s.quotas.lookup(s, aid)
}

// quotaCache is quota_override as the hub process last read it. The table is
// small (one row per AID an operator raised), so it is read whole.
type quotaCache struct {
	mu     sync.Mutex
	rows   map[string]Quota
	readAt time.Time
	valid  bool
}

func (c *quotaCache) lookup(s *Store, aid string) Quota {
	now := s.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.valid || now.Sub(c.readAt) >= quotaRefresh || now.Before(c.readAt) {
		if rows, err := readQuotaOverrides(s.db); err == nil {
			c.rows, c.readAt, c.valid = rows, now, true
		}
		// On an error the last rows read stay, and the next lookup tries
		// again.
	}
	if q, ok := c.rows[aid]; ok {
		return q
	}
	return DefaultQuota()
}

// invalidate makes the next lookup read the table: a change made in this
// process takes effect at once.
func (c *quotaCache) invalidate() {
	c.mu.Lock()
	c.valid = false
	c.mu.Unlock()
}

func readQuotaOverrides(db *sql.DB) (map[string]Quota, error) {
	rows, err := db.Query(`SELECT aid, first_contacts_per_min, non_contact_msgs, non_contact_bytes FROM quota_override`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Quota{}
	for rows.Next() {
		var aid string
		var q Quota
		if err := rows.Scan(&aid, &q.FirstContactsPerMin, &q.NonContactMsgs, &q.NonContactBytes); err != nil {
			return nil, err
		}
		// SetQuota never writes a value under its default; a row that
		// holds one anyway (written by hand) does not lower anything.
		def := DefaultQuota()
		q.FirstContactsPerMin = max(q.FirstContactsPerMin, def.FirstContactsPerMin)
		q.NonContactMsgs = max(q.NonContactMsgs, def.NonContactMsgs)
		q.NonContactBytes = max(q.NonContactBytes, def.NonContactBytes)
		out[aid] = q
	}
	return out, rows.Err()
}
