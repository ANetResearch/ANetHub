package aghub

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/identity"
)

// A2A card admission (A2A-DESIGN §3.7, §10.3, §10.5).
//
// An agent submits its signed A2A AgentCard in /register's a2a_card field.
// The hub verifies it with ANetCore a2acard against the KEL the same
// registration submitted (and that RegisterAgent has just stored as an
// extension of the one held), applies the params.seq high-water rule
// against the card on file, and only then stores the bytes, rebuilds the
// skill and tag indexes, and derives the agent's directory name and
// capability ids from the card. The registry (registry.go) lists nothing
// else: a card that did not pass here is not stored, and a stored card
// that stops verifying is delisted.
//
// The card is kept as the exact bytes received. The signature covers a
// canonical form of those bytes, and re-encoding them with encoding/json
// would publish a card other than the one the agent signed.
//
// The hub does not import a2a-go: ANetCore a2acard is the verifier, the
// same code the daemon uses to check its own card before sending it.

// A2A card statuses reported by /register in card_status. Same names and
// meaning as keys_status.
const (
	CardStatusOK        = "ok"        // verified and stored: the first card, or a higher params.seq
	CardStatusUnchanged = "unchanged" // same params.seq and same canonical payload as the stored card
	CardStatusAbsent    = "absent"    // the registration carried no a2a_card
	CardStatusInvalid   = "invalid"   // did not verify (card_error names the a2acard code); not stored
	CardStatusConflict  = "conflict"  // lower params.seq, or the stored seq with another payload; not stored
)

// CardVerificationOK is the cardVerification of every registry entry: the
// hub lists only cards that verified (A2A-DESIGN §10.5).
const CardVerificationOK = "ok"

// maxA2ACardBytes bounds an A2A card (A2A-DESIGN §10.3); a2acard.Verify
// refuses a larger one before parsing it.
const maxA2ACardBytes = a2acard.MaxCardBytes

// migrateA2ACard brings agent_a2a_card to the admission schema and adds
// the skill and tag indexes.
//
// seq and payload_hash are the high-water mark (a2acard.Mark). verified_at
// is when the card last verified against the agent's KEL; NULL means the
// row is not listed, either because the KEL moved past the key that signed
// it or because it predates admission. search is the lowercased text the
// registry's q parameter matches. fed_seq orders the rows for the
// federation stream (§10.6), like agent_card.fed_seq.
func (s *Store) migrateA2ACard() error {
	for _, q := range []string{
		`ALTER TABLE agent_a2a_card ADD COLUMN seq INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE agent_a2a_card ADD COLUMN payload_hash BLOB`,
		`ALTER TABLE agent_a2a_card ADD COLUMN verified_at TEXT`,
		`ALTER TABLE agent_a2a_card ADD COLUMN search TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agent_a2a_card ADD COLUMN fed_seq INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.Exec(q); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("hub: migrate a2a card: %w", err)
		}
	}
	for _, q := range []string{
		// One row per skill of an admitted card. Written only by
		// admission, so a skill id here is one the agent signed.
		`CREATE TABLE IF NOT EXISTS agent_skill (
		   aid TEXT NOT NULL,
		   skill_id TEXT NOT NULL,
		   name TEXT NOT NULL DEFAULT '',
		   PRIMARY KEY (aid, skill_id)
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_agent_skill ON agent_skill(skill_id)`,
		// The union of the admitted card's skill tags.
		`CREATE TABLE IF NOT EXISTS agent_tag (
		   aid TEXT NOT NULL,
		   tag TEXT NOT NULL,
		   PRIMARY KEY (aid, tag)
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_agent_tag ON agent_tag(tag)`,
		`CREATE INDEX IF NOT EXISTS idx_a2a_card_fedseq ON agent_a2a_card(fed_seq)`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("hub: migrate a2a card: %w", err)
		}
	}
	return s.readmitLegacyA2ACards()
}

// readmitLegacyA2ACards verifies the rows stored before admission existed
// (no payload_hash): a card that verifies against its agent's stored KEL is
// admitted, anything else is deleted. Such rows exist only in development
// databases, since no wire-2 hub stored cards unverified in production.
func (s *Store) readmitLegacyA2ACards() error {
	rows, err := s.db.Query(
		`SELECT c.aid, c.card, a.kel FROM agent_a2a_card c LEFT JOIN agent a ON a.aid = c.aid
		  WHERE c.payload_hash IS NULL`)
	if err != nil {
		return fmt.Errorf("hub: migrate a2a card: %w", err)
	}
	type legacy struct {
		aid       string
		card, kel []byte
	}
	var pending []legacy
	for rows.Next() {
		var l legacy
		if err := rows.Scan(&l.aid, &l.card, &l.kel); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	now := time.Now()
	verify := func(aid string, card, kelBytes []byte) *a2acard.Verified {
		if len(kelBytes) == 0 {
			return nil // no agent row: nobody to speak for
		}
		kel, err := identity.UnmarshalKEL(kelBytes)
		if err != nil {
			return nil
		}
		v, err := a2acard.Verify(card, registrantResolver(aid, kel), uint64(now.UnixMilli()))
		if err != nil || validateCaps(skillIDs(v)) != nil {
			return nil
		}
		return v
	}
	for _, l := range pending {
		v := verify(l.aid, l.card, l.kel)
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if v == nil {
			_, err = tx.Exec(`DELETE FROM agent_a2a_card WHERE aid=?`, l.aid)
		} else {
			err = storeAdmittedA2ACard(tx, l.aid, l.card, v, now)
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("hub: migrate a2a card of %s: %w", l.aid, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// registrantResolver is the a2acard.Resolver for a card submitted by aid:
// it answers with the KEL aid registered with, and refuses every other
// AID, so a card that speaks for somebody else fails verification without
// the hub looking that AID up.
func registrantResolver(aid string, kel []identity.SignedEvent) a2acard.Resolver {
	return func(a string) ([]identity.SignedEvent, error) {
		if a != aid {
			return nil, fmt.Errorf("the card speaks for %s, not for the registrant %s", a, aid)
		}
		return kel, nil
	}
}

// RegisterA2ACard settles the A2A card of a registration that has just
// been written, and returns the card_status and card_error /register
// reports. raw is the a2a_card field (nil when absent) and kel the KEL the
// registration stored.
//
// A card that is refused leaves the stored one in place. The stored card
// is then verified again against kel: a registration may carry a rotated
// KEL, and a card signed by the key the rotation retired no longer
// verifies (a2acard.CodeKeyNotCurrent), so it is delisted until the agent
// re-signs it. Only the KEL changes between two such checks (notBefore
// only moves further into the past), so re-verifying on every
// registration is the same as re-verifying on every KEL change.
func (s *Store) RegisterA2ACard(aid string, raw json.RawMessage, kel []identity.SignedEvent, now time.Time) (status, detail string) {
	status = CardStatusAbsent
	if len(raw) > 0 {
		status, detail = s.AdmitA2ACard(aid, raw, kel, now)
		if status == CardStatusOK || status == CardStatusUnchanged {
			return status, detail
		}
	}
	if err := s.recheckA2ACard(aid, kel, now); err != nil {
		log.Printf("hub: re-verifying the A2A card of %s: %v", aid, err)
	}
	return status, detail
}

// AdmitA2ACard verifies an A2A card for aid against kel and applies the
// params.seq high-water rule (A2A-DESIGN §10.3). It returns CardStatusOK
// (stored), CardStatusUnchanged (the stored card again), CardStatusInvalid
// or CardStatusConflict; detail is the refusal, led by the a2acard code.
//
// On admission, in one transaction: the row (raw bytes, mark, verified_at,
// search text, fed_seq), the agent_skill and agent_tag indexes, and the
// agent's name and capability index, which the card now states (§10.5).
func (s *Store) AdmitA2ACard(aid string, raw []byte, kel []identity.SignedEvent, now time.Time) (status, detail string) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return CardStatusInvalid, "a2a_card must be a JSON object"
	}
	// Verify is pure, so it runs before the store mutex is taken.
	v, err := a2acard.Verify(raw, registrantResolver(aid, kel), uint64(now.UnixMilli()))
	if err != nil {
		return CardStatusInvalid, err.Error()
	}
	if v.AID != aid {
		// The resolver refuses every other AID, so this is unreachable;
		// it is the admission rule, stated where it is applied.
		return CardStatusInvalid, "the card speaks for " + v.AID + ", not for the registrant"
	}
	// The skill ids become the agent's capability ids, and the index
	// bounds apply to them as to ids declared at registration.
	if err := validateCaps(skillIDs(v)); err != nil {
		return CardStatusInvalid, "skill ids: " + err.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return CardStatusInvalid, "not stored: " + err.Error()
	}
	defer tx.Rollback()
	stored, storedRaw, err := a2aMark(tx, aid)
	if err != nil {
		return CardStatusInvalid, "not stored: " + err.Error()
	}
	decision, err := a2acard.CheckHighWater(stored, v.Mark())
	if err != nil {
		if a2acard.IsCode(err, a2acard.CodeSeqRollback) || a2acard.IsCode(err, a2acard.CodeSeqFork) {
			return CardStatusConflict, err.Error()
		}
		return CardStatusInvalid, err.Error()
	}
	status = CardStatusOK
	if decision == a2acard.Same {
		status = CardStatusUnchanged
		if bytes.Equal(raw, storedRaw) {
			// The same statement in the same bytes: refresh when it was
			// last verified and restate the derived fields, which the
			// registration that carried it has just overwritten. A row
			// that had been delisted is listed again, which is a change
			// for the federation stream.
			next, err := nextA2AFedSeq(tx)
			if err != nil {
				return CardStatusInvalid, "not stored: " + err.Error()
			}
			if _, err := tx.Exec(
				`UPDATE agent_a2a_card SET fed_seq = CASE WHEN verified_at IS NULL THEN ? ELSE fed_seq END,
				   verified_at=? WHERE aid=?`,
				next, verifiedStamp(now), aid); err != nil {
				return CardStatusInvalid, "not stored: " + err.Error()
			}
			if err := indexA2ACard(tx, aid, v); err != nil {
				return CardStatusInvalid, "not stored: " + err.Error()
			}
			if err := tx.Commit(); err != nil {
				return CardStatusInvalid, "not stored: " + err.Error()
			}
			return status, ""
		}
		// The same statement in other bytes, for example re-signed under
		// a rotated key: the stored signature may no longer verify, so
		// the new bytes replace it. Same rule as keys.go.
	}
	if err := storeAdmittedA2ACard(tx, aid, raw, v, now); err != nil {
		return CardStatusInvalid, "not stored: " + err.Error()
	}
	if err := tx.Commit(); err != nil {
		return CardStatusInvalid, "not stored: " + err.Error()
	}
	return status, ""
}

// recheckA2ACard verifies aid's listed card against kel. A card that no
// longer verifies is delisted: verified_at is cleared and its skill and
// tag rows removed, and the name and capability ids the registration
// declared stand. A card that still verifies restates the name and
// capability ids derived from it.
func (s *Store) recheckA2ACard(aid string, kel []identity.SignedEvent, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw []byte
	err := s.db.QueryRow(`SELECT card FROM agent_a2a_card WHERE aid=? AND verified_at IS NOT NULL`,
		aid).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	v, verr := a2acard.Verify(raw, registrantResolver(aid, kel), uint64(now.UnixMilli()))
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if verr != nil {
		log.Printf("hub: the A2A card of %s no longer verifies against its KEL and is delisted until it is re-signed: %v",
			aid, verr)
		next, err := nextA2AFedSeq(tx)
		if err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM agent_skill WHERE aid=?`,
			`DELETE FROM agent_tag WHERE aid=?`,
		} {
			if _, err := tx.Exec(q, aid); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`UPDATE agent_a2a_card SET verified_at=NULL, fed_seq=? WHERE aid=?`,
			next, aid); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := indexA2ACard(tx, aid, v); err != nil {
		return err
	}
	return tx.Commit()
}

// a2aMark reads the stored high-water mark and bytes of aid's card; nil
// when none is stored.
func a2aMark(tx *sql.Tx, aid string) (*a2acard.Mark, []byte, error) {
	var seq uint64
	var hash, raw []byte
	err := tx.QueryRow(`SELECT seq, payload_hash, card FROM agent_a2a_card WHERE aid=?`, aid).
		Scan(&seq, &hash, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if len(hash) != 32 {
		// A row with no mark is not a card this hub admitted (migration
		// readmits or deletes such rows); the next card replaces it.
		return nil, raw, nil
	}
	m := &a2acard.Mark{Seq: seq}
	copy(m.PayloadHash[:], hash)
	return m, raw, nil
}

// storeAdmittedA2ACard writes an admitted card and everything derived
// from it, in tx.
func storeAdmittedA2ACard(tx *sql.Tx, aid string, raw []byte, v *a2acard.Verified, now time.Time) error {
	next, err := nextA2AFedSeq(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO agent_a2a_card(aid, card, stored_at, seq, payload_hash, verified_at, search, fed_seq)
		 VALUES(?,?,?,?,?,?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET card=excluded.card, stored_at=excluded.stored_at,
		   seq=excluded.seq, payload_hash=excluded.payload_hash, verified_at=excluded.verified_at,
		   search=excluded.search, fed_seq=excluded.fed_seq`,
		aid, raw, nowStamp(), v.Seq, v.PayloadHash[:], verifiedStamp(now), cardSearchText(raw, v), next); err != nil {
		return err
	}
	return indexA2ACard(tx, aid, v)
}

// indexA2ACard rebuilds aid's agent_skill and agent_tag rows from a
// verified card, and makes the card's name and skill ids the agent's
// directory name and capability ids (A2A-DESIGN §10.5: /agents keeps its
// shape, and for an agent with an A2A card the two come from the card).
func indexA2ACard(tx *sql.Tx, aid string, v *a2acard.Verified) error {
	ids := skillIDs(v)
	capsJSON, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM agent_skill WHERE aid=?`,
		`DELETE FROM agent_tag WHERE aid=?`,
		`DELETE FROM agent_cap WHERE aid=?`,
	} {
		if _, err := tx.Exec(q, aid); err != nil {
			return err
		}
	}
	for _, sk := range v.Skills {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO agent_skill(aid, skill_id, name) VALUES(?,?,?)`,
			aid, sk.ID, sk.Name); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO agent_cap(aid, cap) VALUES(?,?)`, aid, sk.ID); err != nil {
			return err
		}
		for _, tag := range sk.Tags {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO agent_tag(aid, tag) VALUES(?,?)`, aid, tag); err != nil {
				return err
			}
		}
	}
	_, err = tx.Exec(`UPDATE agent SET name=?, caps=? WHERE aid=?`, v.Name, string(capsJSON), aid)
	return err
}

// nextA2AFedSeq is the next position on the A2A card federation stream.
func nextA2AFedSeq(tx *sql.Tx) (int64, error) {
	var next int64
	err := tx.QueryRow(`SELECT COALESCE(MAX(fed_seq),0)+1 FROM agent_a2a_card`).Scan(&next)
	return next, err
}

// skillIDs lists a verified card's skill ids in card order.
func skillIDs(v *a2acard.Verified) []string {
	ids := make([]string, 0, len(v.Skills))
	for _, sk := range v.Skills {
		ids = append(ids, sk.ID)
	}
	return ids
}

// cardSearchText is what the registry's q parameter matches: the card's
// name and description and its skill names, lowercased here so that the
// match folds case beyond ASCII (SQLite's lower() does not).
//
// description is read with encoding/json; Verify has refused cards whose
// member names collide under case folding, so this reads the member
// Verify checked.
func cardSearchText(raw []byte, v *a2acard.Verified) string {
	var c struct {
		Description string `json:"description"`
	}
	_ = json.Unmarshal(raw, &c)
	parts := []string{v.Name, c.Description}
	for _, sk := range v.Skills {
		parts = append(parts, sk.Name)
	}
	return strings.ToLower(strings.Join(parts, "\n"))
}

func verifiedStamp(now time.Time) string { return now.UTC().Format(time.RFC3339) }
