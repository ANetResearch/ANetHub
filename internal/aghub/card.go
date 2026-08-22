package aghub

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/identity"
)

// Cards make a registration attributable to the agent that made it.
//
// The register challenge signs an action, an AID and a timestamp. It
// proves who is calling and covers nothing they said, so this hub could
// change an agent's name or capability list and no party could tell —
// including the agent. That is tolerable for a hub someone chose to
// trust. It is not tolerable for a directory other people search, and it
// becomes untenable the moment directories federate, where the whole
// property being relied on is that a peer can hide a card and never
// invent one.
//
// A card is an ADP AgentCard: subject, capabilities, a monotonic seq and
// a detached JWS over the lot. ANetCore implements the signing, the
// admission gate and the high-water rule, so this file is bookkeeping.

// cardMajors is the schema major this hub admits.
var cardMajors = map[uint16]bool{1: true}

// admitCard verifies a card against the registrant's own key history and
// stores it.
//
// Failure is not fatal to the registration. A node running an older build
// sends no card at all, and refusing it would make an upgrade of this hub
// look like an outage to everyone who had not upgraded — so a
// registration without a verifiable card still registers, and simply has
// nothing attributable behind it.
func (s *Store) AdmitCard(aid string, raw json.RawMessage, kel []identity.SignedEvent) error {
	if len(raw) == 0 {
		return nil
	}
	var card adp.AgentCard
	if err := json.Unmarshal(raw, &card); err != nil {
		return fmt.Errorf("card malformed: %w", err)
	}
	// A card must speak for the agent registering it. Admitting one whose
	// subject is somebody else would let any registrant publish claims in
	// another agent's name — the exact forgery cards exist to prevent.
	if card.SubjectDID != aid {
		return fmt.Errorf("card subject %s is not the registrant %s", card.SubjectDID, aid)
	}
	high, err := s.cardHighWater(aid)
	if err != nil {
		return err
	}
	if _, err := adp.AdmitCard(&card, time.Now(), high, kel, cardMajors, nil); err != nil {
		return fmt.Errorf("card refused: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO agent_card(aid, seq, card, stored_at) VALUES(?,?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET seq=excluded.seq, card=excluded.card, stored_at=excluded.stored_at`,
		aid, card.Seq, []byte(raw), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) cardHighWater(aid string) (uint64, error) {
	var seq uint64
	err := s.db.QueryRow(`SELECT seq FROM agent_card WHERE aid=?`, aid).Scan(&seq)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return 0, nil
	}
	return seq, err
}

// AgentCard returns the signed card an agent published, if any.
func (s *Store) AgentCard(aid string) (json.RawMessage, error) {
	var raw []byte
	err := s.db.QueryRow(`SELECT card FROM agent_card WHERE aid=?`, aid).Scan(&raw)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return json.RawMessage(raw), nil
}
