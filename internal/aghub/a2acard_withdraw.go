package aghub

import (
	"bytes"
	"fmt"
	"log"
)

// Withdrawing an A2A card, and the head of the A2A card federation stream
// (A2A-DESIGN §3.7, §10.1, §10.6; 0017 Q6).
//
// An agent that stops having a public skill stops publishing a card. Left
// alone, the hub would go on listing the last card it admitted, inviting
// callers to a skill the agent no longer serves. So /register takes
// "a2a_card": null as "withdraw my card": the card row and its skill and
// tag index rows are deleted, the agent's directory name and capability
// ids go back to what the registration declared (RegisterAgent has just
// written them), a peer that learned the card is told on /fed/v2/cards,
// and card_status says "withdrawn". An absent a2a_card still means "no
// change": a daemon that predates the field, or one that only refreshes
// its registration, must not unpublish a card by omission.
//
// Withdrawing is authorized like the rest of the registration (the
// request is signed by the registrant's KEL); there is no card to verify,
// and nothing is withdrawn but the registrant's own.

// CardStatusWithdrawn is the card_status of a registration that carried
// "a2a_card": null: the hub holds no A2A card for the agent now, whether
// or not it held one before.
const CardStatusWithdrawn = "withdrawn"

// withdrawReasonAgent is the federation withdrawal reason when the agent
// itself withdrew its card.
const withdrawReasonAgent = "card-withdrawn"

// isNullCard reports an a2a_card field that is JSON null.
func isNullCard(raw []byte) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// WithdrawA2ACard deletes aid's A2A card and its index rows in one
// transaction, after putting a withdrawal on the federation stream when
// the agent federates and a card was there to withdraw.
func (s *Store) WithdrawA2ACard(aid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Before the delete: withdrawA2ACard names only an AID whose card row
	// exists, and only for an agent whose visibility federates.
	if fed, err := agentFederates(tx, aid); err != nil {
		return err
	} else if fed {
		if err := withdrawA2ACard(tx, aid, withdrawReasonAgent); err != nil {
			return err
		}
	}
	for _, q := range []string{
		`DELETE FROM agent_a2a_card WHERE aid=?`,
		`DELETE FROM agent_skill WHERE aid=?`,
		`DELETE FROM agent_tag WHERE aid=?`,
	} {
		if _, err := tx.Exec(q, aid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// migrateA2AFedSeqHead creates the stored head of the A2A card stream and
// seeds it from the rows already on the stream.
//
// The next position used to be MAX(fed_seq)+1 over the cards and the
// withdrawals. A row deleted at the head (a card withdrawn by an agent that
// does not federate, an operator's delete) then gave its position to the
// next card, and a position a reader may already have passed meant two
// different entries. The head only moves forward.
func (s *Store) migrateA2AFedSeqHead() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS a2a_fed_seq (
		   id INTEGER PRIMARY KEY CHECK (id = 1),
		   last INTEGER NOT NULL
		 )`,
		`INSERT OR IGNORE INTO a2a_fed_seq(id, last) SELECT 1, MAX(
		   (SELECT COALESCE(MAX(fed_seq),0) FROM agent_a2a_card),
		   (SELECT COALESCE(MAX(fed_seq),0) FROM a2a_card_withdrawal))`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("hub: migrate a2a card stream head: %w", err)
		}
	}
	return nil
}

// nextA2AFedSeq takes the next position on the A2A card federation stream,
// which the cards and their withdrawals share (fed_a2acard.go). It never
// returns a position given out before, even when the row that held it has
// been deleted. The rows are consulted too, for one an older binary (the
// admin tool) wrote past the stored head.
//
// One statement moves the head and reads it back: some callers pass the
// pool rather than a transaction (SetVisibility, the key set), and the
// admin tool writes from another process, so an UPDATE and a separate
// SELECT could both read the position a concurrent writer took.
func nextA2AFedSeq(x cardStore) (int64, error) {
	var next int64
	err := x.QueryRow(`UPDATE a2a_fed_seq SET last = MAX(last,
	    (SELECT COALESCE(MAX(fed_seq),0) FROM agent_a2a_card),
	    (SELECT COALESCE(MAX(fed_seq),0) FROM a2a_card_withdrawal)) + 1 WHERE id = 1
	  RETURNING last`).Scan(&next)
	return next, err
}

// logCardHome records a card whose relay interface names another hub than
// this one (home, this hub's public base URL). It is not refused: the hub
// knows its own address only from configuration or from the request, and
// behind a reverse proxy either may differ from what agents use. A peer
// reading the card from the federation stream goes by the card
// (fed_a2acard.go, §10.6).
func logCardHome(aid string, card []byte, home string) {
	relay := cardRelayHub(card)
	if relay == "" || home == "" || hubKey(relay) == hubKey(home) {
		return
	}
	log.Printf("hub: the A2A card of %s names relay hub %q, but this hub is %q; kept (a card is not refused for its URL)",
		aid, relay, home)
}
