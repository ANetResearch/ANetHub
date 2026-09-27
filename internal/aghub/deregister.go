package aghub

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"
)

// Leaving a hub.
//
// There was no way to. An agent could join, and joining is what makes it
// findable and deliverable-to — but an agent that moved to another hub
// left a live registration behind, and the old hub went on accepting
// delegations for it into a mailbox nobody would ever poll again. Work
// addressed to that agent was accepted, queued, and silently swallowed.
//
// Found in production: a node was repointed at a second hub, the first
// hub still listed it as local, and a cross-hub call was relayed into the
// dead mailbox instead of crossing. Nothing errored. The delegation
// simply never arrived, and the requester waited.
//
// So this is the other half of registration, and it is deliberately NOT
// an operator action. The agent leaves under its own signature, for the
// same reason it joins under its own signature: which hub speaks for you
// is yours to decide, and a hub that could evict an agent — or an
// operator who could deregister somebody else's — would be deciding it
// for them.
//
// What it does not solve, and should not be read as solving: an agent
// that simply stops existing. There is no heartbeat here and no expiry.
// A node that dies leaves the same stale row, and the honest position is
// that this fixes moving, not disappearing.

// Deregister removes an agent's local registration.
//
// The evidence stays. Reviews, receipts and the credit ledger are records
// of things that happened, and they did happen — deleting them because a
// party moved on would rewrite history to match the directory. What goes
// is the routing: the registry row, the capability index and the card, so
// nothing new is addressed here.
//
// Undelivered mail is reported rather than dropped silently. Somebody
// sent that work and is waiting for it; the count is the only warning
// they will get.
func (s *Store) Deregister(aid string) (undelivered int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Only what is still queued. Since wire 2 a relay row exists only
	// while it is undelivered (ack deletes it), so every row addressed
	// to this AID is a message somebody is waiting on.
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM relay_message WHERE to_aid=?`,
		aid).Scan(&undelivered); err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return undelivered, err
	}
	defer tx.Rollback()
	var found int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM agent WHERE aid=?`, aid).Scan(&found); err != nil {
		return undelivered, err
	}
	if found == 0 {
		return undelivered, fmt.Errorf("hub: %s is not registered here", aid)
	}
	// The key history survives the departure.
	//
	// Deleting the agent row removed the only copy of the KEL this hub
	// held, so /agents/{aid}/kel began answering 404 the moment an agent
	// left. The evidence it had signed — every receipt, every review —
	// stayed in the tables and stayed served, and became uncheckable
	// against any key this hub could produce. `anet verify --receipt
	// --hub` is the third-party verification story, and it broke for
	// every agent that had ever left.
	//
	// Keeping routing and keeping proof are separate decisions, and only
	// the first is what leaving asks for. Found by prodtest 9q.
	var kel []byte
	var visibility string
	if err := tx.QueryRow(`SELECT kel, visibility FROM agent WHERE aid=?`, aid).Scan(&kel, &visibility); err != nil {
		return undelivered, err
	}
	if len(kel) > 0 {
		if _, err := tx.Exec(
			`INSERT INTO departed_kel(aid, kel, at) VALUES(?,?,?)
			 ON CONFLICT(aid) DO UPDATE SET kel=excluded.kel, at=excluded.at`,
			aid, kel, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return undelivered, err
		}
	}
	// The card is withdrawn, not dropped.
	//
	// DELETE FROM agent_card ended the routing here and said nothing
	// anywhere else. /fed/v1/cards is an increment keyed on fed_seq, so a
	// deleted row simply stops appearing and a peer whose cursor is past
	// it observes no change: every peer that had synced this card kept it
	// and went on publishing an agent that had left. Withdrawing writes a
	// row the stream can carry. Read against the visibility BEFORE the
	// registration goes, because a card no peer was ever offered is
	// removed rather than announced — see withdrawCard in card.go.
	if err := withdrawCard(tx, aid, withdrawDeparted, federates(visibility)); err != nil {
		return undelivered, err
	}
	// The encryption key set and the A2A card are routing too: they are
	// how a sender reaches this agent here, and it has left.
	for _, q := range []string{
		`DELETE FROM agent_cap WHERE aid=?`,
		`DELETE FROM agent_keys WHERE aid=?`,
		`DELETE FROM agent_a2a_card WHERE aid=?`,
		`DELETE FROM agent WHERE aid=?`,
	} {
		if _, err := tx.Exec(q, aid); err != nil {
			return undelivered, err
		}
	}
	return undelivered, tx.Commit()
}

// hDeregister lets an agent leave, under its own signature (relayauth v2,
// action "deregister"). An agent says who it is by holding its key, here
// as everywhere.
func (s *Server) hDeregister(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	if _, err := s.store.AgentKEL(aid); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not registered"})
		return
	}
	if _, ok := s.authSelf(w, r, relayauth.ActionDeregister, signedBodyLimit); !ok {
		return
	}
	undelivered, err := s.store.Deregister(aid)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out := map[string]any{"aid": aid, "status": "deregistered", "undelivered": undelivered}
	if undelivered > 0 {
		out["warning"] = fmt.Sprintf(
			"%d message(s) were queued for this agent and will not be delivered — "+
				"whoever sent them is waiting", undelivered)
	}
	writeJSON(w, http.StatusOK, out)
}
