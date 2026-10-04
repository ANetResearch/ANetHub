package aghub

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Leaving a hub, and every other way an agent stops being registered here.
//
// There is exactly one function that removes an agent from this hub,
// DeregisterTx (hub-payment-privacy PAY-O1, core CORE-K27). Every path goes
// through it: the agent leaving under its own signature, a deactivated key
// history (KEL H-4), an operator revoking an admission (anet-hub admissions
// revoke) or deleting it from the admin console, and the sweep of accounts
// that never collected their mail. Each of them therefore leaves the same
// things behind and takes the same things away.
//
// What stays is the evidence and the money. Reviews, receipts and the credit
// ledger are records of things that happened; the balance is still a debt
// of this hub. The key history stays too, as a tombstone in departed_kel.
// That is what keeps "a key history may only grow" (KEL H-1) true for an
// agent that is gone: whoever copied its data directory can sign a fork from
// an earlier event with the key in it, and only the tombstone stops the fork
// from registering as the agent.
//
// What goes is the routing: the registry row, the capability index, the
// cards, the key set, the mailbox and every other row that makes the agent
// reachable here (deregSteps).
//
// Sessions live only in the hub process's memory (sealed-sender SSR-H7),
// where another process cannot reach them. A deregistration therefore writes
// dereg_event in its transaction; the hub process runs its callbacks
// (OnDeregistered) right after its own deregistrations, and within a second
// for one committed by another process (PAY-O2).

// The reasons DeregisterTx takes, one per caller.
const (
	DeregSelf     = "self"     // POST /agents/{aid}/deregister
	DeregDip      = "dip"      // the key history ends in dip (KEL H-4)
	DeregRevoked  = "revoked"  // anet-hub admissions revoke
	DeregInactive = "inactive" // the inactive sweep (PAY-A6)
	DeregOperator = "operator" // the admin console (PAY-O3)
)

// ErrNotRegistered is DeregisterTx's answer for an AID with no agent row. It
// writes nothing.
var ErrNotRegistered = errors.New("hub: that AID is not registered here")

// ErrTombstoneShrinks is DeregisterTx's refusal to overwrite a tombstone
// with a key history that does not extend it. The transaction must be
// rolled back.
var ErrTombstoneShrinks = errors.New("hub: the key history being retired does not extend the tombstone already kept")

// DeregResult is what a deregistration leaves to report.
type DeregResult struct {
	// Balance is the agent's balance, which stays on the ledger.
	Balance int64
	// Undelivered is how many messages were queued for it and are now
	// dropped; somebody sent them and is waiting.
	Undelivered int
}

// deregRun is one deregistration in progress, for the steps.
type deregRun struct {
	tx         *sql.Tx
	aid        string
	why        string
	visibility string
}

// deregStep removes one kind of row an agent is reachable by.
type deregStep struct {
	what string
	run  func(d *deregRun) error
}

// execAID is a step that runs q, whose one parameter is the AID. Each
// statement is written out in full, so a reader (and
// TestSingleDeregisterPath) finds every deletion of an agent's rows in this
// file.
func execAID(q string) func(d *deregRun) error {
	return func(d *deregRun) error {
		_, err := d.tx.Exec(q, d.aid)
		return err
	}
}

// deregSteps is every table keyed by a registered AID and how a
// deregistration removes its rows, in order. An area that adds such a table
// adds its step here (core CORE-K27), or the test that scans hub.db after a
// deregistration (TestDeregRemovesEveryAIDKeyedRow) finds the AID left
// behind. State that lives only in the hub process's memory is dropped by an
// OnDeregistered callback instead.
var deregSteps = []deregStep{
	// The card is withdrawn on the federation stream before its rows go,
	// so a peer that synced it learns the agent left; read against the
	// visibility the agent had (fed_a2acard.go withdrawA2ACard).
	{"withdraw the A2A card from the federation stream", func(d *deregRun) error {
		if !federates(d.visibility) {
			return nil
		}
		return withdrawA2ACard(d.tx, d.aid, withdrawDeparted)
	}},
	{"capability index", execAID(`DELETE FROM agent_cap WHERE aid = ?`)},
	{"encryption key set", execAID(`DELETE FROM agent_keys WHERE aid = ?`)},
	{"A2A card", execAID(`DELETE FROM agent_a2a_card WHERE aid = ?`)},
	{"A2A card skill index", execAID(`DELETE FROM agent_skill WHERE aid = ?`)},
	{"A2A card tag index", execAID(`DELETE FROM agent_tag WHERE aid = ?`)},
	{"mailbox", execAID(`DELETE FROM relay_message WHERE to_aid = ?`)},
	// The credentials it revoked: it is no longer a recipient here. If it
	// registers again, its daemon pushes them again when the registration
	// answer counts none (sealed-sender SSR-D21).
	{"revoked delivery credentials", execAID(`DELETE FROM cap_revocation WHERE owner = ?`)},
	// The registry row last: the steps above may read it. The directory
	// entry (dir_hash, dir_box; directory.go) goes with it.
	{"registry row", execAID(`DELETE FROM agent WHERE aid = ?`)},
}

// DeregisterTx removes aid from this hub inside tx, for the reason why (one
// of the Dereg* constants). It is the only code that deletes an agent row
// (PAY-O1). In order:
//
//  1. no agent row: ErrNotRegistered, nothing written;
//  2. the agent's key history becomes its tombstone in departed_kel. A
//     tombstone already there must be a prefix of it (or equal), so the
//     tombstone is always the longest key history this hub accepted for the
//     AID; otherwise ErrTombstoneShrinks, logged, and the caller rolls back;
//  3. deregSteps;
//  4. for revoked and operator, the admission list row goes too, and so
//     does what the operator raised its quota to (anet-hub quota): both
//     are the operator's decisions about the AID, and both stay when the
//     agent leaves on its own or is swept;
//  5. dereg_event(aid) for the hub process (PAY-O2);
//  6. the balance and the ledger, the reviews it is the subject of and the
//     receipts stay.
func DeregisterTx(tx *sql.Tx, aid, why string) (DeregResult, error) {
	switch why {
	case DeregSelf, DeregDip, DeregRevoked, DeregInactive, DeregOperator:
	default:
		return DeregResult{}, fmt.Errorf("hub: deregistering for an unknown reason %q", why)
	}
	d := &deregRun{tx: tx, aid: aid, why: why}
	var kel []byte
	err := tx.QueryRow(`SELECT kel, visibility FROM agent WHERE aid=?`, aid).Scan(&kel, &d.visibility)
	if errors.Is(err, sql.ErrNoRows) {
		return DeregResult{}, ErrNotRegistered
	}
	if err != nil {
		return DeregResult{}, err
	}
	now := time.Now()
	if err := writeTombstone(tx, aid, kel, now); err != nil {
		return DeregResult{}, err
	}
	var res DeregResult
	if err := tx.QueryRow(`SELECT COUNT(*) FROM relay_message WHERE to_aid=?`, aid).Scan(&res.Undelivered); err != nil {
		return DeregResult{}, err
	}
	for _, st := range deregSteps {
		if err := st.run(d); err != nil {
			return DeregResult{}, fmt.Errorf("hub: deregistering %s (%s): %w", aid, st.what, err)
		}
	}
	if why == DeregRevoked || why == DeregOperator {
		if _, err := tx.Exec(`DELETE FROM admitted WHERE aid=?`, aid); err != nil {
			return DeregResult{}, err
		}
		if _, err := tx.Exec(`DELETE FROM quota_override WHERE aid=?`, aid); err != nil {
			return DeregResult{}, err
		}
	}
	if _, err := tx.Exec(`INSERT INTO dereg_event(aid, at) VALUES(?,?)
	    ON CONFLICT(aid) DO UPDATE SET at=excluded.at`, aid, now.UnixMilli()); err != nil {
		return DeregResult{}, err
	}
	if err := tx.QueryRow(`SELECT COALESCE((SELECT credits FROM credit_balance WHERE aid=?), 0)`, aid).
		Scan(&res.Balance); err != nil {
		return DeregResult{}, err
	}
	return res, nil
}

// writeTombstone keeps kel as aid's tombstone. A tombstone already there
// must be a prefix of kel or equal to it.
func writeTombstone(tx *sql.Tx, aid string, kel []byte, now time.Time) error {
	var held []byte
	err := tx.QueryRow(`SELECT kel FROM departed_kel WHERE aid=?`, aid).Scan(&held)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	default:
		old, oerr := identity.UnmarshalKEL(held)
		next, nerr := identity.UnmarshalKEL(kel)
		if oerr != nil || nerr != nil {
			log.Printf("ERROR hub: deregistering %s: a key history does not decode (tombstone: %v, registered: %v)",
				aid, oerr, nerr)
			return fmt.Errorf("%w: a key history does not decode", ErrTombstoneShrinks)
		}
		if xerr := identity.ExtendsKEL(old, next); xerr != nil {
			log.Printf("ERROR hub: deregistering %s: the registered key history does not extend its tombstone (%v); nothing was changed",
				aid, xerr)
			return fmt.Errorf("%w: %w", ErrTombstoneShrinks, xerr)
		}
	}
	_, err = tx.Exec(`INSERT INTO departed_kel(aid, kel, at) VALUES(?,?,?)
	    ON CONFLICT(aid) DO UPDATE SET kel=excluded.kel, at=excluded.at`,
		aid, kel, now.UTC().Format(time.RFC3339Nano))
	return err
}

// Deregister removes an agent from this hub, for the reason why, in its own
// transaction; then, in the hub process, it runs the OnDeregistered
// callbacks.
func (s *Store) Deregister(aid, why string) (DeregResult, error) {
	s.mu.Lock()
	tx, err := s.db.Begin()
	if err != nil {
		s.mu.Unlock()
		return DeregResult{}, err
	}
	defer tx.Rollback()
	res, err := DeregisterTx(tx, aid, why)
	if err == nil {
		err = tx.Commit()
	}
	s.mu.Unlock()
	if err != nil {
		return DeregResult{}, err
	}
	s.afterDereg(aid)
	return res, nil
}

// ---- the hub process's side (PAY-O2) ----

// deregHooks are the callbacks the hub process runs when an AID is
// deregistered.
type deregHooks struct {
	mu        sync.Mutex
	hooks     []func(aid string)
	inProcess bool // this process is the hub: StartDeregWatcher ran
}

// OnDeregistered adds a callback run with every AID this hub deregisters, in
// this process or (through dereg_event) in another. It is how state kept
// only in the hub process's memory and keyed by AID is dropped: sealed-sender
// registers "drop this AID's sessions and their send buckets" (SSR-H9).
// Callbacks must be quick and may run more than once for one deregistration.
func (s *Store) OnDeregistered(f func(aid string)) {
	s.dereg.mu.Lock()
	defer s.dereg.mu.Unlock()
	s.dereg.hooks = append(s.dereg.hooks, f)
}

// runDeregHooks runs every callback for aid.
func (s *Store) runDeregHooks(aid string) {
	s.dereg.mu.Lock()
	hooks := append([]func(string){}, s.dereg.hooks...)
	s.dereg.mu.Unlock()
	for _, f := range hooks {
		f(aid)
	}
}

// afterDereg is what a deregistration committed in this process does next.
// In the hub process: the callbacks, then the dereg_event row goes. In any
// other process (anet-hub admissions revoke, the admin tool) nothing: the
// row is the hub process's to read.
func (s *Store) afterDereg(aid string) {
	s.dereg.mu.Lock()
	in := s.dereg.inProcess
	s.dereg.mu.Unlock()
	if !in {
		return
	}
	s.runDeregHooks(aid)
	if _, err := s.db.Exec(`DELETE FROM dereg_event WHERE aid=?`, aid); err != nil {
		log.Printf("hub: clearing the deregistration of %s: %v", aid, err)
	}
}

// DeregWatchEvery is how often the hub process looks for deregistrations
// another process committed.
const DeregWatchEvery = time.Second

// StartDeregWatcher makes this process the hub process: it clears
// dereg_event (a restart already ended every session), then once per
// DeregWatchEvery until ctx ends checks whether any other connection wrote
// to the database (PRAGMA data_version) and, when one did, runs the
// callbacks for each row of dereg_event and deletes it.
func (s *Store) StartDeregWatcher(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM dereg_event`); err != nil {
		conn.Close()
		return err
	}
	var last int64
	if err := conn.QueryRowContext(ctx, `PRAGMA data_version`).Scan(&last); err != nil {
		conn.Close()
		return err
	}
	s.dereg.mu.Lock()
	s.dereg.inProcess = true
	s.dereg.mu.Unlock()
	go func() {
		defer conn.Close()
		t := time.NewTicker(DeregWatchEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			var v int64
			if err := conn.QueryRowContext(ctx, `PRAGMA data_version`).Scan(&v); err != nil {
				if ctx.Err() == nil {
					log.Printf("hub: watching for deregistrations: %v", err)
				}
				continue
			}
			if v == last {
				continue
			}
			last = v
			s.drainDeregEvents(ctx, conn)
		}
	}()
	return nil
}

// drainDeregEvents runs the callbacks for each deregistration waiting in
// dereg_event and deletes its row (unless it was written again meanwhile).
func (s *Store) drainDeregEvents(ctx context.Context, conn *sql.Conn) {
	rows, err := conn.QueryContext(ctx, `SELECT aid, at FROM dereg_event ORDER BY at`)
	if err != nil {
		log.Printf("hub: reading deregistrations: %v", err)
		return
	}
	type ev struct {
		aid string
		at  int64
	}
	var evs []ev
	for rows.Next() {
		var e ev
		if err := rows.Scan(&e.aid, &e.at); err != nil {
			break
		}
		evs = append(evs, e)
	}
	rows.Close()
	for _, e := range evs {
		s.runDeregHooks(e.aid)
		if _, err := conn.ExecContext(ctx, `DELETE FROM dereg_event WHERE aid=? AND at=?`, e.aid, e.at); err != nil {
			log.Printf("hub: clearing the deregistration of %s: %v", e.aid, err)
		}
	}
}

// ---- leaving under one's own signature ----

// hDeregister lets an agent leave, under its own signature (relayauth v2,
// action "deregister"). Which hub speaks for an agent is the agent's to
// decide, so leaving is not an operator action; the operator's way to remove
// an agent is to revoke its admission, which goes through the same
// DeregisterTx.
func (s *Server) hDeregister(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	if _, err := s.store.AgentKEL(aid); err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonNotFound, Error: "That agent is not registered here; there is nothing to leave."})
		return
	}
	if _, ok := s.authSelf(w, r, relayauth.ActionDeregister, signedBodyLimit); !ok {
		return
	}
	res, err := s.store.Deregister(aid, DeregSelf)
	if errors.Is(err, ErrNotRegistered) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonNotFound, Error: "That agent is not registered here; there is nothing to leave."})
		return
	}
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	out := map[string]any{"aid": aid, "status": "deregistered", "undelivered": res.Undelivered}
	if res.Undelivered > 0 {
		out["warning"] = fmt.Sprintf(
			"%d message(s) were queued for this agent and will not be delivered — "+
				"whoever sent them is waiting", res.Undelivered)
	}
	writeJSON(w, http.StatusOK, out)
}
