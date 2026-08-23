package aghub

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// The issuance chain: every change to the total supply, in order, signed.
//
// /x402/supply computes issued, redeemed and outstanding from
// credit_entry, and the hub writes those rows. That establishes internal
// consistency — outstanding equals the sum of balances — and nothing
// else. It does not establish that the rows were not edited afterwards.
//
// Transfers do not have this problem. A settlement produces a hub-signed
// receipt held by the payer and recorded on both parties' evidence
// chains, so the hub cannot alter one without contradicting records it
// does not hold. Issuance has no counterparty: a grant creates credit
// with nobody on the other side, so nothing outside the hub attests to
// it.
//
// This file gives issuance the same treatment. Each supply-changing event
// becomes a record on an append-only, hash-linked, hub-signed chain
// (ANetCore/ael), published for anyone to read. What that buys:
//
//   - A reader who has fetched record N can later verify record N is
//     unchanged and still links to N+1. Rewriting the history produces a
//     fork that anyone holding an older copy can demonstrate.
//   - The chain and the balance table can be compared. If the sum over
//     the chain disagrees with the sum over credit_entry, the hub has
//     moved credit without recording it.
//
// What it does not buy, stated because the difference matters: it does
// not prevent issuance, and it offers nothing to a reader who has never
// seen this chain before. A hub that has never been observed can present
// any chain. Witnesses (witness.go) are what close that second gap.

// Issuance event types on the chain.
const (
	// EvCreditIssued records credit created: a registration grant or an
	// operator grant.
	EvCreditIssued = "anet.credit.issued"
	// EvCreditRetired records credit destroyed by redemption.
	EvCreditRetired = "anet.credit.retired"
	// EvCreditOpening records supply that existed before this chain did.
	//
	// A hub that has been running has credit outstanding from before the
	// chain was added. Two wrong ways to handle that: leave the chain
	// permanently disagreeing with the balances, which makes the
	// comparison useless; or backfill one record per historical grant,
	// which has the hub signing a reconstruction of its own unaudited
	// table and presenting it as a contemporaneous record.
	//
	// The opening record says what is true: this much was outstanding
	// when the chain began, it was issued before anything attested to
	// issuance, and nothing outside this hub vouches for it. Supply
	// reports it separately so a reader can see how much of the total is
	// unattested rather than having it folded in silently.
	EvCreditOpening = "anet.credit.opening"
)

// issuanceChain is the hub's own supply chain.
type issuanceChain struct {
	mu sync.Mutex
	db *sql.DB
}

// IssuanceEntry is one supply-changing event as served to a reader.
type IssuanceEntry struct {
	Seq    uint64 `json:"seq"`
	ID     string `json:"id"`
	PrevID string `json:"prev_id"`
	Kind   string `json:"kind"`
	AID    string `json:"aid"`
	Amount int64  `json:"amount"`
	Reason string `json:"reason,omitempty"`
	At     int64  `json:"at"`
	// Record is the signed ael.EventRecord, base64 CoreDet-CBOR. The
	// parsed fields above are a convenience; this is the thing that
	// verifies, and a reader checking the chain must use it rather than
	// the JSON, which the hub could render differently from what it
	// signed.
	Record string `json:"record"`
}

// appendIssuance writes one supply event onto the chain.
//
// Called inside the same operation that moves the credit. A failure here
// fails the operation: a grant that moved credit without a chain record
// would make the chain understate the supply, and a chain that understates
// is worse than no chain because it will be read as complete.
func (s *Store) appendIssuance(kind, aid string, amount int64, reason string) error {
	if s.hubKey == nil {
		// No signing key means no chain. Reported rather than skipped:
		// running without one leaves the supply unauditable, and the
		// operator should learn that from a failure, not from an empty
		// endpoint months later.
		return fmt.Errorf("hub: no signing key, so supply changes cannot be recorded")
	}
	s.issuance.mu.Lock()
	defer s.issuance.mu.Unlock()

	prevID, seq, have, err := s.issuanceHeadLocked()
	if err != nil {
		return err
	}
	next := uint64(0)
	if have {
		next = seq + 1
	}
	rec := &ael.EventRecord{
		ChainDID:     s.hubKey.AID(),
		Seq:          next,
		PrevID:       prevID,
		EventType:    kind,
		VersionMajor: ael.VersionMajor2,
		Payload: map[string]any{
			"aid": aid, "amount": amount, "reason": reason,
		},
		Timestamp:          time.Now().UnixMilli(),
		CriticalExtensions: []string{},
	}
	if err := rec.Sign(s.hubKey); err != nil {
		return err
	}
	raw, err := coredet.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO credit_issuance(seq, id, prev_id, kind, aid, amount, reason, at, record)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		rec.Seq, rec.ID, rec.PrevID, kind, aid, amount, reason, rec.Timestamp, raw)
	return err
}

// issuanceHeadLocked returns the current head, and whether there is one.
//
// The bool is not decoration: an AEL's first record is seq 0, so "no
// records" and "one record" both report seq 0 and only the flag
// distinguishes them. Collapsing the two would make the second append
// overwrite the first.
//
// Caller holds the chain mutex.
func (s *Store) issuanceHeadLocked() (id string, seq uint64, have bool, err error) {
	var idv sql.NullString
	var seqv sql.NullInt64
	err = s.db.QueryRow(`SELECT id, seq FROM credit_issuance ORDER BY seq DESC LIMIT 1`).
		Scan(&idv, &seqv)
	if err == sql.ErrNoRows {
		return ael.GenesisPrev(), 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	return idv.String, uint64(seqv.Int64), true, nil
}

// IssuanceHead is the current head of the supply chain. ok is false when
// nothing has been issued yet, which is a hub with no supply rather than
// a hub hiding one.
func (s *Store) IssuanceHead() (id string, seq uint64, ok bool) {
	s.issuance.mu.Lock()
	defer s.issuance.mu.Unlock()
	id, seq, have, err := s.issuanceHeadLocked()
	if err != nil || !have {
		return "", 0, false
	}
	return id, seq, true
}

// IssuanceSince serves the chain from a cursor, INCLUSIVE of from.
//
// Inclusive because an AEL's first record is seq 0, and an exclusive
// cursor starting at zero silently skips it — which made the chain
// unverifiable from the outside, since the run a reader received began
// at seq 1 and every AEL replay requires seq 0 first.
//
// A reader continues by passing head+1.
func (s *Store) IssuanceSince(from uint64, limit int) ([]IssuanceEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := s.db.Query(
		`SELECT seq, id, prev_id, kind, aid, amount, reason, at, record
		   FROM credit_issuance WHERE seq >= ? ORDER BY seq LIMIT ?`, from, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IssuanceEntry{}
	for rows.Next() {
		var e IssuanceEntry
		var raw []byte
		if err := rows.Scan(&e.Seq, &e.ID, &e.PrevID, &e.Kind, &e.AID,
			&e.Amount, &e.Reason, &e.At, &raw); err != nil {
			return nil, err
		}
		e.Record = base64.StdEncoding.EncodeToString(raw)
		out = append(out, e)
	}
	return out, rows.Err()
}

// OpenBalance writes the opening record if the chain is empty and the
// balances show credit already outstanding.
//
// Called once at startup. Idempotent: a chain that already has records is
// left alone, so a restart cannot add a second opening.
func (s *Store) OpenBalance(outstanding int64) error {
	if outstanding <= 0 || s.hubKey == nil {
		return nil
	}
	s.issuance.mu.Lock()
	_, _, have, err := s.issuanceHeadLocked()
	s.issuance.mu.Unlock()
	if err != nil || have {
		return err
	}
	return s.appendIssuance(EvCreditOpening, s.hubKey.AID(), outstanding,
		"outstanding before this chain existed; not attested by anything outside this hub")
}

// IssuanceTotals sums the chain: what it says was issued and retired.
//
// Compared against the balance table by Supply. The two are written by
// the same process and should always agree; when they do not, the hub has
// moved credit outside the chain, and a reader can see that without
// trusting either number.
func (s *Store) IssuanceTotals() (issued, retired, opening int64, err error) {
	err = s.db.QueryRow(
		`SELECT COALESCE(SUM(CASE WHEN kind=? THEN amount ELSE 0 END),0),
		        COALESCE(SUM(CASE WHEN kind=? THEN amount ELSE 0 END),0),
		        COALESCE(SUM(CASE WHEN kind=? THEN amount ELSE 0 END),0)
		   FROM credit_issuance`,
		EvCreditIssued, EvCreditRetired, EvCreditOpening).Scan(&issued, &retired, &opening)
	return issued, retired, opening, err
}

// VerifyIssuanceChain replays the stored chain and reports the first
// break.
//
// Run by the hub's own operator, which is a limited but real use: it
// catches storage corruption and a signing key that changed without the
// chain being migrated. It cannot catch a hub that rewrote its chain
// consistently — that is what witnesses are for, and only a party other
// than the hub can do it.
func (s *Store) VerifyIssuanceChain(kel []identity.SignedEvent) error {
	entries, err := s.IssuanceSince(0, 1000)
	if err != nil {
		return err
	}
	ledger := ael.NewLedger()
	for _, e := range entries {
		raw, derr := base64.StdEncoding.DecodeString(e.Record)
		if derr != nil {
			return fmt.Errorf("seq %d: %w", e.Seq, derr)
		}
		var rec ael.EventRecord
		if uerr := coredet.Unmarshal(raw, &rec); uerr != nil {
			return fmt.Errorf("seq %d: %w", e.Seq, uerr)
		}
		if aerr := ledger.Append(&rec, kel); aerr != nil {
			return fmt.Errorf("seq %d: %w", e.Seq, aerr)
		}
	}
	return nil
}

// ClearIssuanceForTest empties the chain, to reproduce a hub whose credit
// predates it. Named so nobody mistakes it for an operation the hub
// performs.
func (s *Store) ClearIssuanceForTest() error {
	_, err := s.db.Exec(`DELETE FROM credit_issuance`)
	return err
}
