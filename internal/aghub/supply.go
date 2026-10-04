package aghub

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/liabtree"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Supply epochs and liability proofs (hub-payment-privacy §2.3, §4.2.1).
//
// The public record of what this hub owes is one signed statement per
// closed period, a supply epoch: the days it covers, the total of every
// balance at its close (outstanding) and the root of a Merkle sum tree over
// those balances (ANetCore liabtree). It names nobody and no single
// payment, so reading it says how much the hub owes and not who paid whom.
// Each account checks its own share: GET /agents/{aid}/liability-proof
// gives the account its leaf and the path to the signed root, and a hub that
// shrank the account's balance, or left it out, cannot produce one that
// verifies.
//
// What the hub keeps to make that work:
//
//   - supply_totals, one row: what was ever issued and redeemed, how many
//     supply events happened since the last publication and the last day
//     published. Every supply event updates it in its own transaction
//     (supplyEventTx); a transfer between two accounts is not a supply
//     event and does not touch it.
//   - supply_chain: the published epoch records, hash-linked (ael), each
//     signed by the hub when it closed the epoch.
//   - liab_leaf and liab_meta: every leaf of each epoch's tree, padding
//     included, in tree order, so the tree can be rebuilt to answer a proof.
//     Kept 14 days after the epoch was published.
//
// The invariant every step keeps (P-PAY-3): the agent balances add up to
// issued − redeemed, and the hub's own row holds the negative of that.

// Epoch publication and retention (hub-payment-privacy §0.4).
const (
	// dayMillis is one UTC day in unix milliseconds (core CORE-E6).
	dayMillis = 86_400_000
	// epochEvents and epochDays are the publication rule (PAY-S2): an
	// epoch closes once this many supply events happened since the last
	// one, or this many UTC days passed.
	epochEvents = 20
	epochDays   = 7
	// proofKeptFor is how long after an epoch was published its leaves are
	// kept and its proofs served (PAY-S5).
	proofKeptFor = 14 * dayMillis
	// supplyCheckEvery is how often RunSupplyEpochs looks at the UTC day.
	supplyCheckEvery = time.Minute
	// issuancePage bounds one GET /x402/issuance answer.
	issuancePage = 500
)

// supplySchema is the supply epochs' tables (hub-payment-privacy §3.2).
func supplySchema() []string {
	return []string{
		// The running totals. last_to_day is the last day a published epoch
		// covers, or before the first publication the day before the first
		// supply event; NULL while nothing has happened.
		`CREATE TABLE IF NOT EXISTS supply_totals (
		   id INTEGER PRIMARY KEY CHECK (id = 1),
		   issued INTEGER NOT NULL DEFAULT 0,
		   redeemed INTEGER NOT NULL DEFAULT 0,
		   events_since_publish INTEGER NOT NULL DEFAULT 0,
		   last_to_day INTEGER
		 )`,
		`INSERT INTO supply_totals(id) VALUES(1)`,
		// The published epochs. record is coredet(ael.EventRecord), the thing
		// that verifies; the columns beside it are what it states.
		`CREATE TABLE IF NOT EXISTS supply_chain (
		   seq INTEGER PRIMARY KEY,
		   id TEXT NOT NULL UNIQUE,
		   prev_id TEXT NOT NULL,
		   from_day INTEGER NOT NULL,
		   to_day INTEGER NOT NULL UNIQUE,
		   root TEXT NOT NULL,
		   outstanding INTEGER NOT NULL,
		   depth INTEGER NOT NULL,
		   record BLOB NOT NULL
		 )`,
		// Every leaf of an epoch's tree at its place, padding (aid '')
		// included: rebuilding the same root needs every salt.
		`CREATE TABLE IF NOT EXISTS liab_leaf (
		   to_day INTEGER NOT NULL,
		   pos INTEGER NOT NULL,
		   aid TEXT NOT NULL,
		   balance INTEGER NOT NULL,
		   salt BLOB NOT NULL,
		   PRIMARY KEY (to_day, pos)
		 )`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_liab_leaf_aid ON liab_leaf(to_day, aid) WHERE aid <> ''`,
		// ledger_hw is the largest credit_entry.seq at the close; leaves is how
		// many rows liab_leaf holds for the epoch.
		`CREATE TABLE IF NOT EXISTS liab_meta (
		   to_day INTEGER PRIMARY KEY,
		   ledger_hw INTEGER NOT NULL,
		   leaves INTEGER NOT NULL
		 )`,
	}
}

// utcDay is the UTC day of t (core CORE-E6).
func utcDay(t time.Time) int64 { return t.UnixMilli() / dayMillis }

// supplyKind is the direction of a supply event.
type supplyKind int

const (
	// supplyIssued: credit created (a grant, an admission grant, a trial
	// credit, a peer's settlement cleared here).
	supplyIssued supplyKind = iota
	// supplyRedeemed: credit destroyed (a redemption, a payment settled
	// here to an agent that banks on a peer).
	supplyRedeemed
)

// supplyEventTx records one supply event of amt credits inside tx, the
// transaction that moves the credit (PAY-S1): the issued or redeemed total
// grows, and so does the count since the last publication. The first event
// of a hub starts the clock of the publication rule.
//
// It records nothing else: no AID, no reason and no time, so nothing a
// supply event leaves behind outside the ledger says who or how much.
func (s *Store) supplyEventTx(tx *sql.Tx, kind supplyKind, amt int64) error {
	if amt <= 0 {
		return fmt.Errorf("hub: a supply event of %d credits", amt)
	}
	col := "issued"
	if kind == supplyRedeemed {
		col = "redeemed"
	}
	res, err := tx.Exec(`UPDATE supply_totals SET `+col+` = `+col+` + ?,
	    events_since_publish = events_since_publish + 1,
	    last_to_day = COALESCE(last_to_day, ?)
	  WHERE id = 1 AND `+col+` <= ?`, amt, utcDay(s.now())-1, int64(math.MaxInt64)-amt)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return refuse(payment.ReasonInvalidAmount, "the %s total cannot take %d more: it would pass %d, the most it can hold",
			col, amt, int64(math.MaxInt64))
	}
	return nil
}

// issuedTotal is what this hub has issued in total, read through q.
func issuedTotal(q rowQuerier) (int64, error) {
	var n int64
	err := q.QueryRow(`SELECT issued FROM supply_totals WHERE id = 1`).Scan(&n)
	return n, err
}

// ---- publication ----

// errNoSigningKey: a store without the hub's identity cannot sign an epoch.
var errNoSigningKey = errors.New("hub: no signing key, so no supply epoch can be published")

// ErrSupplyMismatch is a close that found the ledger disagreeing with
// itself: a negative balance, or a tree whose sum is not what the totals and
// the hub's own row say is outstanding. Nothing is published; the hub logs
// it as an error, because a ledger in that state is a bug or tampering and
// either way the operator must look (PAY-S3 step 3).
var ErrSupplyMismatch = errors.New("hub: the ledger does not add up, so no supply epoch was published")

// SupplyEpochEntry is one published epoch as GET /x402/issuance serves it.
type SupplyEpochEntry struct {
	Seq         uint64 `json:"seq"`
	ID          string `json:"id"`
	PrevID      string `json:"prev_id"`
	FromDay     uint64 `json:"from_day"`
	ToDay       uint64 `json:"to_day"`
	Root        string `json:"root"`
	Outstanding uint64 `json:"outstanding"`
	// Record is coredet(ael.EventRecord), base64url: what the hub signed.
	// A reader checks this, not the members beside it.
	Record string `json:"record"`
	depth  int
	raw    []byte
}

// PublishDue closes and publishes the supply epoch that is due, if one is,
// and returns it (nil when none is due). The rule (PAY-S2): d is the UTC day
// that has just ended and last the last day published (before the first
// publication, the day before the first supply event); an epoch [last+1, d]
// is published when 20 or more supply events happened since the last
// publication or d − last ≥ 7. Otherwise nothing is written: there is no
// placeholder record.
//
// The close is one read-write transaction (PAY-S3): the leaves are every
// AID registered here or holding a balance, the hub's own row excluded; the
// tree's sum must equal both issued − redeemed and the negative of the hub's
// row, or nothing is written and ErrSupplyMismatch is returned. Run twice
// for one day it publishes once.
func (s *Store) PublishDue() (*SupplyEpochEntry, error) { return s.publishDueAt(s.now()) }

// publishDueAt is PublishDue with the clock reading now.
func (s *Store) publishDueAt(now time.Time) (*SupplyEpochEntry, error) {
	if s.hubKey == nil || s.hubAID == "" {
		return nil, errNoSigningKey
	}
	d := utcDay(now) - 1
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var issued, redeemed, events int64
	var last sql.NullInt64
	if err := tx.QueryRow(`SELECT issued, redeemed, events_since_publish, last_to_day
	    FROM supply_totals WHERE id = 1`).Scan(&issued, &redeemed, &events, &last); err != nil {
		return nil, err
	}
	if !last.Valid || d <= last.Int64 || d < 0 {
		return nil, nil // nothing has happened yet, or the day is covered
	}
	if events < epochEvents && d-last.Int64 < epochDays {
		return nil, nil
	}
	var have int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM supply_chain WHERE to_day = ?`, d).Scan(&have); err != nil {
		return nil, err
	}
	if have > 0 {
		return nil, nil
	}
	e, err := s.closeEpochTx(tx, uint64(last.Int64+1), uint64(d), issued-redeemed, now)
	if err != nil {
		if errors.Is(err, ErrSupplyMismatch) {
			log.Printf("hub: ERROR: supply epoch %d..%d not published: %v", last.Int64+1, d, err)
		}
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE supply_totals SET events_since_publish = 0, last_to_day = ? WHERE id = 1`, d); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return e, nil
}

// closeEpochTx builds the tree of the balances as they stand in tx, checks
// it against outstanding and the hub's row, and writes the signed record and
// the leaves (PAY-S3 steps 1 to 4).
func (s *Store) closeEpochTx(tx *sql.Tx, fromDay, toDay uint64, outstanding int64, now time.Time) (*SupplyEpochEntry, error) {
	rows, err := tx.Query(`SELECT a.aid, COALESCE(b.credits, 0)
	    FROM (SELECT aid FROM agent UNION SELECT aid FROM credit_balance) a
	    LEFT JOIN credit_balance b ON b.aid = a.aid
	   WHERE a.aid <> ?`, s.hubAID)
	if err != nil {
		return nil, err
	}
	var leaves []liabtree.Leaf
	for rows.Next() {
		var aid string
		var bal int64
		if err := rows.Scan(&aid, &bal); err != nil {
			rows.Close()
			return nil, err
		}
		if bal < 0 {
			rows.Close()
			return nil, fmt.Errorf("%w: %s has a negative balance (%d)", ErrSupplyMismatch, aid, bal)
		}
		leaves = append(leaves, liabtree.Leaf{AID: aid, Balance: uint64(bal)})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var hubRow, ledgerHW int64
	if err := tx.QueryRow(`SELECT COALESCE((SELECT credits FROM credit_balance WHERE aid = ?), 0)`,
		s.hubAID).Scan(&hubRow); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM credit_entry`).Scan(&ledgerHW); err != nil {
		return nil, err
	}
	tree, err := liabtree.Build(leaves, toDay, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSupplyMismatch, err)
	}
	if outstanding < 0 || tree.Outstanding() != uint64(outstanding) || hubRow != -outstanding {
		return nil, fmt.Errorf("%w: the balances add up to %d, issued − redeemed is %d and the hub's row is %d",
			ErrSupplyMismatch, tree.Outstanding(), outstanding, hubRow)
	}
	prevID, seq, have, err := supplyHead(tx)
	if err != nil {
		return nil, err
	}
	next := uint64(0)
	if have {
		next = seq + 1
	}
	rec, err := ael.SupplyEpochRecord(s.hubAID, ael.SupplyEpoch{
		FromDay: fromDay, ToDay: toDay, Root: tree.Root(), Outstanding: tree.Outstanding(), Depth: tree.Depth(),
	})
	if err != nil {
		return nil, err
	}
	rec.Seq, rec.PrevID = next, prevID
	// The time of publication, not of any user's event.
	rec.Timestamp = now.UnixMilli()
	if err := rec.Sign(s.hubKey); err != nil {
		return nil, err
	}
	raw, err := coredet.Marshal(rec)
	if err != nil {
		return nil, err
	}
	root := liabtree.Hex(tree.Root())
	if _, err := tx.Exec(`INSERT INTO supply_chain(seq, id, prev_id, from_day, to_day, root, outstanding, depth, record)
	    VALUES(?,?,?,?,?,?,?,?,?)`, next, rec.ID, rec.PrevID, fromDay, toDay, root, tree.Outstanding(),
		tree.Depth(), raw); err != nil {
		return nil, err
	}
	entries := tree.Entries()
	for pos, e := range entries {
		if _, err := tx.Exec(`INSERT INTO liab_leaf(to_day, pos, aid, balance, salt) VALUES(?,?,?,?,?)`,
			toDay, pos, e.AID, e.Balance, e.Salt[:]); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(`INSERT INTO liab_meta(to_day, ledger_hw, leaves) VALUES(?,?,?)`,
		toDay, ledgerHW, len(entries)); err != nil {
		return nil, err
	}
	return &SupplyEpochEntry{Seq: next, ID: rec.ID, PrevID: rec.PrevID, FromDay: fromDay, ToDay: toDay,
		Root: root, Outstanding: tree.Outstanding(), Record: wire3.EncodeB64URL(raw), depth: tree.Depth(), raw: raw}, nil
}

// supplyHead is the last published epoch's id and seq, and whether there is
// one, read through q. An ael chain starts at seq 0, so only the flag tells
// "no epoch" from "one epoch".
func supplyHead(q rowQuerier) (id string, seq uint64, have bool, err error) {
	err = q.QueryRow(`SELECT id, seq FROM supply_chain ORDER BY seq DESC LIMIT 1`).Scan(&id, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return ael.GenesisPrev(), 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	return id, seq, true, nil
}

// SupplyHead is the last published epoch's id and seq; ok is false before
// the first publication.
func (s *Store) SupplyHead() (id string, seq uint64, ok bool) {
	id, seq, ok, err := supplyHead(s.db)
	if err != nil || !ok {
		return "", 0, false
	}
	return id, seq, true
}

// SupplyEpochs serves the published epochs from seq from, inclusive (an ael
// chain starts at seq 0, which a verifier needs first), at most limit of
// them (issuancePage when limit is 0 or more).
func (s *Store) SupplyEpochs(from uint64, limit int) ([]SupplyEpochEntry, error) {
	if limit <= 0 || limit > issuancePage {
		limit = issuancePage
	}
	out := []SupplyEpochEntry{}
	// seq is an SQLite INTEGER, so no epoch is at or above 2^63, and
	// database/sql refuses a uint64 with the high bit set.
	if from > math.MaxInt64 {
		return out, nil
	}
	rows, err := s.db.Query(`SELECT seq, id, prev_id, from_day, to_day, root, outstanding, depth, record
	    FROM supply_chain WHERE seq >= ? ORDER BY seq LIMIT ?`, int64(from), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e SupplyEpochEntry
		if err := rows.Scan(&e.Seq, &e.ID, &e.PrevID, &e.FromDay, &e.ToDay, &e.Root, &e.Outstanding,
			&e.depth, &e.raw); err != nil {
			return nil, err
		}
		e.Record = wire3.EncodeB64URL(e.raw)
		out = append(out, e)
	}
	return out, rows.Err()
}

// latestEpoch is the last published epoch; ok is false before the first.
func (s *Store) latestEpoch() (e SupplyEpochEntry, ok bool, err error) {
	_, seq, have, err := supplyHead(s.db)
	if err != nil || !have {
		return e, false, err
	}
	es, err := s.SupplyEpochs(seq, 1)
	if err != nil || len(es) == 0 {
		return e, false, err
	}
	return es[0], true, nil
}

// RunSupplyEpochs publishes due epochs until ctx ends: once at start (a hub
// that was down over a midnight catches up), then once after each UTC
// midnight (PAY-S2). It also drops the leaves of epochs past their 14 days.
func (s *Store) RunSupplyEpochs(ctx context.Context) {
	check := func() {
		if e, err := s.PublishDue(); err != nil {
			if !errors.Is(err, ErrSupplyMismatch) { // logged where it is found
				log.Printf("hub: supply epoch: %v", err)
			}
		} else if e != nil {
			log.Printf("hub: published supply epoch %d (days %d..%d)", e.Seq, e.FromDay, e.ToDay)
		}
		if err := s.PruneLiabilityProofs(); err != nil {
			log.Printf("hub: dropping old balance proofs: %v", err)
		}
	}
	check()
	day := utcDay(s.now())
	t := time.NewTicker(supplyCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if d := utcDay(s.now()); d != day {
				day = d
				check()
			}
		}
	}
}

// ---- liability proofs ----

// ErrProofUnavailable is a liability proof this hub does not keep: the
// epoch is past its 14 days or was never published, or the AID was not on
// the books when it closed (404 proof_unavailable).
var ErrProofUnavailable = errors.New("hub: no balance proof is kept for that period")

// LiabilityProof is the answer of GET /agents/{aid}/liability-proof: the
// account's leaf and its path to the root (liabtree.WireProof: to_day, aid,
// balance, salt, path), the epoch's first day, the ledger's high-water mark
// at the close and the signed epoch record, base64url. side in a path step
// is the side the sibling is on (liabtree.Side). The caller checks that aid
// and to_day are the ones it asked about: liabtree.Verify does not.
type LiabilityProof struct {
	liabtree.WireProof
	FromDay  uint64 `json:"from_day"`
	LedgerHW uint64 `json:"ledger_hw"`
	Record   string `json:"record"`
}

// liabTreeCache holds the rebuilt trees of epochs whose proofs are served,
// by to_day: a tree is rebuilt from its leaves once, not per request.
type liabTreeCache struct {
	mu    sync.Mutex
	trees map[uint64]*liabtree.Tree
}

func (c *liabTreeCache) get(toDay uint64) *liabtree.Tree {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.trees[toDay]
}

func (c *liabTreeCache) put(toDay uint64, t *liabtree.Tree) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.trees == nil {
		c.trees = map[uint64]*liabtree.Tree{}
	}
	// At most one epoch a day is published and 14 days are served.
	if len(c.trees) >= 2*proofKeptFor/dayMillis {
		c.trees = map[uint64]*liabtree.Tree{}
	}
	c.trees[toDay] = t
}

func (c *liabTreeCache) drop(toDay uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.trees, toDay)
}

// publishedAt is the time an epoch record was signed: its publication.
func publishedAt(raw []byte) (int64, error) {
	rec, err := ael.UnmarshalEventRecord(raw)
	if err != nil {
		return 0, err
	}
	return rec.Timestamp, nil
}

// LiabilityProof is aid's proof in the epoch that closed on toDay, or in the
// latest one when toDay is nil (PAY-S5). It is ErrProofUnavailable when that
// epoch is not kept (never published, or published 14 days ago or more) or
// aid has no leaf in it.
func (s *Store) LiabilityProof(aid string, toDay *uint64) (LiabilityProof, error) {
	return s.liabilityProofAt(aid, toDay, s.now())
}

// liabilityProofAt is LiabilityProof with the clock reading now.
func (s *Store) liabilityProofAt(aid string, toDay *uint64, now time.Time) (LiabilityProof, error) {
	var e SupplyEpochEntry
	if toDay == nil {
		latest, ok, err := s.latestEpoch()
		if err != nil {
			return LiabilityProof{}, err
		}
		if !ok {
			return LiabilityProof{}, ErrProofUnavailable
		}
		e = latest
	} else {
		if *toDay > math.MaxInt64 {
			return LiabilityProof{}, ErrProofUnavailable
		}
		err := s.db.QueryRow(`SELECT seq, id, prev_id, from_day, to_day, root, outstanding, depth, record
		    FROM supply_chain WHERE to_day = ?`, int64(*toDay)).Scan(&e.Seq, &e.ID, &e.PrevID, &e.FromDay,
			&e.ToDay, &e.Root, &e.Outstanding, &e.depth, &e.raw)
		if errors.Is(err, sql.ErrNoRows) {
			return LiabilityProof{}, ErrProofUnavailable
		}
		if err != nil {
			return LiabilityProof{}, err
		}
	}
	at, err := publishedAt(e.raw)
	if err != nil {
		return LiabilityProof{}, fmt.Errorf("hub: epoch %d: %w", e.Seq, err)
	}
	if now.UnixMilli()-at >= proofKeptFor {
		return LiabilityProof{}, ErrProofUnavailable
	}
	tree, ledgerHW, err := s.liabTree(e)
	if err != nil {
		return LiabilityProof{}, err
	}
	p, ok := tree.Proof(aid)
	if !ok {
		return LiabilityProof{}, ErrProofUnavailable
	}
	return LiabilityProof{WireProof: p.Wire(), FromDay: e.FromDay, LedgerHW: ledgerHW,
		Record: wire3.EncodeB64URL(e.raw)}, nil
}

// liabTree is the tree of epoch e, rebuilt from its stored leaves, and the
// ledger's high-water mark at its close. A tree that does not rebuild to the
// published root is an error: the stored leaves are not the ones the record
// was signed over.
func (s *Store) liabTree(e SupplyEpochEntry) (*liabtree.Tree, uint64, error) {
	var ledgerHW uint64
	var leaves int
	err := s.db.QueryRow(`SELECT ledger_hw, leaves FROM liab_meta WHERE to_day = ?`, e.ToDay).Scan(&ledgerHW, &leaves)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrProofUnavailable // dropped after its 14 days
	}
	if err != nil {
		return nil, 0, err
	}
	if t := s.liabTrees.get(e.ToDay); t != nil && liabtree.Hex(t.Root()) == e.Root {
		return t, ledgerHW, nil
	}
	rows, err := s.db.Query(`SELECT pos, aid, balance, salt FROM liab_leaf WHERE to_day = ? ORDER BY pos`, e.ToDay)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	entries := make([]liabtree.Entry, 0, leaves)
	for rows.Next() {
		var pos int
		var en liabtree.Entry
		var salt []byte
		if err := rows.Scan(&pos, &en.AID, &en.Balance, &salt); err != nil {
			return nil, 0, err
		}
		if pos != len(entries) || len(salt) != liabtree.SaltSize {
			return nil, 0, fmt.Errorf("hub: epoch %d: leaf %d is damaged", e.Seq, pos)
		}
		copy(en.Salt[:], salt)
		entries = append(entries, en)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(entries) != leaves {
		return nil, 0, fmt.Errorf("hub: epoch %d keeps %d of its %d leaves", e.Seq, len(entries), leaves)
	}
	t, err := liabtree.Rebuild(e.ToDay, entries)
	if err != nil {
		return nil, 0, fmt.Errorf("hub: epoch %d: %w", e.Seq, err)
	}
	if liabtree.Hex(t.Root()) != e.Root || t.Outstanding() != e.Outstanding || t.Depth() != e.depth {
		return nil, 0, fmt.Errorf("hub: epoch %d: the stored leaves do not rebuild the published root", e.Seq)
	}
	s.liabTrees.put(e.ToDay, t)
	return t, ledgerHW, nil
}

// PruneLiabilityProofs deletes the leaves of every epoch published 14 days
// ago or more (PAY-S5); its proofs are proof_unavailable from then on. The
// epoch record itself stays: the chain is permanent.
func (s *Store) PruneLiabilityProofs() error { return s.pruneLiabilityProofsAt(s.now()) }

// pruneLiabilityProofsAt is PruneLiabilityProofs with the clock reading at.
func (s *Store) pruneLiabilityProofsAt(at time.Time) error {
	rows, err := s.db.Query(`SELECT m.to_day, c.record FROM liab_meta m JOIN supply_chain c ON c.to_day = m.to_day`)
	if err != nil {
		return err
	}
	now := at.UnixMilli()
	var old []uint64
	for rows.Next() {
		var toDay uint64
		var raw []byte
		if err := rows.Scan(&toDay, &raw); err != nil {
			rows.Close()
			return err
		}
		pub, err := publishedAt(raw)
		if err != nil {
			rows.Close()
			return err
		}
		if now-pub >= proofKeptFor {
			old = append(old, toDay)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, d := range old {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		for _, q := range []string{`DELETE FROM liab_leaf WHERE to_day = ?`, `DELETE FROM liab_meta WHERE to_day = ?`} {
			if _, err := tx.Exec(q, d); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		s.liabTrees.drop(d)
	}
	return nil
}

// ---- the operator's view ----

// Supply is where this hub's supply stands now: what anet-hub supply prints
// (PAY-S7). It is not public; the public statement is the latest epoch.
type Supply struct {
	// Issued and Redeemed are the running totals; Outstanding is
	// Issued − Redeemed, what the hub owes its users now.
	Issued      int64 `json:"issued"`
	Redeemed    int64 `json:"redeemed"`
	Outstanding int64 `json:"outstanding"`
	// Balances is what the agent rows add up to and HubRow the hub's own
	// row; Consistent says whether the three agree.
	Balances int64 `json:"balances"`
	HubRow   int64 `json:"hub_row"`
	// EventsSincePublish counts the supply events since the last epoch.
	EventsSincePublish int64 `json:"events_since_publish"`
	// Owed is what peer hubs owe this one; Due what this hub owes for
	// payments to agents that bank on peers.
	Owed int64 `json:"owed_by_peers"`
	Due  int64 `json:"due_to_peers"`
	// Latest is the last published epoch, nil before the first.
	Latest *SupplyEpochEntry `json:"latest,omitempty"`
}

// Consistent is the supply invariant (P-PAY-3): the agent balances add up to
// issued − redeemed, and the hub's own row holds the negative of that.
func (s Supply) Consistent() bool {
	return s.Balances == s.Outstanding && s.HubRow == -s.Outstanding
}

// Supply reads where the supply stands now. hubAID names the hub's own row.
func (s *Store) Supply(hubAID string) (Supply, error) {
	var out Supply
	if err := s.db.QueryRow(`SELECT issued, redeemed, events_since_publish FROM supply_totals WHERE id = 1`).
		Scan(&out.Issued, &out.Redeemed, &out.EventsSincePublish); err != nil {
		return out, err
	}
	out.Outstanding = out.Issued - out.Redeemed
	if err := s.db.QueryRow(`SELECT COALESCE(SUM(credits),0) FROM credit_balance WHERE aid<>?`,
		hubAID).Scan(&out.Balances); err != nil {
		return out, err
	}
	if err := s.db.QueryRow(`SELECT COALESCE((SELECT credits FROM credit_balance WHERE aid=?),0)`,
		hubAID).Scan(&out.HubRow); err != nil {
		return out, err
	}
	if err := s.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM hub_owed`).Scan(&out.Owed); err != nil {
		return out, err
	}
	if err := s.db.QueryRow(`SELECT COALESCE(SUM(amount),0) FROM hub_due`).Scan(&out.Due); err != nil {
		return out, err
	}
	if e, ok, err := s.latestEpoch(); err != nil {
		return out, err
	} else if ok {
		out.Latest = &e
	}
	return out, nil
}

// OwedByPeer is what each peer hub owes this one, by peer AID.
func (s *Store) OwedByPeer() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT peer_aid, amount FROM hub_owed WHERE amount > 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var aid string
		var amt int64
		if err := rows.Scan(&aid, &amt); err != nil {
			return nil, err
		}
		out[aid] = amt
	}
	return out, rows.Err()
}

// ---- HTTP ----

// supplyNote is the one sentence /x402/supply carries. It is fixed, so the
// answer is the same bytes until the next epoch is published.
const supplyNote = "epoch is the latest closed period: outstanding is what this hub owed all its users in total " +
	"when it closed, and root is the root of the tree of their balances; record is that statement as this hub " +
	"signed it. Each account checks its own balance against it with GET /agents/{aid}/liability-proof."

// SupplyEpochView is the epoch member of GET /x402/supply.
type SupplyEpochView struct {
	Seq         uint64 `json:"seq"`
	FromDay     uint64 `json:"from_day"`
	ToDay       uint64 `json:"to_day"`
	Root        string `json:"root"`
	Outstanding uint64 `json:"outstanding"`
	Depth       int    `json:"depth"`
}

// SupplyResponse is the answer of GET /x402/supply. Before the first
// publication it has no epoch and no record.
type SupplyResponse struct {
	Hub    string           `json:"hub"`
	Epoch  *SupplyEpochView `json:"epoch,omitempty"`
	Record string           `json:"record,omitempty"`
	Note   string           `json:"note"`
}

// hSupply publishes what this hub owes its users: the latest epoch, nothing
// computed now (PAY-S4). Public and unauthenticated; between two
// publications every answer is the same bytes.
func (s *Server) hSupply(w http.ResponseWriter, _ *http.Request) {
	out := SupplyResponse{Hub: s.hubAID, Note: supplyNote}
	e, ok, err := s.store.latestEpoch()
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	if ok {
		out.Epoch = &SupplyEpochView{Seq: e.Seq, FromDay: e.FromDay, ToDay: e.ToDay, Root: e.Root,
			Outstanding: e.Outstanding, Depth: e.depth}
		out.Record = e.Record
	}
	writeJSON(w, http.StatusOK, out)
}

// IssuanceResponse is the answer of GET /x402/issuance.
type IssuanceResponse struct {
	Entries []SupplyEpochEntry `json:"entries"`
}

// hIssuance serves the published epochs from ?from=<seq> (inclusive; 0 when
// absent), at most issuancePage of them. A reader continues with the last
// seq + 1.
func (s *Server) hIssuance(w http.ResponseWriter, r *http.Request) {
	var from uint64
	if vs, ok := r.URL.Query()["from"]; ok {
		n, err := strconv.ParseUint(vs[0], 10, 64)
		if len(vs) != 1 || err != nil {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
				Error: "from must be one sequence number, a whole number; omit it to start at the first period."})
			return
		}
		from = n
	}
	entries, err := s.store.SupplyEpochs(from, 0)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, IssuanceResponse{Entries: entries})
}

// IssuanceHead is the answer of GET /x402/issuance/head: the last published
// epoch, which is what a witness signs. Empty before the first publication.
type IssuanceHead struct {
	Seq *uint64 `json:"seq,omitempty"`
	ID  string  `json:"id,omitempty"`
}

// hIssuanceHead serves the head of the epoch chain.
func (s *Server) hIssuanceHead(w http.ResponseWriter, _ *http.Request) {
	id, seq, ok, err := supplyHead(s.store.db)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	out := IssuanceHead{}
	if ok {
		out = IssuanceHead{Seq: &seq, ID: id}
	}
	writeJSON(w, http.StatusOK, out)
}

// hLiabilityProof answers GET /agents/{aid}/liability-proof[?to_day=N] to
// the account holder only (relayauth liab_proof, signed by the AID in the
// path): its leaf and path in the epoch that closed on to_day, the latest
// when it is absent.
func (s *Server) hLiabilityProof(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authSelf(w, r, relayauth.ActionLiabProof, signedBodyLimit)
	if !ok {
		return
	}
	var toDay *uint64
	if vs, has := r.URL.Query()["to_day"]; has {
		n, err := strconv.ParseUint(vs[0], 10, 64)
		if len(vs) != 1 || err != nil {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
				Error: "to_day must be one UTC day number, a whole number; omit it for the latest period."})
			return
		}
		toDay = &n
	}
	p, err := s.store.LiabilityProof(a.AID, toDay)
	switch {
	case errors.Is(err, ErrProofUnavailable):
		wire3.Refuse(w, wire3.ReasonProofUnavailable)
		return
	case err != nil:
		wire3.Internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}
