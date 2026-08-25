package aghub

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

// Credit that can only go in is not credit, it is a score.
//
// Until now every path here created credit or moved it between agents,
// and nothing took it back out. That makes the balance a number a hub
// prints, which is a fine thing to be honest about and a poor thing to
// leave unsaid. This file is the way out, and the way to see the whole
// picture:
//
//	redemption   an agent gives credit back to the hub and gets whatever
//	             the hub agreed to give — outside this system. This code
//	             does not touch that side and does not pretend to. What
//	             it does is destroy the credit and sign a statement of
//	             what was destroyed and against which external reference,
//	             so the agent holds a claim it can produce later.
//	supply       what the hub has issued, what has come back, and what is
//	             therefore outstanding. Published, because a custodian
//	             whose liabilities cannot be counted is being trusted for
//	             more than it said.
//	clearing     two hubs settling what they owe each other, so hub_owed
//	             comes down instead of only up.
//
// Redemption is modelled as a payment TO THE HUB, which is what it is.
// That reuses the authorization, its signature, its window and its replay
// guard rather than inventing a second half-tested object — the agent
// signs "pay N to the hub", and the hub's own row is where credit goes to
// stop existing.

// hubLedgerReason marks entries on the hub's own row.
const (
	reasonIssued   = "issued"
	reasonRedeemed = "redeemed"
)

// Redemption is one credit-out event, as the agent sees it.
type Redemption struct {
	AuthID string `json:"auth_id"`
	AID    string `json:"aid"`
	Amount uint64 `json:"amount"`
	// Reference is what the hub is being asked to settle against on the
	// outside — an invoice number, a payout id, whatever that hub and
	// that agent agreed. Opaque here on purpose: a hub that understood
	// the reference would be a payment processor, and this is not one.
	Reference string `json:"reference"`
	At        string `json:"at"`
	// Receipt is the hub's signed statement that the credit was
	// destroyed. Base64 CoreDet-CBOR.
	Receipt string `json:"receipt,omitempty"`
}

// Redeem destroys credit an agent signed away, and says so under
// signature.
//
// The signature requirement is the whole safety of it: a hub cannot
// redeem an agent's balance on the agent's behalf, because it cannot
// produce the authorization. What a hub CAN do is take the credit and
// never deliver whatever it promised outside. Nothing here prevents that
// — it is the custody bargain the whole ledger rests on — but the agent
// walks away holding a signed statement of exactly what was taken and
// against what reference, which is the difference between a dispute and
// a shrug.
func (s *Store) Redeem(hubAID string, p *payment.PaymentPayload, reference string) (Redemption, error) {
	auth, err := s.decodeAuth(hubAID, p)
	if err != nil {
		return Redemption{}, err
	}
	if auth.PayTo != hubAID {
		return Redemption{}, fmt.Errorf(
			"a redemption is signed as a payment to this hub (%s), not to %s", hubAID, auth.PayTo)
	}
	if auth.Payer == hubAID {
		return Redemption{}, fmt.Errorf("the hub cannot redeem its own liability into itself")
	}
	settled := s.SettlePayment(hubAID, p)
	if !settled.Success {
		return Redemption{}, fmt.Errorf("%s", settled.ErrorReason)
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(
		`INSERT INTO credit_redemption(auth_id, aid, amount, reference, at) VALUES(?,?,?,?,?)`,
		settled.Transaction, auth.Payer, int64(auth.Amount), reference, at); err != nil {
		// The credit is already gone; the note is what is missing. Say
		// so rather than reporting a failure that would have the agent
		// believe it still had the balance.
		return Redemption{
			AuthID: settled.Transaction, AID: auth.Payer, Amount: auth.Amount,
			Reference: reference, At: at,
		}, fmt.Errorf("credit was redeemed but the note could not be recorded: %w", err)
	}
	// The hub's own row is the supply counter: it goes down when credit
	// is issued and up when credit comes home, so the rows across the
	// whole ledger sum to zero and a hub's outstanding liability is a
	// number anyone can compute rather than one it reports.
	//
	// The entry is NOT written here. A redemption is a payment whose
	// payee is the hub, and SettlePayment now writes an entry for both
	// parties — so adding one here counted the hub's row twice and drove
	// outstanding negative by the redeemed amount.
	// And on the signed chain, so the supply is auditable in both
	// directions. A redemption missing from the chain would leave the
	// chain overstating what is outstanding.
	if err := s.appendIssuance(EvCreditRetired, auth.Payer, int64(auth.Amount), reference); err != nil {
		log.Printf("hub: redemption %s not recorded on the issuance chain: %v",
			settled.Transaction, err)
	}

	out := Redemption{AuthID: settled.Transaction, AID: auth.Payer, Amount: auth.Amount,
		Reference: reference, At: at}
	if enc, ok := settled.Extensions[payment.ExtReceipt].(string); ok {
		out.Receipt = enc
	}
	return out, nil
}

// entry appends to the ledger without touching a balance.
func (s *Store) entry(aid string, delta int64, reason string) error {
	_, err := s.db.Exec(
		`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
		aid, delta, reason, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// Redemptions lists what an agent has taken out.
func (s *Store) Redemptions(aid string, limit int) ([]Redemption, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT auth_id, aid, amount, reference, at FROM credit_redemption
		 WHERE aid=? ORDER BY rowid DESC LIMIT ?`, aid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Redemption{}
	for rows.Next() {
		var r Redemption
		var amt int64
		if err := rows.Scan(&r.AuthID, &r.AID, &amt, &r.Reference, &r.At); err != nil {
			return nil, err
		}
		r.Amount = uint64(amt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Supply is what this hub has put into circulation and what has come
// back, so its liability can be counted rather than asserted.
type Supply struct {
	Issued      int64 `json:"issued"`
	Redeemed    int64 `json:"redeemed"`
	Outstanding int64 `json:"outstanding"`
	// Balances is what every agent row adds up to. It must equal
	// Outstanding; a hub where it does not has a bug or a thumb on the
	// scale, and either way the number is the way to find out.
	Balances int64 `json:"balances"`
	// Owed is what peer hubs owe this one, kept apart from the local
	// supply because a claim on another hub is not credit here.
	Owed int64 `json:"owed_by_peers"`
	// Due is the other direction: credit this hub destroyed to pay agents
	// that bank on peers, and therefore owes to those peers' hubs.
	//
	// Published because it is the only place the obligation appears. The
	// credit is already off this ledger — outstanding fell when it left —
	// so a reader looking only at supply would see a hub that had retired
	// credit and owed nobody anything.
	Due int64 `json:"due_to_peers"`
	// ChainIssued and ChainRetired are the same totals derived from the
	// signed issuance chain instead of the balance table.
	//
	// Published alongside rather than instead, because the point is the
	// comparison. The two are written by the same process and should
	// always agree; when they do not, this hub moved credit without
	// recording it on the chain, and a reader can see that without
	// trusting either number. ChainAgrees says whether they match.
	ChainIssued  int64 `json:"chain_issued"`
	ChainRetired int64 `json:"chain_retired"`
	// ChainOpening is supply that predates the chain: outstanding when
	// the chain began, issued before anything recorded issuance.
	//
	// Reported separately rather than folded into ChainIssued, because
	// the two are not equally supported. Everything in ChainIssued has a
	// signed, ordered record that a witness can pin. ChainOpening is this
	// hub's own statement about its own past, and nothing outside the hub
	// vouches for it.
	ChainOpening int64 `json:"chain_opening,omitempty"`
	// ChainOutstanding is what the chain says is outstanding now:
	// opening + issued - retired.
	//
	// This, not the issued/redeemed split, is what the chain and the
	// table can be held to. A chain that begins partway through a hub's
	// life knows nothing about how much was issued and redeemed before
	// it — only the net that was outstanding when it opened. Comparing
	// the historical split reported false disagreement on any hub that
	// had processed a redemption before the chain existed.
	ChainOutstanding int64 `json:"chain_outstanding"`
	ChainAgrees      bool  `json:"chain_agrees"`
	// ChainHead is the current head of the issuance chain, which is what
	// a witness attests to.
	//
	// ChainHeadSeq has no omitempty: an AEL's first record is seq 0, and
	// omitting it would make a one-record chain indistinguishable from no
	// chain to every reader deciding whether there is a head to pin.
	ChainHead    string `json:"chain_head,omitempty"`
	ChainHeadSeq uint64 `json:"chain_head_seq"`
}

// Supply computes the hub's position.
func (s *Store) Supply(hubAID string) (Supply, error) {
	var out Supply
	if err := s.db.QueryRow(
		`SELECT COALESCE(SUM(delta),0) FROM credit_entry WHERE aid=? AND delta<0`,
		hubAID).Scan(&out.Issued); err != nil {
		return out, err
	}
	out.Issued = -out.Issued
	if err := s.db.QueryRow(
		`SELECT COALESCE(SUM(delta),0) FROM credit_entry WHERE aid=? AND delta>0`,
		hubAID).Scan(&out.Redeemed); err != nil {
		return out, err
	}
	out.Outstanding = out.Issued - out.Redeemed
	if err := s.db.QueryRow(
		`SELECT COALESCE(SUM(credits),0) FROM credit_balance WHERE aid<>?`,
		hubAID).Scan(&out.Balances); err != nil {
		return out, err
	}
	if err := s.db.QueryRow(
		`SELECT COALESCE(SUM(amount),0) FROM hub_owed`).Scan(&out.Owed); err != nil {
		return out, err
	}
	if err := s.db.QueryRow(
		`SELECT COALESCE(SUM(amount),0) FROM hub_due`).Scan(&out.Due); err != nil {
		return out, err
	}
	ci, cr, co, cerr := s.IssuanceTotals()
	if cerr != nil {
		return out, cerr
	}
	out.ChainIssued, out.ChainRetired, out.ChainOpening = ci, cr, co
	out.ChainOutstanding = co + ci - cr
	out.ChainAgrees = out.ChainOutstanding == out.Outstanding
	out.ChainHead, out.ChainHeadSeq, _ = s.IssuanceHead()
	return out, nil
}

// ---- clearing between hubs ----

// SettleOwed reduces what a peer hub owes us, against that peer's signed
// statement that it has paid.
//
// The counterpart to ClearFromPeer, and the half that was missing: owed
// only ever went up. What "paid" means between two hubs is outside this
// system — an invoice, a wire, a standing arrangement — and this does not
// model it. What it does is let the peer say, under its own key, "that
// obligation is discharged", and hold the peer to exactly what it signed.
//
// A peer could sign a discharge it never funded. That is the same trust
// ClearFromPeer already extends and the same answer applies: peers are an
// allowlist, and the statement is attributable, so a peer that does this
// can be shown to have done it.
func (s *Store) SettleOwed(hubAID, peerAID string, peerKEL []identity.SignedEvent,
	rec *payment.Receipt) error {
	if rec == nil {
		return fmt.Errorf("no clearing statement")
	}
	if rec.Payer != peerAID {
		return fmt.Errorf("this statement is from %s, not from %s", rec.Payer, peerAID)
	}
	if rec.PayTo != hubAID {
		return fmt.Errorf("this statement discharges an obligation to %s, not to us", rec.PayTo)
	}
	if err := rec.Verify(peerKEL, peerAID, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("clearing statement from %s: %w", peerAID, err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The replay guard goes FIRST, and the ordering is not cosmetic.
	// Checking the balance first meant a re-sent discharge — the ordinary
	// consequence of a lost response — was rejected as an attempt to
	// clear more than was owed, because the first one had already cleared
	// it. A retry is not an attack, and a system that answers it as one
	// leaves two hubs disagreeing about a debt that is in fact settled.
	//
	// One row per statement id: a peer replaying a discharge clears the
	// obligation once.
	if _, err := tx.Exec(
		`INSERT INTO hub_cleared(auth_id, peer_aid, amount, at) VALUES(?,?,?,?)`,
		rec.AuthID, peerAID, int64(rec.Amount), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return nil // already applied; the same statement, not a new one
	}
	var owed int64
	if err := tx.QueryRow(`SELECT COALESCE(amount,0) FROM hub_owed WHERE peer_aid=?`,
		peerAID).Scan(&owed); err != nil && err.Error() != "sql: no rows in result set" {
		return err
	}
	if int64(rec.Amount) > owed {
		// Rolls back the guard row with it, so this exact statement can
		// be presented again if the debt ever reaches that size.
		return fmt.Errorf("%s offers to clear %d but owes %d", peerAID, rec.Amount, owed)
	}
	if _, err := tx.Exec(
		`UPDATE hub_owed SET amount = amount - ? WHERE peer_aid = ?`,
		int64(rec.Amount), peerAID); err != nil {
		return err
	}
	return tx.Commit()
}

// IssueOwedSettlement signs this hub's statement that it has discharged
// what it owes a peer.
func (s *Store) IssueOwedSettlement(hubAID, peerAID string, amount uint64,
	reference string) (*payment.Receipt, error) {
	if s.hubKey == nil {
		return nil, fmt.Errorf("this hub holds no signing key")
	}
	if amount == 0 {
		return nil, fmt.Errorf("nothing to clear")
	}
	// The id has to be unique per statement, not per reference.
	//
	// It was peer + reference, and a reference is a human's note about
	// why — "prodtest-clear", "august invoice". Two genuinely different
	// discharges written with the same note produced the same id, and the
	// creditor's replay guard swallowed the second one as a repeat of the
	// first: it answered 200 with the debt unchanged, while the debtor
	// reduced its own record on the strength of that 200. The two hubs
	// then disagreed about a debt, which is precisely what the replay
	// guard exists to prevent.
	//
	// Amount and a random nonce, so two statements are the same statement
	// only when they really are one. A timestamp alone would not do it:
	// two discharges within the same millisecond are rare and not
	// impossible, and "rare" is how this class of bug gets shipped.
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	rec := &payment.Receipt{
		AuthID: fmt.Sprintf("clear:%s:%s:%d:%d:%s",
			peerAID, reference, amount, now, hex.EncodeToString(nonce[:])),
		Payer:    hubAID,
		PayTo:    peerAID,
		Amount:   amount,
		Network:  payment.CreditNetwork(hubAID),
		SettleAt: now,
	}
	if err := rec.Sign(s.hubKey); err != nil {
		return nil, err
	}
	return rec, nil
}

// ---- HTTP ----

// hRedeem takes credit out of circulation.
func (s *Server) hRedeem(w http.ResponseWriter, r *http.Request) {
	var req struct {
		X402Version    int                     `json:"x402Version"`
		PaymentPayload *payment.PaymentPayload `json:"paymentPayload"`
		Reference      string                  `json:"reference"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": payment.ReasonMalformed})
		return
	}
	out, err := s.store.Redeem(s.hubAID, req.PaymentPayload, req.Reference)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "redemption": out})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// hRedemptions lists an agent's withdrawals.
func (s *Server) hRedemptions(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.Redemptions(r.PathValue("aid"), 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"redemptions": out})
}

// hSupply publishes what this hub owes its users.
//
// Public and unauthenticated. A custodian that would only tell you its
// liabilities if you asked nicely is one whose liabilities you should
// assume are worse than it says.
func (s *Server) hSupply(w http.ResponseWriter, _ *http.Request) {
	out, err := s.store.Supply(s.hubAID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hub":    s.hubAID,
		"supply": out,
		"note": "outstanding is what this hub owes its users. balances is what those users' rows " +
			"add up to; the two must agree. credit is issued by this hub and redeemed back to it — " +
			"what a redemption is worth outside this ledger is between the hub and the agent, and " +
			"is not something this software can vouch for.",
	})
}

// clearingRequest is a peer hub saying it has paid what it owed.
type clearingRequest struct {
	PeerAID string `json:"peer_aid"`
	// Receipt is the peer's signed statement, base64 CoreDet-CBOR.
	Receipt string `json:"receipt"`
}

// hClear applies a peer's discharge.
func (s *Server) hClear(w http.ResponseWriter, r *http.Request) {
	var req clearingRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": payment.ReasonMalformed})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.Receipt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "receipt not base64"})
		return
	}
	rec, err := payment.UnmarshalReceipt(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	kel, err := s.peerKEL(req.PeerAID)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	if err := s.store.SettleOwed(s.hubAID, req.PeerAID, kel, rec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	owed, _ := s.store.Owed(req.PeerAID)
	writeJSON(w, http.StatusOK, map[string]any{"peer": req.PeerAID, "owed": owed})
}
