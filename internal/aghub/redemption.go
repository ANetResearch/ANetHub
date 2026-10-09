package aghub

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
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
//	supply       what the hub owes in total, published once per supply
//	             epoch with a tree each account checks its own balance
//	             against (supply.go). Published, because a custodian whose
//	             liabilities cannot be counted is being trusted for more
//	             than it said.
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
	// Seq orders the redemptions; /agents/{aid}/redemptions states the
	// earliest of its window as oldest_seq.
	Seq    uint64 `json:"seq"`
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
	// StoredAmount is set, and Amount left 0, only on a row whose stored
	// amount is not a positive int64: one written before the amount
	// range check, when a redemption signed for 2^64-1000 was stored as
	// -1000 and credited the redeemer. It is the stored figure as it is.
	StoredAmount int64 `json:"stored_amount,omitempty"`
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
//
// It settles through settleAuth rather than SettleWithRequirements. The one
// term of a redemption is that the payee is this hub, checked here;
// requirements built from the authorization's own amount would only
// compare the authorization with itself.
func (s *Store) Redeem(hubAID string, p *payment.PaymentPayload, reference string) (Redemption, error) {
	auth, id, kel, rf := s.verifiedAuth(hubAID, p)
	if rf != nil {
		return Redemption{}, rf
	}
	// verifiedAuth refused it already (parseAuth); the conversion is kept
	// behind the same check. An overflowing redemption used to be booked
	// as a negative one, which credited the redeemer: minting.
	amt, ok := amountInt64(auth.Amount)
	if !ok {
		return Redemption{}, amountRefusal("authorization", auth.Amount)
	}
	if auth.PayTo != hubAID {
		return Redemption{}, refuse(payment.ReasonPayeeMismatch,
			"a redemption is signed as a payment to this hub (%s), not to %s", hubAID, auth.PayTo)
	}
	if auth.Payer == hubAID {
		return Redemption{}, fmt.Errorf("the hub cannot redeem its own liability into itself")
	}
	// A redemption already recorded for this authorization is answered with
	// that record and its receipt, whether or not the window has closed:
	// the agent resending the authorization is asking what became of it,
	// the question a repeated settlement asks (A2A-DESIGN §8.5). It used to
	// reach the insert below, fail on the primary key, and report "credit
	// was redeemed but the note could not be recorded" for a note that had
	// been recorded.
	if prior, found, err := s.redemptionOf(hubAID, id); err != nil {
		return Redemption{}, refuse(payment.ReasonSettlementFailed, "%v", err)
	} else if found {
		return prior, nil
	}
	if rf := currentAuth(auth, kel, s.now().UnixMilli()); rf != nil {
		return Redemption{}, rf
	}
	settled := s.settleAuth(hubAID, auth, id, "")
	if !settled.Success {
		detail, _ := settled.Extensions[payment.ExtErrorDetail].(string)
		return Redemption{}, &Refusal{Reason: settled.ErrorReason, Detail: detail}
	}
	at := ledgerStamp(s.now())
	res, err := s.db.Exec(
		`INSERT INTO credit_redemption(auth_id, aid, amount, reference, at) VALUES(?,?,?,?,?)`,
		settled.Transaction, auth.Payer, amt, reference, at)
	if err != nil {
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
	// Neither the entry nor the supply event is written here. A
	// redemption is a payment whose payee is the hub, and settleAuth
	// writes an entry for both parties and records the credit leaving
	// circulation, in the settlement's transaction — so adding either here
	// would count it twice.

	out := Redemption{AuthID: settled.Transaction, AID: auth.Payer, Amount: auth.Amount,
		Reference: reference, At: at}
	if seq, err := res.LastInsertId(); err == nil && seq > 0 {
		out.Seq = uint64(seq)
	}
	if enc, ok := settled.Extensions[payment.ExtReceipt].(string); ok {
		out.Receipt = enc
	}
	return out, nil
}

// RedemptionWindow is what /agents/{aid}/redemptions serves: an account's
// redemptions of the last LedgerWindowDays days (PAY-L6), the newest limit
// of them, newest first, with the window's totals.
type RedemptionWindow struct {
	Redemptions []Redemption
	// Total and Sum cover every redemption of the window, whatever the
	// page; OldestSeq is the seq of the earliest of them, 0 when there is
	// none.
	Total     int
	Sum       uint64
	OldestSeq uint64
}

// Redemptions lists what an agent has taken out in the ledger window,
// newest first. Older ones are deleted (janitor.go): the redeemer's own
// lasting record is the receipt on its evidence chain.
func (s *Store) Redemptions(aid string, limit int) (RedemptionWindow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	from := windowStart(s.now())
	var w RedemptionWindow
	var n int64
	var amt, oldest sql.NullInt64
	if err := s.db.QueryRow(
		`SELECT COUNT(*), SUM(amount), MIN(seq) FROM credit_redemption WHERE aid=? AND at >= ?`, aid, from,
	).Scan(&n, &amt, &oldest); err != nil {
		return w, err
	}
	w.Total = int(n)
	if amt.Valid {
		// 0 for a total that is not a positive int64 (possible only with
		// rows from before the amount range check); see storedAmount.
		w.Sum, _ = storedAmount(amt.Int64)
	}
	if oldest.Valid {
		w.OldestSeq = uint64(oldest.Int64)
	}
	rows, err := s.db.Query(
		`SELECT seq, auth_id, aid, amount, reference, at FROM credit_redemption
		 WHERE aid=? AND at >= ? ORDER BY seq DESC LIMIT ?`, aid, from, limit)
	if err != nil {
		return w, err
	}
	defer rows.Close()
	w.Redemptions = []Redemption{}
	for rows.Next() {
		var r Redemption
		var amt int64
		if err := rows.Scan(&r.Seq, &r.AuthID, &r.AID, &amt, &r.Reference, &r.At); err != nil {
			return w, err
		}
		// A row from before the amount range check (-1000 for a
		// redemption signed as 2^64-1000) is listed, since it is the
		// account's history, but not as an amount it never was: a bare
		// uint64(…) would show the overflowed figure as credit taken out.
		if n, ok := storedAmount(amt); ok {
			r.Amount = n
		} else {
			r.StoredAmount = amt
			log.Printf("hub: %v", errStoredAmount("credit_redemption", r.AuthID, amt))
		}
		w.Redemptions = append(w.Redemptions, r)
	}
	return w, rows.Err()
}

// redemptionOf is the redemption recorded for an authorization, with the
// settlement's receipt, if there is one.
func (s *Store) redemptionOf(hubAID, authID string) (Redemption, bool, error) {
	var r Redemption
	var amt int64
	err := s.db.QueryRow(
		`SELECT seq, auth_id, aid, amount, reference, at FROM credit_redemption WHERE auth_id=?`, authID).
		Scan(&r.Seq, &r.AuthID, &r.AID, &amt, &r.Reference, &r.At)
	if errors.Is(err, sql.ErrNoRows) {
		return Redemption{}, false, nil
	}
	if err != nil {
		return Redemption{}, false, err
	}
	// Answered as a record only when it could be one; see storedAmount.
	n, ok := storedAmount(amt)
	if !ok {
		return Redemption{}, false, errStoredAmount("credit_redemption", authID, amt)
	}
	r.Amount = n
	if settled, _, ok, err := s.settledBefore(hubAID, authID); err != nil {
		return Redemption{}, false, err
	} else if ok {
		r.Receipt, _ = settled.Extensions[payment.ExtReceipt].(string)
	}
	return r, true, nil
}

// ---- clearing between hubs ----

// StatementError is a peer's discharge statement this hub does not apply
// (POST /fed/v3/clear answers 400 bad_request with the sentence).
type StatementError struct{ Sentence string }

func (e *StatementError) Error() string { return e.Sentence }

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
//
// A statement this hub does not apply is a *StatementError, whose sentence
// says why; any other error is this hub's.
func (s *Store) SettleOwed(hubAID, peerAID string, peerKEL []identity.SignedEvent,
	rec *payment.Receipt) error {
	if rec == nil {
		return &StatementError{"The request carries no discharge statement; send the signed statement as receipt."}
	}
	// A negative discharge passes "more than owed" and raises the debt.
	amt, ok := amountInt64(rec.Amount)
	if !ok {
		return amountRefusal("clearing statement", rec.Amount)
	}
	if rec.Payer != peerAID {
		return &StatementError{"The statement is not your hub's own (its payer is another hub); sign it as your hub and send it again."}
	}
	if rec.PayTo != hubAID {
		return &StatementError{"The statement discharges what is owed to another hub, not to this one; address it to this hub and send it again."}
	}
	// At the time the peer signed it (KEL H-34).
	if err := rec.Verify(peerKEL, peerAID, rec.SettleAt); err != nil {
		return &StatementError{"The statement's signature does not verify against your hub's key history; sign it again with your hub's current key."}
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
		rec.AuthID, peerAID, amt, ledgerStamp(s.now())); err != nil {
		// Already applied is success: the same statement, not a new one.
		// Any other failure to write the row is returned; reading every
		// failure as "already applied" answered a discharge that was never
		// applied as done, and the debtor then reduced its own record.
		var n int
		if qerr := tx.QueryRow(`SELECT COUNT(1) FROM hub_cleared WHERE auth_id=?`, rec.AuthID).
			Scan(&n); qerr == nil && n > 0 {
			return nil
		}
		return fmt.Errorf("recording the discharge %s: %w", rec.AuthID, err)
	}
	var owed int64
	if err := tx.QueryRow(`SELECT COALESCE(amount,0) FROM hub_owed WHERE peer_aid=?`,
		peerAID).Scan(&owed); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if amt > owed {
		// Rolls back the guard row with it, so this exact statement can
		// be presented again if the debt ever reaches that size.
		return &StatementError{fmt.Sprintf("The statement discharges %d credits, and this hub records your hub owing it %d; "+
			"compare the two hubs' records, then send a statement for at most that.", amt, owed)}
	}
	if _, err := tx.Exec(
		`UPDATE hub_owed SET amount = amount - ? WHERE peer_aid = ?`,
		amt, peerAID); err != nil {
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
	// The peer books this as an int64, and so does DischargeDue here; see
	// amountInt64.
	if _, ok := amountInt64(amount); !ok {
		return nil, amountRefusal("discharge", amount)
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
	now := s.now().UnixMilli()
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

// RedemptionsResponse is GET /agents/{aid}/redemptions: the account's
// redemptions of the ledger window, newest first (core §2.12.2;
// hub-payment-privacy PAY-L6).
type RedemptionsResponse struct {
	Redemptions []Redemption `json:"redemptions"`
	// Total and Sum cover every redemption of the window, whatever the
	// page; Returned is how many this page lists.
	Total     int    `json:"total"`
	Sum       uint64 `json:"sum"`
	Returned  int    `json:"returned"`
	Truncated bool   `json:"truncated,omitempty"`
	Note      string `json:"note,omitempty"`
	// WindowDays is always LedgerWindowDays; OldestSeq is the seq of the
	// earliest redemption in the window, 0 when there is none.
	WindowDays uint   `json:"window_days"`
	OldestSeq  uint64 `json:"oldest_seq"`
}

// hRedemptions lists an agent's withdrawals of the ledger window, newest
// first.
//
// The same shape hLedger carries, for the same reason: the page is
// capped and the response used to say nothing about it. Once an account
// passed 100 withdrawals the list stopped growing — a new redemption
// pushed the oldest one out — so a caller counting the list to see whether
// its withdrawal landed got the same number forever, and had no field to
// tell it the answer was a page rather than the history.
//
// Found by scripts/prodtest.sh: "did the redemption appear in the list"
// stayed red for sixty seconds of polling while the very next check found
// the record — because it matched one left by an earlier run.
//
// total and sum cover the whole window regardless of the page; window_days
// and oldest_seq say that the window is all there is (PAY-L6): older
// redemptions are deleted, and the redeemer's lasting record is the receipt
// on its own evidence chain.
//
// Served to the account holder only: the request must be signed by the
// AID in the path (relayauth v2, action "redemptions"), and the signature
// covers the query, so ?limit is part of what was signed. Unsigned → 401.
// See hBalance for why.
func (s *Server) hRedemptions(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authSelf(w, r, relayauth.ActionRedemptions, signedBodyLimit)
	if !ok {
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &limit)
	}
	win, err := s.store.Redemptions(a.AID, limit)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	out := RedemptionsResponse{Redemptions: win.Redemptions, Total: win.Total, Sum: win.Sum,
		Returned: len(win.Redemptions), WindowDays: LedgerWindowDays, OldestSeq: win.OldestSeq}
	if win.Total > len(win.Redemptions) {
		out.Truncated = true
		out.Note = "redemptions is the newest page; total and sum cover every withdrawal of the last " +
			"window_days days. Older ones are deleted; your receipts are your record of them."
	}
	writeJSON(w, http.StatusOK, out)
}

// ClearRequest is the body of POST /fed/v3/clear: a peer hub's signed
// statement that it has paid what it owed this hub (the body of the former
// /federation/clear; core §2.12.2).
type ClearRequest struct {
	// PeerAID is the hub that sends the statement; it must be the hub that
	// signed the request.
	PeerAID string `json:"peer_aid"`
	// Receipt is the statement, coredet(payment.Receipt) in base64url
	// (core CORE-E5).
	Receipt string `json:"receipt"`
}

// ClearResponse is the answer of POST /fed/v3/clear: the peer, and what it
// still owes this hub once the statement is applied.
type ClearResponse struct {
	Peer string `json:"peer"`
	Owed int64  `json:"owed"`
}

// FedClearBodyLimit bounds a /fed/v3/clear body: an AID and one statement.
const FedClearBodyLimit = 64 << 10

// ServeFedClear answers POST /fed/v3/clear (hub-payment-privacy PAY-U2) for a
// request the peer hub peerAID signed (federation authPeer has checked the
// peer table, the signature and RC1), whose body is body: the peer's signed
// statement that it has paid what it owed. Applied once (SettleOwed); a
// repeat of an applied statement is answered as applied. A refusal is a
// wire-3 error body (core G1): 400 bad_request, with a sentence that says
// what is wrong with the request or the statement.
func (s *Server) ServeFedClear(w http.ResponseWriter, peerAID string, body []byte) {
	var req ClearRequest
	if err := wire3.DecodeStrict(body, &req); err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	if req.PeerAID != peerAID {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The member \"peer_aid\" names another hub than the one that signed this request; name your own hub and send again."})
		return
	}
	raw, err := wire3.DecodeB64URL("receipt", req.Receipt)
	if err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	rec, err := payment.UnmarshalReceipt(raw)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The member \"receipt\" is not a signed discharge statement; send the statement your hub signed."})
		return
	}
	kel, err := s.store.peerKELFor(s.peerKEL, peerAID, receiptSeq(rec))
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	if err := s.store.SettleOwed(s.hubAID, peerAID, kel, rec); err != nil {
		var se *StatementError
		var rf *Refusal
		switch {
		case errors.As(err, &se):
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest, Error: se.Sentence})
		case errors.As(err, &rf):
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest, Error: fmt.Sprintf(
				"The statement discharges %d credits, outside 1..%d; sign one for a whole number of credits in that range.",
				rec.Amount, int64(math.MaxInt64))})
		default:
			wire3.Internal(w, err)
		}
		return
	}
	owed, err := s.store.Owed(peerAID)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	log.Printf("hub: fed_clear signed by %s: applied; it owes this hub %d", peerAID, owed)
	writeJSON(w, http.StatusOK, ClearResponse{Peer: peerAID, Owed: owed})
}
