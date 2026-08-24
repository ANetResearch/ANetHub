package aghub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

// This hub is an x402 facilitator for its own credit rail.
//
// x402 permits it explicitly — a resource server may host the facilitator
// endpoints itself, with no separation required — and for a ledger rail
// there is nothing to separate from: the balances are here.
//
// # Custody, stated plainly
//
// On an onchain rail a facilitator holds no funds; it broadcasts an
// authorization the payer signed and could not divert it. That property
// does not carry over. This hub keeps the balances, so this hub is their
// custodian, and an agent registering here is choosing to trust it with
// that. Nothing in x402 changes it and the name should not be allowed to
// imply otherwise.
//
// What this hub cannot do is rewrite what happened. The payer signs the
// authorization; this hub signs the settlement; both parties keep both
// and put the event on their own evidence chains. The balance is ours.
// The record is theirs.

// creditDecimals is how many ledger units make one credit. Integers
// throughout — a balance that can be half a unit is a balance with a
// rounding policy, and a rounding policy is a way to lose money quietly.
const creditDecimals = 0

// Balance is one agent's standing on this hub's ledger.
type Balance struct {
	AID     string `json:"aid"`
	Credits int64  `json:"credits"`
}

// Credit adds to an agent's balance — how a hub operator funds an
// account, however they decide accounts get funded.
//
// The matching debit goes on the hub's own row. Credit does not appear
// from nowhere: it is issued, and the issuer carries the liability. That
// is what makes Supply computable instead of asserted — the rows across
// the whole ledger sum to zero, so "what this hub owes its users" is
// arithmetic anyone can repeat rather than a number the hub reports.
func (s *Store) Credit(aid string, amount int64, reason string) error {
	if amount == 0 {
		return nil
	}
	if s.hubAID != "" && aid != s.hubAID {
		if err := s.entry(s.hubAID, -amount, reasonIssued+":"+reason); err != nil {
			return err
		}
		// On the signed chain before the balance moves. A grant recorded
		// only in the balance table is a grant nothing outside this hub
		// attests to, which is the gap this chain exists to close.
		if err := s.appendIssuance(EvCreditIssued, aid, amount, reason); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(
		`INSERT INTO credit_balance(aid, credits) VALUES(?,?)
		 ON CONFLICT(aid) DO UPDATE SET credits = credits + excluded.credits`, aid, amount)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
		aid, amount, reason, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// Balance reads one.
func (s *Store) Balance(aid string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT credits FROM credit_balance WHERE aid=?`, aid).Scan(&n)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return 0, nil
	}
	return n, err
}

// VerifyPayment answers "would this settle?" without moving anything.
func (s *Store) VerifyPayment(hubAID string, p *payment.PaymentPayload) payment.VerifyResponse {
	auth, err := s.decodeAuth(hubAID, p)
	if err != nil {
		return payment.VerifyResponse{IsValid: false, InvalidReason: err.Error()}
	}
	bal, err := s.Balance(auth.Payer)
	if err != nil {
		return payment.VerifyResponse{IsValid: false, InvalidReason: err.Error()}
	}
	if bal < int64(auth.Amount) {
		return payment.VerifyResponse{IsValid: false, Payer: auth.Payer,
			InvalidReason: fmt.Sprintf("insufficient balance: has %d, needs %d", bal, auth.Amount)}
	}
	if spent, _ := s.authSpent(auth); spent {
		return payment.VerifyResponse{IsValid: false, Payer: auth.Payer,
			InvalidReason: "authorization already settled"}
	}
	return payment.VerifyResponse{IsValid: true, Payer: auth.Payer}
}

// SettlePayment moves the credit, once.
//
// Idempotent on the authorization's content id: a settle call repeated
// because a reply was lost must not charge twice, and the id derives from
// the signed bytes so a payer cannot make two different authorizations
// look like one.
// PeerSettler forwards a settlement to the hub that owns the ledger and
// clears the result locally. Wired by the application, so this package
// keeps knowing nothing about federation.
type PeerSettler func(network string, p *payment.PaymentPayload) (payment.SettlementResponse, bool)

// SetPeerSettler installs the cross-hub settlement path.
func (s *Store) SetPeerSettler(f PeerSettler) { s.peerSettle = f }

// SetClearablePeers records whose ledgers this hub will settle against.
//
// Wired from federation rather than read from it, so the kernel still
// knows nothing about federation (K207).
func (s *Store) SetClearablePeers(f func() []string) { s.clearable = f }

// ClearablePeers is the AIDs of hubs this one will forward a settlement
// to. Empty when federation is off, which is the honest answer: an
// unfederated hub can only settle on its own ledger.
func (s *Store) ClearablePeers() []string {
	if s.clearable == nil {
		return nil
	}
	return s.clearable()
}

func (s *Store) SettlePayment(hubAID string, p *payment.PaymentPayload) payment.SettlementResponse {
	// A payment on another hub's ledger is that hub's to settle. We ask
	// it, and if it says yes we credit our own payee and record what that
	// hub now owes us — the two hubs clearing against each other rather
	// than one of them minting.
	if p != nil && p.Accepted.Network != payment.CreditNetwork(hubAID) && s.peerSettle != nil {
		if r, handled := s.peerSettle(p.Accepted.Network, p); handled {
			return r
		}
	}
	auth, err := s.decodeAuth(hubAID, p)
	if err != nil {
		return payment.SettlementResponse{Success: false, ErrorReason: err.Error(),
			Network: payment.CreditNetwork(hubAID)}
	}
	id, err := auth.ID()
	if err != nil {
		return payment.SettlementResponse{Success: false, ErrorReason: err.Error(),
			Network: payment.CreditNetwork(hubAID)}
	}
	fail := func(reason string) payment.SettlementResponse {
		return payment.SettlementResponse{Success: false, ErrorReason: reason, Payer: auth.Payer,
			Transaction: id, Network: auth.Network, Amount: payment.Amount(auth.Amount)}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fail(err.Error())
	}
	defer tx.Rollback()

	// The settled table is the idempotency key AND the replay guard: one
	// row per authorization id, inserted first, so a concurrent second
	// settle loses on the primary key rather than on a check it raced.
	if _, err := tx.Exec(
		`INSERT INTO credit_settled(auth_id, payer, pay_to, amount, interaction_id, at)
		 VALUES(?,?,?,?,?,?)`,
		id, auth.Payer, auth.PayTo, int64(auth.Amount), auth.InteractionID,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		// Already settled: report the same success as the first call, so a
		// retried settle is indistinguishable from the one that worked.
		//
		// Including the receipt. A caller whose first response was lost is
		// the caller most in need of the hub's signed statement, and
		// answering the retry with a bare success would leave the one
		// party who has actually been charged holding nothing to show for
		// it. The flag says it was a replay; the proof is the same proof.
		replay := s.signSettlement(payment.SettlementResponse{Success: true, Payer: auth.Payer,
			Transaction: id, Network: auth.Network, Amount: payment.Amount(auth.Amount)}, auth, id)
		if replay.Extensions == nil {
			replay.Extensions = map[string]any{}
		}
		replay.Extensions["anet.replayed"] = true
		return replay
	}

	var bal int64
	if err := tx.QueryRow(`SELECT COALESCE(credits,0) FROM credit_balance WHERE aid=?`,
		auth.Payer).Scan(&bal); err != nil && err.Error() != "sql: no rows in result set" {
		return fail(err.Error())
	}
	if bal < int64(auth.Amount) {
		// The x402 reason first so a client can branch on a constant, the
		// numbers after so a person can see how short they were.
		return fail(fmt.Sprintf("%s: has %d, needs %d",
			payment.ReasonInsufficientFunds, bal, auth.Amount))
	}
	if _, err := tx.Exec(
		`INSERT INTO credit_balance(aid, credits) VALUES(?, -?)
		 ON CONFLICT(aid) DO UPDATE SET credits = credits - ?`,
		auth.Payer, int64(auth.Amount), int64(auth.Amount)); err != nil {
		return fail(err.Error())
	}
	// Whether the payee banks here decides where the credit goes.
	//
	// A payee registered here is credited, and the two rows net to zero:
	// credit moved between two accounts on one ledger and the supply did
	// not change.
	//
	// A payee registered on a peer holds no account here, and crediting it
	// anyway was wrong in a way nothing local could see. The payee's own
	// hub credits it too, on the peer's signed receipt — so one payment
	// produced two credits, one on each ledger, and the total across the
	// federation grew by the amount paid. Each hub stayed internally
	// consistent, so neither hub's own supply check could notice.
	//
	// So: this hub destroys the credit and records what it now owes the
	// payee. That is the true position — the value left this ledger — and
	// it is the debt the payee's hub is recording as a claim.
	// An account this hub keeps: a registered agent, or the hub itself.
	// The hub is a payee on every redemption — a redemption is a payment
	// to the hub — and it holds the supply row rather than an agent
	// registration, so checking the agent table alone classified every
	// redemption as cross-hub and stopped moving the supply counter.
	local := auth.PayTo == hubAID
	if !local {
		if err := tx.QueryRow(`SELECT COUNT(1) FROM agent WHERE aid=?`,
			auth.PayTo).Scan(&local); err != nil {
			return fail(err.Error())
		}
	}
	if local {
		if _, err := tx.Exec(
			`INSERT INTO credit_balance(aid, credits) VALUES(?,?)
			 ON CONFLICT(aid) DO UPDATE SET credits = credits + ?`,
			auth.PayTo, int64(auth.Amount), int64(auth.Amount)); err != nil {
			return fail(err.Error())
		}
	} else {
		if _, err := tx.Exec(
			`INSERT INTO hub_due(payee_aid, amount) VALUES(?,?)
			 ON CONFLICT(payee_aid) DO UPDATE SET amount = amount + ?`,
			auth.PayTo, int64(auth.Amount), int64(auth.Amount)); err != nil {
			return fail(err.Error())
		}
		// The credit comes home to the hub's own row, which is the same
		// movement a redemption makes: value left this ledger, so this
		// hub's outstanding liability falls by it. Without this the payer
		// was debited and nothing recorded the drop, so outstanding kept
		// counting credit that was no longer on any account here.
		if _, err := tx.Exec(
			`INSERT INTO credit_balance(aid, credits) VALUES(?,?)
			 ON CONFLICT(aid) DO UPDATE SET credits = credits + ?`,
			hubAID, int64(auth.Amount), int64(auth.Amount)); err != nil {
			return fail(err.Error())
		}
	}
	// The ledger entries, in the same transaction as the balance move.
	//
	// Settlement changed credit_balance and wrote nothing to
	// credit_entry, so /agents/{aid}/ledger showed grants and nothing
	// else: an agent could not see what it had paid or been paid, and the
	// balance disagreed with the entries behind it by exactly the amount
	// that had moved through payments. Found by `anet reconcile` against
	// the live hub, which is what it was built to do.
	//
	// The reason column carries the transaction id, which is what the
	// payer's own evidence chain records. That is what lets the two sides
	// be matched at all.
	at := time.Now().UTC().Format(time.RFC3339Nano)
	for _, e := range []struct {
		aid   string
		delta int64
	}{
		{auth.Payer, -int64(auth.Amount)},
		{auth.PayTo, int64(auth.Amount)},
	} {
		// A foreign payee has no account here, so it gets no entry here.
		// Its entry is written by its own hub when that hub clears this
		// settlement. An entry for an account that does not exist would
		// read as credit held here that is not.
		if e.aid == auth.PayTo && !local {
			// The foreign payee gets no entry here; the hub's own row does,
			// because that is where the credit went. Supply is counted off
			// this row, so the entry is what makes the liability fall.
			if _, err := tx.Exec(
				`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
				hubAID, int64(auth.Amount), id, at); err != nil {
				return fail(err.Error())
			}
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
			e.aid, e.delta, id, at); err != nil {
			return fail(err.Error())
		}
	}
	if err := tx.Commit(); err != nil {
		return fail(err.Error())
	}
	// Credit that left this ledger goes on the signed chain, for the same
	// reason a redemption does: the chain must account for every supply
	// change or chain_outstanding stops equalling outstanding. Paying a
	// foreign payee destroys credit here exactly as a redemption does.
	//
	// After the commit, and logged rather than failed, matching the
	// redemption path: the credit is already gone, and reporting a failure
	// would have the payer believe it still held the balance.
	if !local {
		if err := s.appendIssuance(EvCreditRetired, auth.Payer, int64(auth.Amount),
			"cross-hub settlement "+id+" to "+auth.PayTo); err != nil {
			log.Printf("hub: cross-hub settlement %s not recorded on the issuance chain: %v",
				id, err)
		}
	}
	return s.signSettlement(payment.SettlementResponse{Success: true, Payer: auth.Payer,
		Transaction: id, Network: auth.Network, Amount: payment.Amount(auth.Amount)}, auth, id)
}

// signSettlement attaches this hub's signed receipt.
//
// Every settlement, not only the cross-hub ones. A payer holding a
// receipt for its own hub's settlement can show what it was charged
// without asking the hub to agree, and that is worth more than the one
// line it costs.
func (s *Store) signSettlement(r payment.SettlementResponse, auth *payment.Authorization,
	authID string) payment.SettlementResponse {
	if s.hubKey == nil {
		return r
	}
	rec := &payment.Receipt{
		AuthID: authID, Payer: auth.Payer, PayTo: auth.PayTo, Amount: auth.Amount,
		Network: auth.Network, SettleAt: time.Now().UnixMilli(),
	}
	if err := rec.Sign(s.hubKey); err != nil {
		return r
	}
	b, err := rec.Marshal()
	if err != nil {
		return r
	}
	if r.Extensions == nil {
		r.Extensions = map[string]any{}
	}
	r.Extensions[payment.ExtReceipt] = base64.StdEncoding.EncodeToString(b)
	return r
}

// SetHubKey gives the store the identity it signs settlements with, and
// the row credit is issued from and redeemed back into.
func (s *Store) SetHubKey(c *identity.Controller) {
	s.hubKey = c
	s.hubAID = c.AID()
}

// ClearFromPeer credits a local payee against a peer hub's signed
// settlement, and records what that peer now owes us.
//
// This is the whole of "two hubs clearing against each other", and the
// trust it introduces is worth naming. We are crediting our own user
// because another hub says it debited theirs. The receipt makes that
// claim attributable — we can show exactly what they told us — but it
// does not make it true: a peer that signs settlements it never performed
// has issued itself credit here. Which is why peers are an allowlist and
// the balance owed is recorded rather than netted away.
func (s *Store) ClearFromPeer(peerAID string, peerKEL []identity.SignedEvent,
	rec *payment.Receipt) error {
	if rec == nil {
		return fmt.Errorf("no settlement receipt")
	}
	if rec.Network != payment.CreditNetwork(peerAID) {
		return fmt.Errorf("receipt is for %s, not %s's ledger", rec.Network, peerAID)
	}
	if err := rec.Verify(peerKEL, peerAID, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("settlement receipt from %s: %w", peerAID, err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// One row per foreign authorization: a peer repeating a receipt must
	// not credit our user twice.
	if _, err := tx.Exec(
		`INSERT INTO credit_cleared(auth_id, peer_aid, pay_to, amount, at) VALUES(?,?,?,?,?)`,
		rec.AuthID, peerAID, rec.PayTo, int64(rec.Amount),
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return nil // already cleared; the same statement, not a new one
	}
	if _, err := tx.Exec(
		`INSERT INTO credit_balance(aid, credits) VALUES(?,?)
		 ON CONFLICT(aid) DO UPDATE SET credits = credits + ?`,
		rec.PayTo, int64(rec.Amount), int64(rec.Amount)); err != nil {
		return err
	}
	// With its ledger entry, for the same reason settlement has one: a
	// payee whose balance rose with nothing in the entries to explain it
	// cannot reconcile its own account.
	if _, err := tx.Exec(
		`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
		rec.PayTo, int64(rec.Amount), rec.AuthID,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	// The hub's own row falls by what it just created, because supply is
	// counted off that row: crediting the payee without it left the ledger
	// showing more credit on accounts than the hub had ever issued.
	if _, err := tx.Exec(
		`INSERT INTO credit_balance(aid, credits) VALUES(?, -?)
		 ON CONFLICT(aid) DO UPDATE SET credits = credits - ?`,
		s.hubKey.AID(), int64(rec.Amount), int64(rec.Amount)); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
		s.hubKey.AID(), -int64(rec.Amount), rec.AuthID,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	// What the peer owes us, kept as a running total rather than netted
	// into anyone's balance: it is a claim on another hub, not credit
	// here, and the two must not be allowed to look alike.
	if _, err := tx.Exec(
		`INSERT INTO hub_owed(peer_aid, amount) VALUES(?,?)
		 ON CONFLICT(peer_aid) DO UPDATE SET amount = amount + ?`,
		peerAID, int64(rec.Amount), int64(rec.Amount)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Credit created here goes on the signed chain.
	//
	// This is issuance: the payee's balance rose on this ledger and no
	// account here fell, because the payer's account is on the peer. It is
	// backed by a claim on that peer rather than by nothing, and the
	// reason names the receipt so an auditor can follow it to the peer's
	// own chain — but it is still new supply here, and a supply change
	// missing from the chain breaks chain_outstanding == outstanding.
	//
	// After the commit and logged rather than failed, matching the
	// redemption path: the credit is already there, and refusing now would
	// tell the payee it had not been paid when it had.
	if err := s.appendIssuance(EvCreditIssued, rec.PayTo, int64(rec.Amount),
		"cleared from "+peerAID+" "+rec.AuthID); err != nil {
		log.Printf("hub: clearing %s from %s not recorded on the issuance chain: %v",
			rec.AuthID, peerAID, err)
	}
	return nil
}

// Due is what this hub owes, by payee: credit that left this ledger to
// pay an agent that banks on a peer.
//
// Reported so an operator can see the obligation before discharging it,
// and so the two hubs' numbers can be compared — this hub's due to a
// payee should match that payee's hub's owed from this hub.
func (s *Store) Due() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT payee_aid, amount FROM hub_due WHERE amount > 0`)
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

// DischargeDue reduces what this hub owes a payee, once the discharge to
// that payee's hub has been signed and accepted.
//
// Separate from signing the statement, because the statement can be
// signed and the peer can still refuse it — reducing the obligation
// before the peer accepted would leave this hub believing it had paid
// something the other hub still shows as owed.
func (s *Store) DischargeDue(payeeAID string, amount int64) error {
	res, err := s.db.Exec(
		`UPDATE hub_due SET amount = amount - ? WHERE payee_aid = ? AND amount >= ?`,
		amount, payeeAID, amount)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("nothing that size is due to %s", payeeAID)
	}
	return nil
}

// Owed reports what a peer hub owes this one.
func (s *Store) Owed(peerAID string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT amount FROM hub_owed WHERE peer_aid=?`, peerAID).Scan(&n)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return 0, nil
	}
	return n, err
}

// decodeAuth pulls the anet-credit authorization out of a payload and
// checks everything that is not a balance.
func (s *Store) decodeAuth(hubAID string, p *payment.PaymentPayload) (*payment.Authorization, error) {
	if p == nil {
		return nil, fmt.Errorf("no payment payload")
	}
	if p.Accepted.Scheme != payment.SchemeCredit {
		return nil, fmt.Errorf("this facilitator settles %q, not %q", payment.SchemeCredit, p.Accepted.Scheme)
	}
	want := payment.CreditNetwork(hubAID)
	if p.Accepted.Network != want {
		// A credit on another hub is not a credit here, and settling one
		// as though it were would mint money. Forwarding it to the hub
		// that owns that ledger is a different matter, and happens above
		// this — see SettlePayment.
		return nil, fmt.Errorf("this facilitator settles %q, not %q", want, p.Accepted.Network)
	}
	raw, _ := p.Payload["authorization"].(string)
	if raw == "" {
		return nil, fmt.Errorf("payload has no authorization")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("authorization not base64: %w", err)
	}
	auth, err := payment.UnmarshalAuthorization(b)
	if err != nil {
		return nil, fmt.Errorf("authorization malformed: %w", err)
	}
	if auth.Network != want {
		return nil, fmt.Errorf("authorization is for %q, not %q", auth.Network, want)
	}
	// The signature is checked against the payer's own registered key
	// history, which is what makes this a payment the payer made rather
	// than one this hub decided they made.
	kelBytes, err := s.AgentKEL(auth.Payer)
	if err != nil {
		return nil, fmt.Errorf("payer %s not registered here", auth.Payer)
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		return nil, err
	}
	if err := auth.Verify(kel, time.Now().UnixMilli()); err != nil {
		return nil, err
	}
	return auth, nil
}

func (s *Store) authSpent(a *payment.Authorization) (bool, error) {
	id, err := a.ID()
	if err != nil {
		return false, err
	}
	var n int
	err = s.db.QueryRow(`SELECT COUNT(1) FROM credit_settled WHERE auth_id=?`, id).Scan(&n)
	return n > 0, err
}

// ---- HTTP: the three endpoints x402 defines for a facilitator ----

// hX402Supported lists every ledger this facilitator will settle on.
//
// Its own, and each peer's it will clear against. The second half is what
// lets an agent priced on this hub be bought by an agent whose credits
// live on a peer: the seller reads this list, offers those networks in
// its 402, and the buyer pays on the ledger it actually holds credit on.
//
// Before this, /x402/supported named only this hub's own network, so a
// seller offered exactly one option and a cross-hub buyer could only be
// told it had insufficient funds. The cross-hub clearing path existed and
// nothing could reach it.
func (s *Server) hX402Supported(w http.ResponseWriter, _ *http.Request) {
	kinds := []payment.SupportedKind{{
		X402Version: payment.Version,
		Scheme:      payment.SchemeCredit,
		Network:     payment.CreditNetwork(s.hubAID),
	}}
	for _, aid := range s.store.ClearablePeers() {
		kinds = append(kinds, payment.SupportedKind{
			X402Version: payment.Version,
			Scheme:      payment.SchemeCredit,
			Network:     payment.CreditNetwork(aid),
		})
	}
	writeJSON(w, http.StatusOK, payment.Supported{Kinds: kinds})
}

func (s *Server) hX402Verify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		X402Version    int                     `json:"x402Version"`
		PaymentPayload *payment.PaymentPayload `json:"paymentPayload"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, payment.VerifyResponse{
			IsValid: false, InvalidReason: "malformed request"})
		return
	}
	writeJSON(w, http.StatusOK, s.store.VerifyPayment(s.hubAID, req.PaymentPayload))
}

func (s *Server) hX402Settle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		X402Version    int                     `json:"x402Version"`
		PaymentPayload *payment.PaymentPayload `json:"paymentPayload"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, payment.SettlementResponse{
			Success: false, ErrorReason: "malformed request"})
		return
	}
	writeJSON(w, http.StatusOK, s.store.SettlePayment(s.hubAID, req.PaymentPayload))
}

// hBalance lets an agent see its own standing. Public, because a balance
// on a ledger somebody else keeps is exactly the thing its owner must be
// able to check without asking permission.
func (s *Server) hBalance(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	n, err := s.store.Balance(aid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, Balance{AID: aid, Credits: n})
}

// ---- how credit gets into the system ----

// RegistrationGrant is what a newly registered agent is given, so it can
// try a paid capability before anyone has funded it.
//
// A network where nothing works until an operator notices you is a
// network nobody evaluates. The number is small on purpose: enough to
// find out whether this is useful, not enough to be worth farming
// identities for — and an identity is free to mint, so the grant must
// never be worth more than the effort of minting one.
const RegistrationGrant = 100

// grantOnRegistration credits a first-time registrant.
//
// First time only, keyed on the agent row rather than a separate flag: an
// agent re-registering is the same agent, and paying out again for a
// changed capability list would make re-registration a faucet.
func (s *Store) GrantOnRegistration(aid string) error {
	var entries int
	if err := s.db.QueryRow(
		`SELECT COUNT(1) FROM credit_entry WHERE aid=? AND reason=?`,
		aid, "registration grant").Scan(&entries); err != nil {
		return err
	}
	if entries > 0 {
		return nil
	}
	return s.Credit(aid, RegistrationGrant, "registration grant")
}

// GrantCredit is the operator's way in. Everything else that creates
// credit on this ledger is either this or the registration grant, which
// is what makes the total supply something an operator can account for.
func (s *Store) GrantCredit(aid string, amount int64, reason string) error {
	if amount <= 0 {
		return fmt.Errorf("a grant must be positive, got %d", amount)
	}
	if reason == "" {
		reason = "operator grant"
	}
	return s.Credit(aid, amount, reason)
}

// LedgerEntries returns an account's movements, newest last.
//
// The point of keeping them is that a balance can be explained rather
// than asserted — by the account holder, without asking the hub to agree
// about anything except what it already published.
func (s *Store) LedgerEntries(aid string, limit int) ([]LedgerEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT delta, reason, at FROM credit_entry WHERE aid=? ORDER BY seq DESC LIMIT ?`, aid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LedgerEntry{}
	for rows.Next() {
		var e LedgerEntry
		if err := rows.Scan(&e.Delta, &e.Reason, &e.At); err != nil {
			return nil, err
		}
		out = append([]LedgerEntry{e}, out...)
	}
	return out, rows.Err()
}

// LedgerEntry is one movement on an account.
type LedgerEntry struct {
	Delta  int64  `json:"delta"`
	Reason string `json:"reason"`
	At     string `json:"at"`
}

// KnowsAgent reports whether an agent has registered here before.
func (s *Store) KnowsAgent(aid string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(1) FROM agent WHERE aid=?`, aid).Scan(&n)
	return n > 0
}

// LedgerTotals is how many entries an account has and what they add up
// to, over the whole account rather than a page.
//
// The sum is what a balance must equal. Computing it in SQL rather than
// by paging keeps a reconciliation to one request no matter how long an
// account has been running.
func (s *Store) LedgerTotals(aid string) (count int, sum int64, err error) {
	err = s.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(delta),0) FROM credit_entry WHERE aid=?`, aid).
		Scan(&count, &sum)
	return count, sum, err
}
