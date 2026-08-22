package aghub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
func (s *Store) Credit(aid string, amount int64, reason string) error {
	if amount == 0 {
		return nil
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
		return payment.SettlementResponse{Success: true, Payer: auth.Payer, Transaction: id,
			Network: auth.Network, Amount: payment.Amount(auth.Amount),
			Extensions: map[string]any{"anet.replayed": true}}
	}

	var bal int64
	if err := tx.QueryRow(`SELECT COALESCE(credits,0) FROM credit_balance WHERE aid=?`,
		auth.Payer).Scan(&bal); err != nil && err.Error() != "sql: no rows in result set" {
		return fail(err.Error())
	}
	if bal < int64(auth.Amount) {
		return fail(fmt.Sprintf("insufficient balance: has %d, needs %d", bal, auth.Amount))
	}
	if _, err := tx.Exec(
		`INSERT INTO credit_balance(aid, credits) VALUES(?, -?)
		 ON CONFLICT(aid) DO UPDATE SET credits = credits - ?`,
		auth.Payer, int64(auth.Amount), int64(auth.Amount)); err != nil {
		return fail(err.Error())
	}
	if _, err := tx.Exec(
		`INSERT INTO credit_balance(aid, credits) VALUES(?,?)
		 ON CONFLICT(aid) DO UPDATE SET credits = credits + ?`,
		auth.PayTo, int64(auth.Amount), int64(auth.Amount)); err != nil {
		return fail(err.Error())
	}
	if err := tx.Commit(); err != nil {
		return fail(err.Error())
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

// SetHubKey gives the store the identity it signs settlements with.
func (s *Store) SetHubKey(c *identity.Controller) { s.hubKey = c }

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
	// What the peer owes us, kept as a running total rather than netted
	// into anyone's balance: it is a claim on another hub, not credit
	// here, and the two must not be allowed to look alike.
	if _, err := tx.Exec(
		`INSERT INTO hub_owed(peer_aid, amount) VALUES(?,?)
		 ON CONFLICT(peer_aid) DO UPDATE SET amount = amount + ?`,
		peerAID, int64(rec.Amount), int64(rec.Amount)); err != nil {
		return err
	}
	return tx.Commit()
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

func (s *Server) hX402Supported(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, payment.Supported{Kinds: []payment.SupportedKind{{
		X402Version: payment.Version,
		Scheme:      payment.SchemeCredit,
		Network:     payment.CreditNetwork(s.hubAID),
	}}})
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
