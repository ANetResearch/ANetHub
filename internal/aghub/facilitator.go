package aghub

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
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
	// ProbationUntil (unix ms) and Trial (pending or granted) are there
	// only for an account that came in through a sign-up window or open
	// registration (hub-payment-privacy §2.2): when its probation ends, and
	// where its 20 trial credits stand.
	ProbationUntil *uint64 `json:"probation_until,omitempty"`
	Trial          string  `json:"trial,omitempty"`
}

// Credit adds to an agent's balance — how a hub operator funds an
// account, however they decide accounts get funded.
//
// The matching debit goes on the hub's own row. Credit does not appear
// from nowhere: it is issued, and the issuer carries the liability. That
// is what makes the supply countable instead of asserted — the rows across
// the whole ledger sum to zero, so "what this hub owes its users" is the
// negative of the hub's row, and the sum of a supply epoch's tree.
//
// One transaction: the hub row and its entry, the supply totals, the
// balance and the account's entry are written together or not at all.
func (s *Store) Credit(aid string, amount int64, reason string) error {
	if amount == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.creditTx(tx, aid, amount, reason); err != nil {
		return err
	}
	return tx.Commit()
}

// creditTx is Credit inside tx. It does not check that the issuance fits
// the supply's bound; issueTx does.
//
// Credit to an agent is a supply event (hub-payment-privacy PAY-S1): the
// hub's own row falls by it, with its ledger entry, and the issued total
// grows, in this transaction. A store with no hub identity (some tests)
// moves the balance alone.
func (s *Store) creditTx(tx *sql.Tx, aid string, amount int64, reason string) error {
	if amount == 0 {
		return nil
	}
	at := ledgerStamp(s.now())
	if s.hubAID != "" && aid != s.hubAID {
		if amount < 0 {
			return fmt.Errorf("an issuance must be positive, got %d", amount)
		}
		if err := addToRow(tx, "credit_balance", "aid", "credits", s.hubAID, -amount); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
			s.hubAID, -amount, reasonIssued+":"+reason, at); err != nil {
			return err
		}
		if err := s.supplyEventTx(tx, supplyIssued, amount); err != nil {
			return err
		}
	}
	if err := addToRow(tx, "credit_balance", "aid", "credits", aid, amount); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
		aid, amount, reason, at)
	return err
}

// issueTx creates amount credits for aid inside tx: a supply event (an
// operator's grant, an admission grant, a trial credit). It is refused when
// it would take what this hub has issued past what its supply can add up to
// (issuanceRoom); the transaction is the serialisation, so concurrent
// issuance cannot pass the check together.
func (s *Store) issueTx(tx *sql.Tx, aid string, amount int64, reason string) error {
	if amount <= 0 {
		return fmt.Errorf("an issuance must be positive, got %d", amount)
	}
	if s.hubAID != "" && aid != s.hubAID {
		if err := issuanceRoom(tx, amount); err != nil {
			return err
		}
	}
	return s.creditTx(tx, aid, amount, reason)
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

// ---- settlement: the x402 facilitator ----

// Refusal is a facilitator's answer that a payment will not settle: an
// x402 errorReason and the detail behind it.
//
// Reason is always exactly one of the payment.Reason* constants. It is
// what a client branches on and what the daemon maps to an a2a-x402
// x402.payment.error code (A2A-DESIGN §8.5), and that mapping is a lookup
// on the exact string, so the prose goes in Detail and travels in the
// response's extensions under payment.ExtErrorDetail.
type Refusal struct {
	Reason string
	Detail string
}

func (r *Refusal) Error() string {
	if r.Detail == "" {
		return r.Reason
	}
	return r.Reason + ": " + r.Detail
}

func refuse(reason, format string, args ...any) *Refusal {
	return &Refusal{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// refusedSettlement is the SettlementResponse for a refusal.
//
// Payer, Amount and Transaction are filled from the authorization when it
// could be read, so a caller can tie the refusal to what it sent.
// Transaction is then the refused authorization's id; on a
// duplicate_binding refusal the settlement that holds the binding is in
// the extensions under payment.ExtOriginalTransaction.
func refusedSettlement(rf *Refusal, auth *payment.Authorization, network string) payment.SettlementResponse {
	out := payment.SettlementResponse{Success: false, ErrorReason: rf.Reason, Network: network,
		Extensions: map[string]any{}}
	if auth != nil {
		out.Payer = auth.Payer
		out.Amount = payment.Amount(auth.Amount)
		if id, err := auth.ID(); err == nil {
			out.Transaction = id
		}
	}
	if rf.Detail != "" {
		out.Extensions[payment.ExtErrorDetail] = rf.Detail
	}
	return out
}

// CheckRequirements compares a payment with the terms the resource server
// requires: payee, amount, network and scheme.
//
// Both halves of the payload are compared. The authorization is what the
// payer signed and what this hub settles; the accepted option is the
// payer's unsigned statement of which offer it took. The gateway used to
// check only the accepted option and settle the authorization, so a buyer
// could state the full price to the seller while signing a smaller amount
// to somebody else, and receive a full voucher (R06 D2). Here the
// authorization must meet the requirements, and the accepted option must
// state the authorization's own payee and amount.
//
// It verifies no signature and needs no KEL. That is what lets an entry
// hub run it on a payment whose ledger, and whose payer's key history,
// are on another hub, before forwarding it: a payment this hub would
// refuse is not sent anywhere. The ledger hub runs it again after it has
// verified the signature.
//
// The authorized amount may exceed the required amount; it may not fall
// short of it.
func CheckRequirements(p *payment.PaymentPayload, auth *payment.Authorization,
	req *payment.PaymentRequirements) *Refusal {
	if req == nil {
		return refuse(payment.ReasonInvalidRequirements, "paymentRequirements is required")
	}
	want, err := payment.ParseAmount(req.Amount)
	if err != nil {
		return refuse(payment.ReasonInvalidRequirements, "required amount: %v", err)
	}
	// A price this ledger cannot hold is not a price: an authorization
	// meeting it would be refused below anyway, and a requirement of 0 is
	// met by any amount at all. See amountInt64.
	if _, ok := amountInt64(want); !ok {
		return refuse(payment.ReasonInvalidRequirements,
			"required amount %d is outside 1..%d, the range this ledger can hold", want, int64(math.MaxInt64))
	}
	if req.PayTo == "" || req.Network == "" {
		return refuse(payment.ReasonInvalidRequirements, "the requirements name no payee or no network")
	}
	if p == nil || auth == nil {
		return refuse(payment.ReasonMalformed, "no payment")
	}
	// parseAuth refuses it first; this function is also called on an
	// authorization decoded elsewhere, and "at least want" must not be
	// read off an amount that is negative on the ledger.
	if _, ok := amountInt64(auth.Amount); !ok {
		return amountRefusal("authorization", auth.Amount)
	}
	if req.Scheme != payment.SchemeCredit {
		return refuse(payment.ReasonUnsupportedScheme,
			"this facilitator settles %q; the requirements name %q", payment.SchemeCredit, req.Scheme)
	}
	if p.Accepted.Scheme != req.Scheme {
		return refuse(payment.ReasonUnsupportedScheme,
			"the payment is on scheme %q; the requirements name %q", p.Accepted.Scheme, req.Scheme)
	}
	if p.Accepted.Network != req.Network {
		return refuse(payment.ReasonNetworkMismatch,
			"the payment is offered on %s; the requirements name %s", p.Accepted.Network, req.Network)
	}
	if auth.Network != req.Network {
		return refuse(payment.ReasonNetworkMismatch,
			"the authorization is for %s; the requirements name %s", auth.Network, req.Network)
	}
	if auth.PayTo != req.PayTo {
		return refuse(payment.ReasonPayeeMismatch,
			"the authorization pays %s; the requirements name %s", auth.PayTo, req.PayTo)
	}
	if p.Accepted.PayTo != auth.PayTo {
		return refuse(payment.ReasonPayeeMismatch,
			"the payload states payee %s; the authorization pays %s", p.Accepted.PayTo, auth.PayTo)
	}
	accepted, err := payment.ParseAmount(p.Accepted.Amount)
	if err != nil || accepted != auth.Amount {
		return refuse(payment.ReasonInvalidAmount,
			"the payload states amount %q; the authorization pays %d", p.Accepted.Amount, auth.Amount)
	}
	if auth.Amount < want {
		return refuse(payment.ReasonInvalidAmount,
			"the authorization pays %d; the requirements ask for %d", auth.Amount, want)
	}
	return nil
}

// parseAuth reads the anet-credit authorization out of a payload. It
// checks that there is one to read, and that its amount is one this
// ledger can hold (amountInt64).
//
// Every door onto a settlement comes through here: /x402/verify and
// /x402/settle (own ledger and forwarded), /fed/v3/settle and /x402/redeem.
// An amount above math.MaxInt64 is refused before its signature is even
// looked at, so no path below can book it as the negative number a bare
// int64(…) would make of it; so is an authorization valid for longer than
// payment.MaxAuthWindow (authWindow), which comes back with the refusal so
// the answer can name its payer and id.
func parseAuth(p *payment.PaymentPayload) (*payment.Authorization, *Refusal) {
	if p == nil {
		return nil, refuse(payment.ReasonMalformed, "no payment payload")
	}
	raw, _ := p.Payload["authorization"].(string)
	if raw == "" {
		return nil, refuse(payment.ReasonMalformed, "payload has no authorization")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, refuse(payment.ReasonMalformed, "authorization not base64: %v", err)
	}
	auth, err := payment.UnmarshalAuthorization(b)
	if err != nil {
		return nil, refuse(payment.ReasonMalformed, "authorization malformed: %v", err)
	}
	if _, ok := amountInt64(auth.Amount); !ok {
		return nil, amountRefusal("authorization", auth.Amount)
	}
	if rf := authWindow(auth); rf != nil {
		return auth, rf
	}
	return auth, nil
}

// maxAuthWindowMillis is payment.MaxAuthWindow in unix milliseconds.
const maxAuthWindowMillis = uint64(payment.MaxAuthWindow / time.Millisecond)

// authWindow refuses an authorization valid for longer than
// payment.MaxAuthWindow, 24 hours (auth_window_too_long, hub-payment-privacy
// PAY-L3). One that lives longer is a standing bearer instrument, and what
// keeps a settled one from settling again holds only for one that expires
// soon: its settled row is kept 7 days past NotAfter, its binding 30 days.
// A daemon signs its own for five minutes.
//
// The difference is taken once the order of the two times is known, so a
// NotAfter near math.MaxInt64 cannot overflow it; a NotAfter not after
// IssuedAt is no window at all, which Verify refuses (expired_payment).
func authWindow(a *payment.Authorization) *Refusal {
	if a.NotAfter > a.IssuedAt && uint64(a.NotAfter)-uint64(a.IssuedAt) > maxAuthWindowMillis {
		return refuse(payment.ReasonAuthWindowTooLong,
			"the authorization is valid for %d ms, longer than the %d ms a hub accepts; nothing was charged",
			uint64(a.NotAfter)-uint64(a.IssuedAt), maxAuthWindowMillis)
	}
	return nil
}

// verifiedAuth decodes a payment on this hub's own ledger and checks the
// payer's signature against the payer's registered key history.
//
// The signature is checked at the authorization's own time, IssuedAt, and
// the validity window is not checked here. The split is what lets a
// settlement already made be answered with its original receipt after the
// window has closed (SettleWithRequirements): for a repeat, the question is
// whether the payer signed these bytes, not whether they could still be
// spent. A new settlement additionally passes currentAuth.
//
// The authorization is returned with a refusal when it could be decoded,
// so the response can name its payer and id.
func (s *Store) verifiedAuth(hubAID string, p *payment.PaymentPayload) (
	*payment.Authorization, string, []identity.SignedEvent, *Refusal) {
	if p == nil {
		return nil, "", nil, refuse(payment.ReasonMalformed, "no payment payload")
	}
	if p.Accepted.Scheme != payment.SchemeCredit {
		return nil, "", nil, refuse(payment.ReasonUnsupportedScheme,
			"this facilitator settles %q, not %q", payment.SchemeCredit, p.Accepted.Scheme)
	}
	want := payment.CreditNetwork(hubAID)
	if p.Accepted.Network != want {
		// A credit on another hub is not a credit here, and settling one
		// as though it were would mint money. Forwarding it to the hub
		// that owns that ledger is a different matter, and happens before
		// this — see SettleWithRequirements.
		return nil, "", nil, refuse(payment.ReasonNetworkMismatch,
			"this facilitator settles %q, not %q", want, p.Accepted.Network)
	}
	auth, rf := parseAuth(p)
	if rf != nil {
		return auth, "", nil, rf
	}
	if auth.Network != want {
		return auth, "", nil, refuse(payment.ReasonNetworkMismatch,
			"authorization is for %q, not %q", auth.Network, want)
	}
	id, err := auth.ID()
	if err != nil {
		return auth, "", nil, refuse(payment.ReasonMalformed, "authorization id: %v", err)
	}
	// The signature is checked against the payer's own registered key
	// history, which is what makes this a payment the payer made rather
	// than one this hub decided they made.
	kelBytes, err := s.AgentKEL(auth.Payer)
	if err != nil {
		return auth, id, nil, refuse(payment.ReasonUnknownPayer, "payer %s not registered here", auth.Payer)
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		return auth, id, nil, refuse(payment.ReasonSettlementFailed,
			"the payer's stored key history is unreadable: %v", err)
	}
	// /x402/verify and /x402/settle need no authentication, so a bad
	// signature is refused on the key the KEL names, before auth.Verify
	// replays the payer's KEL (kelreplay.go) [redteam:F36]. Only where
	// auth.Verify would reach the signature: its other refusals come first
	// and cost nothing.
	if auth.IssuedAt > 0 && auth.NotAfter > auth.IssuedAt {
		if verr := plausibleEnvelope(auth.Envelope, auth.Payer, kel, auth.CanonicalPreimage); verr != nil {
			return auth, id, nil, refuse(verifyReason(verr), "%v", verr)
		}
	}
	if err := auth.Verify(kel, auth.IssuedAt); err != nil {
		return auth, id, nil, refuse(verifyReason(err), "%v", err)
	}
	return auth, id, kel, nil
}

// currentAuth is what a new settlement needs beyond verifiedAuth when the
// authorization has no first verification at its key's tip (keyAtFirstVerify):
// the validity window, and the signing key being valid now and not only at
// IssuedAt. Checking the key at IssuedAt alone would let a key the payer
// has rotated away sign a spendable authorization by backdating it.
func currentAuth(auth *payment.Authorization, kel []identity.SignedEvent, now int64) *Refusal {
	if err := auth.Verify(kel, now); err != nil {
		return refuse(verifyReason(err), "%v", err)
	}
	return nil
}

// The payer's key is judged as of this hub's first verification of the
// authorization (KEL H-40 to H-42).
//
// A payer that rotates its key while a payment it signed is between the
// merchant's /x402/verify and /x402/settle must not have that payment
// refused: it was signed by the key that was current, and this hub said so.
// So the ledger hub records, the first time it verifies an authorization
// whole (signature, validity window and terms), whether the key that signed
// it was then the tip of the payer's key history held here, and active
// (x402_first_verify). Later, while the record is kept, an authorization
// recorded so is judged against the key history as it stood then: its window
// at now, its signature under that key state. One recorded otherwise, or not
// recorded, needs the key to be current now (currentAuth), and a retired key
// signing a backdated authorization is refused as before (INVALID_SIGNATURE).
// Planned and emergency rotations are alike (H-42). The record is kept until
// 7 days after the authorization's NotAfter, like its settlement (janitor.go).
//
// Only the ledger hub verifies a payer's signature and records; an entry hub
// forwarding a payment to the payer's hub does neither.

// firstVerifySchema is the record of first verifications (KEL S-3, core
// §2.16): one row per authorization id; payer and key_state_seq are the
// payer and the key state that signed it, tip_at_first whether that state was
// the active tip then (1) or not (0); times in unix ms. It goes into backups
// with the ledger window's tables.
func firstVerifySchema() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS x402_first_verify (
		   auth_id TEXT PRIMARY KEY,
		   payer TEXT NOT NULL,
		   key_state_seq INTEGER NOT NULL,
		   tip_at_first INTEGER NOT NULL,
		   first_verified_at INTEGER NOT NULL,
		   delete_after INTEGER NOT NULL
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_first_verify_delete ON x402_first_verify(delete_after)`,
	}
}

// keyAtFirstVerify is the check of an authorization's validity window and
// signing key at now, for an authorization verifiedAuth accepted (signed by
// its payer, under a key state of kel, at IssuedAt) whose terms the caller
// has compared. First the window, at now, with the signature under the key
// state that signed as if it were the tip; then, the authorization being
// verified whole, its first verification is recorded (recordFirstVerify);
// then, unless that record says the key was the active tip, the key must be
// current now (currentAuth).
func (s *Store) keyAtFirstVerify(auth *payment.Authorization, id string, kel []identity.SignedEvent, now int64) *Refusal {
	seq := auth.Envelope.KeyStateSeq
	if seq >= uint64(len(kel)) {
		return currentAuth(auth, kel, now)
	}
	if err := auth.Verify(kel[:seq+1], now); err != nil {
		return refuse(verifyReason(err), "%v", err)
	}
	tip, err := s.recordFirstVerify(auth, id, now)
	if err != nil {
		return refuse(payment.ReasonSettlementFailed, "recording the first verification: %v", err)
	}
	if tip {
		return nil
	}
	return currentAuth(auth, kel, now)
}

// recordFirstVerify records this hub's first whole verification of the
// authorization id at now, unless one is recorded, and reports whether the
// recorded one found the key state that signed it to be the active tip of
// the payer's key history (H-40). The key history is read in the transaction
// that writes the record, so a rotation this hub takes concurrently is
// either before the record or after it, never between.
func (s *Store) recordFirstVerify(auth *payment.Authorization, id string, now int64) (bool, error) {
	seq := auth.Envelope.KeyStateSeq
	// Recorded already, as for a settlement after the merchant's verify: read
	// without the write lock a transaction here takes.
	if tip, found, err := firstVerifyOf(s.db, id, auth.Payer, seq); err != nil || found {
		return tip, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if tip, found, err := firstVerifyOf(tx, id, auth.Payer, seq); err != nil || found {
		return tip, err
	}
	var raw []byte
	if err := tx.QueryRow(`SELECT kel FROM agent WHERE aid = ?`, auth.Payer).Scan(&raw); err != nil {
		return false, err
	}
	kel, err := identity.UnmarshalKEL(raw)
	if err != nil {
		return false, err
	}
	states, err := identity.Replay(kel)
	if err != nil {
		return false, err
	}
	last := states[len(states)-1]
	tip := last.KeyStateSeq == seq && last.Status == identity.StatusActive
	if seq > math.MaxInt64 {
		return false, fmt.Errorf("key state %d is beyond what this hub stores", seq)
	}
	if _, err := tx.Exec(`INSERT INTO x402_first_verify(auth_id, payer, key_state_seq, tip_at_first, first_verified_at, delete_after)
	    VALUES(?,?,?,?,?,?)`, id, auth.Payer, int64(seq), tip, now, firstVerifyDeleteAfter(auth.NotAfter)); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return tip, nil
}

// firstVerifyOf reads the first verification recorded for the authorization
// id, through q: found when there is one, and tip when it says the key state
// that signed was the active tip. A record speaks only for the payer and the
// key state it was made for: the id covers the terms, not the signature.
func firstVerifyOf(q rowQuerier, id, payer string, seq uint64) (tip, found bool, err error) {
	var rowPayer string
	var rowSeq int64
	var rowTip bool
	err = q.QueryRow(`SELECT payer, key_state_seq, tip_at_first FROM x402_first_verify WHERE auth_id = ?`, id).
		Scan(&rowPayer, &rowSeq, &rowTip)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return rowTip && rowPayer == payer && rowSeq >= 0 && uint64(rowSeq) == seq, true, nil
}

// firstVerifyDeleteAfter is when a first verification of an authorization
// valid until notAfter is deleted: settledKeptAfter later, as its
// settlement's row is, without overflowing int64.
func firstVerifyDeleteAfter(notAfter int64) int64 {
	keep := settledKeptAfter.Milliseconds()
	if notAfter > math.MaxInt64-keep {
		return math.MaxInt64
	}
	return notAfter + keep
}

// verifyReason classifies a payment.Authorization.Verify failure.
func verifyReason(err error) string {
	if errors.Is(err, payment.ErrExpired) || errors.Is(err, payment.ErrBadWindow) {
		return payment.ReasonExpiredPayment
	}
	return payment.ReasonInvalidSignature
}

// PeerSettler forwards a settlement to the hub that owns the ledger and
// clears the result locally. Wired by the application, so this package
// keeps knowing nothing about federation.
//
// auth is decoded from p but not verified: its signature is the ledger
// hub's to check. handled is false when network is not a ledger this hub
// clears against; the payment is then refused here with network_mismatch.
type PeerSettler func(network string, p *payment.PaymentPayload, req *payment.PaymentRequirements,
	auth *payment.Authorization) (out payment.SettlementResponse, handled bool)

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

// SettleWithRequirements moves the credit, once, if the payment meets the
// requirements. /x402/settle calls it.
//
// The payee must be an account of this hub (hub-payment-privacy PAY-L4,
// payee_not_local). A payment to an agent that banks on a peer is settled
// through that agent's hub, which forwards it signed (/fed/v3/settle,
// SettleForPeer): settled here on an unauthenticated request, it let anyone
// move a payer's credit off this ledger and make this hub owe whichever hub
// they named. Refused, nothing is charged and nothing is forwarded.
//
// On this hub's own ledger the order is: decode and verify the payer's
// signature; compare with the requirements; answer an authorization
// already settled with its original receipt; check the validity window;
// settle. The repeat is answered before the window check, so a charged
// authorization yields its receipt at any time — a merchant whose settle
// call timed out retries until it learns the outcome (A2A-DESIGN §8.3) —
// and after the requirements check, so the receipt is returned only to a
// caller asking on the terms it was settled for. "Any time" ends when the
// settled row is deleted, 7 days after the authorization's NotAfter
// (janitor.go); a repeat after that is expired and moves nothing.
//
// On a peer's ledger this hub is the entry hub. It compares the payment
// with the requirements, then forwards payload and requirements to the
// ledger hub, which verifies and compares again. A payment this hub would
// refuse is not forwarded.
func (s *Store) SettleWithRequirements(hubAID string, p *payment.PaymentPayload,
	req *payment.PaymentRequirements) payment.SettlementResponse {
	own := payment.CreditNetwork(hubAID)
	if req == nil {
		return refusedSettlement(refuse(payment.ReasonInvalidRequirements,
			"paymentRequirements is required"), nil, own)
	}
	if p == nil {
		return refusedSettlement(refuse(payment.ReasonMalformed, "no payment payload"), nil, own)
	}
	if rf := payeeIsThisHub(hubAID, req); rf != nil {
		return refusedSettlement(rf, nil, own)
	}
	if rf := s.payeeHere(req.PayTo); rf != nil {
		return refusedSettlement(rf, nil, own)
	}
	// A payment on another hub's ledger is that hub's to settle. We ask
	// it, and if it says yes we credit our own payee and record what that
	// hub now owes us — the two hubs clearing against each other rather
	// than one of them minting.
	if p.Accepted.Network != own && s.peerSettle != nil {
		auth, rf := parseAuth(p)
		if rf != nil {
			return refusedSettlement(rf, auth, p.Accepted.Network)
		}
		if rf := CheckRequirements(p, auth, req); rf != nil {
			return refusedSettlement(rf, auth, p.Accepted.Network)
		}
		if out, handled := s.peerSettle(p.Accepted.Network, p, req, auth); handled {
			return out
		}
	}
	auth, id, kel, rf := s.verifiedAuth(hubAID, p)
	if rf != nil {
		return refusedSettlement(rf, auth, own)
	}
	if rf := CheckRequirements(p, auth, req); rf != nil {
		return refusedSettlement(rf, auth, own)
	}
	if out, done := s.repeatOf(hubAID, id, auth, ""); done {
		return out
	}
	if rf := s.keyAtFirstVerify(auth, id, kel, s.now().UnixMilli()); rf != nil {
		return refusedSettlement(rf, auth, own)
	}
	return s.settleAuth(hubAID, auth, id, "")
}

// SettleForPeer settles, on this hub's own ledger, a payment the peer hub
// peerAID forwarded for a payee that banks on that peer: POST /fed/v3/settle,
// whose signature federation verified (core G3; hub-payment-privacy PAY-L4,
// PAY-L5). It is the one way this hub settles for a payee that is not its
// account. The payer is charged, the credit leaves this ledger (a supply
// event), and this hub owes the hub that signed the request what left:
// hub_due[peerAID], which anet-hub clear discharges.
//
// The payee must be neither an account of this hub (payee_mismatch: a
// payment to it is settled here, at /x402/settle), nor this hub, nor the
// forwarding hub itself: a payment to a hub is a redemption on that hub's
// own ledger, and the forwarding hub would not clear a receipt naming it
// (ClearFromPeer). A repeat is answered with the original receipt to the
// peer it was settled for, and refused to any other (duplicate_nonce), so a
// payee registered on two hubs is not credited on both for one payment.
//
// The answer is always a SettlementResponse; the route answers it with 200
// (core G3).
func (s *Store) SettleForPeer(hubAID, peerAID string, p *payment.PaymentPayload,
	req *payment.PaymentRequirements) payment.SettlementResponse {
	own := payment.CreditNetwork(hubAID)
	if req == nil {
		return refusedSettlement(refuse(payment.ReasonInvalidRequirements,
			"paymentRequirements is required"), nil, own)
	}
	if p == nil {
		return refusedSettlement(refuse(payment.ReasonMalformed, "no payment payload"), nil, own)
	}
	if rf := payeeIsThisHub(hubAID, req); rf != nil {
		return refusedSettlement(rf, nil, own)
	}
	if req.PayTo == peerAID {
		return refusedSettlement(refuse(payment.ReasonPayeeMismatch,
			"the requirements name the forwarding hub (%s) as the payee; a payment to a hub is a redemption on that hub's own ledger",
			peerAID), nil, own)
	}
	if here, err := s.registered(s.db, req.PayTo); err != nil {
		return refusedSettlement(refuse(payment.ReasonSettlementFailed, "%v", err), nil, own)
	} else if here {
		return refusedSettlement(refuse(payment.ReasonPayeeMismatch,
			"%s is an account of this hub; a payment to it is settled here, at /x402/settle, not forwarded", req.PayTo),
			nil, own)
	}
	auth, id, kel, rf := s.verifiedAuth(hubAID, p)
	if rf != nil {
		return refusedSettlement(rf, auth, own)
	}
	if rf := CheckRequirements(p, auth, req); rf != nil {
		return refusedSettlement(rf, auth, own)
	}
	if out, done := s.repeatOf(hubAID, id, auth, peerAID); done {
		return out
	}
	if rf := s.keyAtFirstVerify(auth, id, kel, s.now().UnixMilli()); rf != nil {
		return refusedSettlement(rf, auth, own)
	}
	return s.settleAuth(hubAID, auth, id, peerAID)
}

// payeeIsThisHub refuses requirements that name this hub as the payee.
//
// A payment to the hub is a redemption, and /x402/redeem is the one path
// that books it as one: it records the redemption with its reference.
// Settled through /x402/settle the same authorization moved the credit to
// the hub's row without that record, and before supply epochs it also left
// the published supply disagreeing with the signed issuance record (found
// by FuzzHubX402Facilitator, ANet an internal note). On a peer's ledger the
// same payment comes back as a peer receipt naming this hub, which
// ClearFromPeer refuses for the same reason, so it is not forwarded either.
func payeeIsThisHub(hubAID string, req *payment.PaymentRequirements) *Refusal {
	if hubAID != "" && req.PayTo == hubAID {
		return refuse(payment.ReasonPayeeMismatch,
			"the requirements name this hub (%s) as the payee; a payment to the hub is a redemption, made at /x402/redeem",
			hubAID)
	}
	return nil
}

// payeeHere refuses a payee that is not a registered account of this hub
// (payee_not_local, PAY-L4). It is checked before the payment is decoded:
// whatever the payment says, this hub does not settle it.
func (s *Store) payeeHere(payTo string) *Refusal {
	here, err := s.registered(s.db, payTo)
	if err != nil {
		return refuse(payment.ReasonSettlementFailed, "%v", err)
	}
	if !here {
		return refuse(payment.ReasonPayeeNotLocal,
			"%s is not an account of this hub; a payment to an agent on another hub is settled through that agent's hub, and nothing was charged",
			payTo)
	}
	return nil
}

// registered reports whether aid is a registered agent of this hub, read
// through q (the database, or the settlement's transaction).
func (s *Store) registered(q rowQuerier, aid string) (bool, error) {
	var n int
	if err := q.QueryRow(`SELECT COUNT(1) FROM agent WHERE aid=?`, aid).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// repeatOf answers an authorization this hub already settled: with the
// original success and receipt when it was settled for the same caller
// (via: "" for /x402/settle and /x402/redeem, the peer hub for
// /fed/v3/settle), and with duplicate_nonce when it was settled for another.
// done is false when the authorization has not been settled here.
func (s *Store) repeatOf(hubAID, id string, auth *payment.Authorization, via string) (out payment.SettlementResponse, done bool) {
	prior, settledVia, settled, err := s.settledBefore(hubAID, id)
	switch {
	case err != nil:
		return refusedSettlement(refuse(payment.ReasonSettlementFailed, "%v", err), auth, payment.CreditNetwork(hubAID)), true
	case !settled:
		return payment.SettlementResponse{}, false
	case settledVia != via:
		return refusedSettlement(refuse(payment.ReasonDuplicateNonce,
			"this authorization was already settled, for another hub's payee; it moved nothing this time"),
			auth, payment.CreditNetwork(hubAID)), true
	}
	return prior, true
}

// settleAuth moves the credit for an authorization whose caller has
// already done the checks: the signature and the window, and the terms.
// SettleWithRequirements and SettleForPeer check the terms against the
// requirements; Redeem checks its one term, that the payee is this hub,
// itself, because requirements built from the authorization's own amount
// would compare the authorization with itself.
//
// via is the peer hub a forwarded settlement is for (SettleForPeer), or "".
// With "" the payee must be an account of this hub or the hub itself
// (payee_not_local); with a peer it must be neither (payee_mismatch), and
// what left this ledger is owed to that peer (hub_due). Both are checked
// again here, in the transaction that moves the credit.
//
// Idempotent on the authorization's content id: a settle call repeated
// because a reply was lost must not charge twice, and the id derives from
// the signed bytes so a payer cannot make two different authorizations
// look like one.
//
// At most one authorization per payer and task settles, when the
// InteractionID (the task's pay_bind, A2A-DESIGN X4) is not empty: a second
// one — signed because the first one's outcome was lost, or because a payer
// is paying twice — is refused with duplicate_binding and moves nothing, for
// 30 days after the first (PAY-L3). The guard holds
// evidence.SettleGuard(payer, pay_bind) and nothing else (core L33), so it
// does not keep who paid for what. Resending the first authorization is a
// repeat, not a second one, and is answered with its receipt.
func (s *Store) settleAuth(hubAID string, auth *payment.Authorization, id, via string) payment.SettlementResponse {
	network := auth.Network
	fail := func(rf *Refusal) payment.SettlementResponse { return refusedSettlement(rf, auth, network) }
	// parseAuth already refused it; this is the conversion itself, kept
	// behind the same check so no statement below can book a negative
	// amount even if a caller skipped parseAuth.
	amt, ok := amountInt64(auth.Amount)
	if !ok {
		return fail(amountRefusal("authorization", auth.Amount))
	}
	// The binding key, before anything is written: a payer or a pay_bind
	// with U+0000 in it could move the boundary of the hash input
	// (core CORE-E9), and is refused.
	var guard []byte
	if auth.InteractionID != "" {
		g, err := settleGuardKey(auth.Payer, auth.InteractionID)
		if err != nil {
			return fail(refuse(payment.ReasonMalformed, "the authorization's payer or interaction id: %v", err))
		}
		guard = g
	}
	now := s.now().UTC()
	at := ledgerStamp(now)
	// Signed before the commit and stored with the row, so a repeat is
	// answered with these exact bytes.
	rec, err := s.signReceipt(id, auth.Payer, auth.PayTo, auth.Amount, network, now.UnixMilli())
	if err != nil {
		return fail(refuse(payment.ReasonSettlementFailed, "signing the receipt: %v", err))
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fail(refuse(payment.ReasonSettlementFailed, "%v", err))
	}
	// A failure below rolls the whole settlement back, the settled row
	// and its binding included, so retrying after a real failure (an
	// insufficient balance topped up since) is not refused as a duplicate.
	defer tx.Rollback()

	// The settled table is the idempotency key and the replay guard: one
	// row per authorization id, inserted first, so a concurrent second
	// settle loses on the primary key rather than on a check it raced.
	if _, err := tx.Exec(
		`INSERT INTO credit_settled(auth_id, payer, pay_to, amount, at, receipt, not_after, guard_h, via)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		id, auth.Payer, auth.PayTo, amt, at, rec, auth.NotAfter, guard, via); err != nil {
		_ = tx.Rollback()
		return s.settleConflict(hubAID, auth, id, via, err)
	}
	// The binding, in the same transaction. A guard whose 30 days are over
	// and that the janitor has not deleted yet is taken over; a live one
	// is not, and nothing moves.
	if guard != nil {
		res, err := tx.Exec(
			`INSERT INTO settle_guard(h, until) VALUES(?,?)
			 ON CONFLICT(h) DO UPDATE SET until = excluded.until WHERE settle_guard.until <= ?`,
			guard, now.Add(guardKept).UnixMilli(), now.UnixMilli())
		if err != nil {
			return fail(refuse(payment.ReasonSettlementFailed, "%v", err))
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			_ = tx.Rollback()
			return s.bindingRefusal(auth, guard)
		}
	}

	var bal int64
	if err := tx.QueryRow(`SELECT COALESCE(credits,0) FROM credit_balance WHERE aid=?`,
		auth.Payer).Scan(&bal); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fail(refuse(payment.ReasonSettlementFailed, "%v", err))
	}
	if bal < amt {
		return fail(refuse(payment.ReasonInsufficientFunds, "has %d, needs %d", bal, auth.Amount))
	}
	// Every balance below moves through addToRow, which refuses a sum
	// the column cannot hold rather than letting SQLite store it as a
	// REAL; a refusal rolls the settlement back like any other failure.
	moved := func(err error) *Refusal {
		var rf *Refusal
		if errors.As(err, &rf) {
			return rf
		}
		return refuse(payment.ReasonSettlementFailed, "%v", err)
	}
	// Whether the payee banks here decides where the credit goes.
	//
	// An account this hub keeps — a registered agent, or the hub itself —
	// is credited, and the two rows net to zero: credit moved between two
	// accounts on one ledger and the supply did not change. The hub is the
	// payee of every redemption (a payment to the hub), and holds the
	// supply row rather than an agent registration.
	//
	// A payee that banks on the peer the settlement was forwarded for is
	// not credited here: its own hub credits it, on this hub's receipt.
	// Crediting it here too made one payment two credits, one on each
	// ledger. This hub destroys the credit and records what it now owes
	// that peer — the value left this ledger, and it is the claim the peer
	// records against this hub.
	local := auth.PayTo == hubAID
	if !local {
		if local, err = s.registered(tx, auth.PayTo); err != nil {
			return fail(refuse(payment.ReasonSettlementFailed, "%v", err))
		}
	}
	switch {
	case via == "" && !local:
		return fail(refuse(payment.ReasonPayeeNotLocal,
			"%s is not an account of this hub; a payment to an agent on another hub is settled through that agent's hub, and nothing was charged",
			auth.PayTo))
	case via != "" && local:
		return fail(refuse(payment.ReasonPayeeMismatch,
			"%s is an account of this hub; a payment to it is settled here, at /x402/settle, not forwarded", auth.PayTo))
	}
	if err := addToRow(tx, "credit_balance", "aid", "credits", auth.Payer, -amt); err != nil {
		return fail(moved(err))
	}
	if local {
		if err := addToRow(tx, "credit_balance", "aid", "credits", auth.PayTo, amt); err != nil {
			return fail(moved(err))
		}
	}
	// Credit that comes home to the hub's own row leaves circulation: a
	// redemption (a payment to the hub), or a payment to an agent on a
	// peer (below). That is a supply event, recorded in this transaction
	// with the movement itself (hub-payment-privacy PAY-S1). It used to be
	// appended to the public issuance chain after the commit, naming the
	// payer, the amount and the payee; an epoch states only the total.
	if auth.PayTo == hubAID || via != "" {
		if err := s.supplyEventTx(tx, supplyRedeemed, amt); err != nil {
			return fail(moved(err))
		}
	}
	if via != "" {
		// Owed to the hub that signed the forwarded request: a fact this
		// hub verified, where the payee's hub would be a guess.
		if err := addToRow(tx, "hub_due", "peer_aid", "amount", via, amt); err != nil {
			return fail(moved(err))
		}
		// The credit comes home to the hub's own row, which is the same
		// movement a redemption makes: value left this ledger, so this
		// hub's outstanding liability falls by it. Without this the payer
		// was debited and nothing recorded the drop, so outstanding kept
		// counting credit that was no longer on any account here.
		if err := addToRow(tx, "credit_balance", "aid", "credits", hubAID, amt); err != nil {
			return fail(moved(err))
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
	// be matched at all. A payee on a peer has no account here and gets no
	// entry here; the hub's own row does, because that is where the credit
	// went, and supply is counted off that row.
	credited := auth.PayTo
	if via != "" {
		credited = hubAID
	}
	for _, e := range []struct {
		aid   string
		delta int64
	}{
		{auth.Payer, -amt},
		{credited, amt},
	} {
		if _, err := tx.Exec(
			`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
			e.aid, e.delta, id, at); err != nil {
			return fail(refuse(payment.ReasonSettlementFailed, "%v", err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fail(refuse(payment.ReasonSettlementFailed, "%v", err))
	}
	out := payment.SettlementResponse{Success: true, Payer: auth.Payer,
		Transaction: id, Network: network, Amount: payment.Amount(auth.Amount)}
	if rec != nil {
		out.Extensions = map[string]any{payment.ExtReceipt: base64.StdEncoding.EncodeToString(rec)}
	}
	return out
}

// settleGuardKey is the key of the binding guard of a payer's settlement of
// one task: evidence.SettleGuard(payer, pay_bind) (core L33), which refuses a
// field holding U+0000 (CORE-E9).
func settleGuardKey(payer, payBind string) ([]byte, error) {
	return evidence.SettleGuard(payer, payBind)
}

// settleConflict explains an INSERT into credit_settled that failed.
//
// Either this authorization is already settled — a concurrent repeat
// committed first — and the answer is its original receipt (repeatOf), or
// the insert failed for another reason, which is reported as
// settlement_failed.
func (s *Store) settleConflict(hubAID string, auth *payment.Authorization, id, via string,
	insertErr error) payment.SettlementResponse {
	if out, done := s.repeatOf(hubAID, id, auth, via); done {
		return out
	}
	return refusedSettlement(refuse(payment.ReasonSettlementFailed, "%v", insertErr), auth, auth.Network)
}

// bindingRefusal is the answer to a second authorization for a task its
// payer already settled: duplicate_binding, nothing moved. The settlement
// that holds the binding is named while its row is kept (7 days past its
// NotAfter); after that the guard alone remains, and only the code is given.
func (s *Store) bindingRefusal(auth *payment.Authorization, guard []byte) payment.SettlementResponse {
	holder, err := s.guardHolder(guard)
	if err != nil {
		return refusedSettlement(refuse(payment.ReasonSettlementFailed, "%v", err), auth, auth.Network)
	}
	if holder == "" {
		return refusedSettlement(refuse(payment.ReasonDuplicateBinding,
			"payer %s already settled this task; this authorization moved nothing", auth.Payer), auth, auth.Network)
	}
	out := refusedSettlement(refuse(payment.ReasonDuplicateBinding,
		"payer %s already settled %s for this task; this authorization moved nothing", auth.Payer, holder),
		auth, auth.Network)
	out.Extensions[payment.ExtOriginalTransaction] = holder
	return out
}

// settledBefore answers a repeated settlement of an authorization this hub
// already settled: the same success, with the original receipt, flagged
// payment.ExtReplayed; via is whom it was settled for ("" here, or the
// peer hub of a forwarded one).
//
// A caller whose first response was lost is the caller most in need of the
// hub's signed statement, because it is the party that has been charged.
// So the answer is the same proof whenever it is asked for, including
// after the authorization's window has closed, as long as the row is kept.
func (s *Store) settledBefore(hubAID, id string) (out payment.SettlementResponse, via string, settled bool, err error) {
	var payer, payTo, at string
	var amount int64
	var rec []byte
	err = s.db.QueryRow(
		`SELECT payer, pay_to, amount, at, receipt, via FROM credit_settled WHERE auth_id=?`, id).
		Scan(&payer, &payTo, &amount, &at, &rec, &via)
	if errors.Is(err, sql.ErrNoRows) {
		return payment.SettlementResponse{}, "", false, nil
	}
	if err != nil {
		return payment.SettlementResponse{}, "", false, err
	}
	// Stated back as it was settled, and only an amount that could have
	// been: a row from before the range check (a settlement of 2^64-1000
	// stored as -1000) is not answered as a success, and its receipt is
	// not re-signed.
	settledAmount, ok := storedAmount(amount)
	if !ok {
		return payment.SettlementResponse{}, "", false, errStoredAmount("credit_settled", id, amount)
	}
	network := payment.CreditNetwork(hubAID)
	out = payment.SettlementResponse{Success: true, Payer: payer, Transaction: id,
		Network: network, Amount: payment.Amount(settledAmount),
		Extensions: map[string]any{payment.ExtReplayed: true}}
	if len(rec) == 0 {
		// A row settled while the store had no signing key. The receipt is
		// signed now from the row, with the row's own time as the
		// settlement time. Ed25519 signatures are deterministic, so every
		// later repeat of this row returns the same bytes, as long as the
		// hub's signing key has not changed.
		var settleAt int64
		if t, perr := time.Parse(time.RFC3339Nano, at); perr == nil {
			settleAt = t.UnixMilli()
		}
		if rec, err = s.signReceipt(id, payer, payTo, settledAmount, network, settleAt); err != nil {
			log.Printf("hub: re-signing the receipt of settlement %s: %v", id, err)
		}
	}
	if len(rec) > 0 {
		out.Extensions[payment.ExtReceipt] = base64.StdEncoding.EncodeToString(rec)
	}
	return out, via, true, nil
}

// authSettled reports whether an authorization id has been settled here.
func (s *Store) authSettled(id string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM credit_settled WHERE auth_id=?`, id).Scan(&n)
	return n > 0, err
}

// guardHeld reports whether the binding guard is live at now (unix ms), and
// the settlement that holds it while that row is kept ("" after).
func (s *Store) guardHeld(guard []byte, now int64) (held bool, holder string, err error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM settle_guard WHERE h=? AND until > ?`, guard, now).
		Scan(&n); err != nil || n == 0 {
		return false, "", err
	}
	holder, err = s.guardHolder(guard)
	return true, holder, err
}

// guardHolder is the settlement that holds the binding guard, or "" when
// none of the kept settlements does.
func (s *Store) guardHolder(guard []byte) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT auth_id FROM credit_settled WHERE guard_h=? LIMIT 1`, guard).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// signReceipt is this hub's signed statement of one settlement, marshalled.
//
// Every settlement gets one, not only the cross-hub ones. A payer holding
// a receipt for its own hub's settlement can show what it was charged
// without asking the hub to agree, and that is worth more than the one
// line it costs. Nil, with no error, when the store has no signing key:
// an unsigned settlement is weaker, not broken.
func (s *Store) signReceipt(authID, payer, payTo string, amount uint64, network string,
	settleAt int64) ([]byte, error) {
	if s.hubKey == nil {
		return nil, nil
	}
	rec := &payment.Receipt{AuthID: authID, Payer: payer, PayTo: payTo, Amount: amount,
		Network: network, SettleAt: settleAt}
	if err := rec.Sign(s.hubKey); err != nil {
		return nil, err
	}
	return rec.Marshal()
}

// VerifyWithRequirements answers "would this settle?" without moving
// anything, for a payment on this hub's own ledger.
//
// A payment on a peer's ledger is refused with network_mismatch rather
// than forwarded (A2A-DESIGN §8.5). Verify moves nothing, so there is no
// cross-hub state to keep consistent by asking the peer, and /x402/settle
// runs the same checks at the entry hub and the ledger hub when it is
// called.
func (s *Store) VerifyWithRequirements(hubAID string, p *payment.PaymentPayload,
	req *payment.PaymentRequirements) payment.VerifyResponse {
	invalid := func(rf *Refusal, auth *payment.Authorization) payment.VerifyResponse {
		out := payment.VerifyResponse{IsValid: false, InvalidReason: rf.Reason}
		if auth != nil {
			out.Payer = auth.Payer
		}
		return out
	}
	if req == nil {
		return invalid(refuse(payment.ReasonInvalidRequirements, "paymentRequirements is required"), nil)
	}
	if p == nil {
		return invalid(refuse(payment.ReasonMalformed, "no payment payload"), nil)
	}
	if rf := payeeIsThisHub(hubAID, req); rf != nil {
		return invalid(rf, nil)
	}
	// What /x402/settle would refuse (payee_not_local), verify refuses.
	if rf := s.payeeHere(req.PayTo); rf != nil {
		return invalid(rf, nil)
	}
	if own := payment.CreditNetwork(hubAID); p.Accepted.Network != own {
		return invalid(refuse(payment.ReasonNetworkMismatch,
			"this facilitator verifies payments on %s only", own), nil)
	}
	auth, id, kel, rf := s.verifiedAuth(hubAID, p)
	if rf != nil {
		return invalid(rf, auth)
	}
	if rf := CheckRequirements(p, auth, req); rf != nil {
		return invalid(rf, auth)
	}
	if spent, err := s.authSettled(id); err != nil {
		return invalid(refuse(payment.ReasonSettlementFailed, "%v", err), auth)
	} else if spent {
		return invalid(refuse(payment.ReasonDuplicateNonce, "authorization already settled"), auth)
	}
	now := s.now().UnixMilli()
	if auth.InteractionID != "" {
		guard, err := settleGuardKey(auth.Payer, auth.InteractionID)
		if err != nil {
			return invalid(refuse(payment.ReasonMalformed, "the authorization's payer or interaction id: %v", err), auth)
		}
		held, holder, err := s.guardHeld(guard, now)
		if err != nil {
			return invalid(refuse(payment.ReasonSettlementFailed, "%v", err), auth)
		}
		if held {
			return invalid(refuse(payment.ReasonDuplicateBinding, "binding held by %q", holder), auth)
		}
	}
	if rf := s.keyAtFirstVerify(auth, id, kel, now); rf != nil {
		return invalid(rf, auth)
	}
	amt, ok := amountInt64(auth.Amount)
	if !ok {
		return invalid(amountRefusal("authorization", auth.Amount), auth)
	}
	bal, err := s.Balance(auth.Payer)
	if err != nil {
		return invalid(refuse(payment.ReasonSettlementFailed, "%v", err), auth)
	}
	if bal < amt {
		return invalid(refuse(payment.ReasonInsufficientFunds, "has %d, needs %d", bal, auth.Amount), auth)
	}
	return payment.VerifyResponse{IsValid: true, Payer: auth.Payer}
}

// SettlementPending is the entry hub's answer for a forwarded payment
// whose outcome it does not know: the ledger hub did not answer, answered
// unreadably, or settled and this hub has not credited the payee.
//
// Not final (payment.ReasonSettlementPending). The merchant retries with
// the same payload: the ledger hub answers an authorization it already
// settled with the original receipt, whether or not the window has closed,
// and ClearFromPeer is idempotent on the authorization id, so the retry
// credits the payee at most once. When the ledger hub's reply carried a
// receipt it is kept in the extensions, as the evidence that the payer was
// charged.
func SettlementPending(auth *payment.Authorization, network, detail string,
	peer *payment.SettlementResponse) payment.SettlementResponse {
	out := refusedSettlement(refuse(payment.ReasonSettlementPending, "%s", detail), auth, network)
	if peer != nil {
		if rec, ok := peer.Extensions[payment.ExtReceipt]; ok {
			out.Extensions[payment.ExtReceipt] = rec
		}
	}
	return out
}

// SettlementRefusedByPeer is the entry hub's answer for a forwarded payment
// the ledger hub refused before its ledger saw it (the hub does not count
// this one as a peer, or did not take its signature): settlement_failed,
// with the ledger hub's reason in the detail. Nothing was charged there,
// and the same request would be refused again; the operators of the two
// hubs settle it between them.
func SettlementRefusedByPeer(auth *payment.Authorization, network, peerAID, reason string) payment.SettlementResponse {
	log.Printf("hub: the ledger hub %s refused a forwarded settlement: %s", peerAID, reason)
	return refusedSettlement(refuse(payment.ReasonSettlementFailed,
		"the ledger hub %s refused the forwarded request (%s); nothing was charged there", peerAID, reason),
		auth, network)
}

// ClearPeerSettlement is the entry hub's second half of a cross-hub
// settlement: it checks that the ledger hub settled the required terms and
// credits the local payee against the ledger hub's receipt.
//
// The receipt must name the forwarded authorization and its payer, the
// ledger it was forwarded to, the required payee and at least the required
// amount. A receipt for other terms is refused rather than cleared:
// clearing it would credit whoever the ledger hub named. The refusal
// carries the receipt, because the ledger hub has moved credit this hub
// will not match and the receipt is what shows it.
//
// A matching receipt that cannot be cleared — the peer's key history
// cannot be fetched, the receipt does not verify against it, or the write
// fails — is settlement_pending: the payer has been charged, and the retry
// described at SettlementPending completes it.
func (s *Store) ClearPeerSettlement(peerAID string,
	peerKEL func(string) ([]identity.SignedEvent, error), out payment.SettlementResponse,
	auth *payment.Authorization, req *payment.PaymentRequirements) payment.SettlementResponse {
	network := req.Network
	withReceipt := func(rf *Refusal) payment.SettlementResponse {
		r := refusedSettlement(rf, auth, network)
		if rec, ok := out.Extensions[payment.ExtReceipt]; ok {
			r.Extensions[payment.ExtReceipt] = rec
		}
		log.Printf("hub: cross-hub settlement at %s not cleared: %v", peerAID, rf)
		return r
	}
	b64, _ := out.Extensions[payment.ExtReceipt].(string)
	if b64 == "" {
		return withReceipt(refuse(payment.ReasonSettlementFailed,
			"%s reported success without a settlement receipt; nothing was credited here", peerAID))
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return withReceipt(refuse(payment.ReasonSettlementFailed, "%s's receipt is not base64: %v", peerAID, err))
	}
	rec, err := payment.UnmarshalReceipt(raw)
	if err != nil {
		return withReceipt(refuse(payment.ReasonSettlementFailed, "%s's receipt is unreadable: %v", peerAID, err))
	}
	id, err := auth.ID()
	if err != nil {
		return withReceipt(refuse(payment.ReasonMalformed, "authorization id: %v", err))
	}
	want, err := payment.ParseAmount(req.Amount)
	if err != nil {
		return withReceipt(refuse(payment.ReasonInvalidRequirements, "required amount: %v", err))
	}
	if _, ok := amountInt64(rec.Amount); !ok {
		// Forwarded only in range (parseAuth), so a receipt outside it
		// states a movement the ledger hub made of its own accord; this
		// ledger cannot book it, and ClearFromPeer would refuse it too.
		return withReceipt(amountRefusal(peerAID+"'s receipt", rec.Amount))
	}
	switch {
	case rec.AuthID != id || rec.Payer != auth.Payer || rec.Network != network:
		return withReceipt(refuse(payment.ReasonSettlementFailed,
			"%s's receipt is for authorization %s by %s on %s, not %s by %s on %s",
			peerAID, rec.AuthID, rec.Payer, rec.Network, id, auth.Payer, network))
	case rec.PayTo != req.PayTo:
		return withReceipt(refuse(payment.ReasonPayeeMismatch,
			"%s settled a payment to %s; the requirements name %s", peerAID, rec.PayTo, req.PayTo))
	case rec.Amount < want:
		return withReceipt(refuse(payment.ReasonInvalidAmount,
			"%s settled %d; the requirements ask for %d", peerAID, rec.Amount, want))
	case rec.Amount != auth.Amount:
		// The ledger hub moves exactly what the payer signed (settleAuth),
		// and the authorization is here to compare with. A receipt for more
		// credited the local payee, and what the peer owes us, with an
		// amount nobody signed — up to 2^63-1 at a time, enough to push a
		// balance past what the ledger can hold [redteam:si9].
		return withReceipt(refuse(payment.ReasonInvalidAmount,
			"%s settled %d; the authorization it was forwarded pays %d", peerAID, rec.Amount, auth.Amount))
	}
	kel, err := s.peerKELFor(peerKEL, peerAID, receiptSeq(rec))
	if err != nil {
		return SettlementPending(auth, network,
			"settled at "+peerAID+" but not cleared here: "+err.Error(), &out)
	}
	if err := s.ClearFromPeer(peerAID, kel, rec); err != nil {
		if errors.Is(err, errReceiptOutOfWindow) {
			// Final: no retry makes this receipt clearable. Logged where
			// ClearFromPeer refused it; what the payer paid is a matter
			// between the two hubs' operators (anet-hub clear).
			return withReceipt(refuse(payment.ReasonSettlementFailed,
				"%s settled this payment, but its receipt is dated outside the %s this hub clears receipts in; nothing was credited here",
				peerAID, peerReceiptMaxAge))
		}
		// The peer moved credit and we could not credit our payee. The
		// money left one ledger and has not arrived on the other; the
		// merchant is told the outcome is pending and retries.
		log.Printf("hub: cross-hub settlement %s at %s not cleared yet: %v", id, peerAID, err)
		return SettlementPending(auth, network,
			"settled at "+peerAID+" but not cleared here: "+err.Error(), &out)
	}
	return out
}

// SetHubKey gives the store the identity it signs settlements with, and
// the row credit is issued from and redeemed back into. It takes the hub
// identity as a Signer (KEL H-36): the Controller itself, whose Sign takes
// one key state at a time, or a snapshot.
func (s *Store) SetHubKey(c identity.Signer) {
	s.hubKey = c
	s.hubAID = c.AID()
}

// errReceiptOutOfWindow is ClearFromPeer's refusal of a receipt dated
// outside the time this hub clears receipts in (receipt_too_old): more than
// peerReceiptMaxAge ago, or further ahead than any clock is off. No retry
// makes it clearable.
var errReceiptOutOfWindow = errors.New("receipt_too_old")

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
//
// A receipt is cleared once (credit_cleared, kept until 8 days after its
// SettleAt) and only within 7 days of its SettleAt (PAY-L5): one older is
// refused with errReceiptOutOfWindow and logged as receipt_too_old, so a
// receipt whose row the janitor has deleted cannot be cleared a second
// time. A receipt already cleared is answered as cleared at any age, so a
// merchant retrying late still hears the outcome.
func (s *Store) ClearFromPeer(peerAID string, peerKEL []identity.SignedEvent,
	rec *payment.Receipt) error {
	if rec == nil {
		return fmt.Errorf("no settlement receipt")
	}
	// A peer's signature over an amount this ledger cannot hold does not
	// make it one: credited as int64(…) it debited the local payee and
	// the peer's debt to us. See amountInt64.
	amt, ok := amountInt64(rec.Amount)
	if !ok {
		return amountRefusal("receipt", rec.Amount)
	}
	if rec.Network != payment.CreditNetwork(peerAID) {
		return fmt.Errorf("receipt is for %s, not %s's ledger", rec.Network, peerAID)
	}
	// Not to this hub itself. The credit would land on the hub's own row
	// and leave it again below, the peer would be recorded as owing it,
	// and the issuance would be held by no account, so the supply stopped
	// adding up (found by FuzzHubClearFromPeer, ANet an internal note). A
	// payment to a hub is a redemption on that hub's own ledger;
	// SettleWithRequirements does not forward one.
	if s.hubAID != "" && rec.PayTo == s.hubAID {
		return refuse(payment.ReasonPayeeMismatch,
			"%s's receipt pays this hub (%s); a peer's settlement credits an agent here, never the hub's own row",
			peerAID, rec.PayTo)
	}
	now := s.now()
	// At the time the peer settled (KEL H-34): a receipt the peer signed
	// before it rotated still verifies under the key it had then.
	if err := rec.Verify(peerKEL, peerAID, rec.SettleAt); err != nil {
		return fmt.Errorf("settlement receipt from %s: %w", peerAID, err)
	}
	// One transaction, which holds the database's write lock from its
	// start: issuanceRoom below and the credit are one step against every
	// other issuance, as in issueTx.
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Already cleared is success: the same statement, not a new one.
	if done, err := clearedTx(tx, rec.AuthID); err != nil || done {
		return err
	}
	// SettleAt is the peer's to write, any int64: it is compared with the
	// two ends of the window, never subtracted from now, since a SettleAt
	// 2^63 ms before now made now − SettleAt wrap to math.MinInt64, which
	// neither "too old" nor (negated, still negative) "too new" caught.
	nowMs := now.UnixMilli()
	if rec.SettleAt < nowMs-peerReceiptMaxAge.Milliseconds() || rec.SettleAt > nowMs+relayauth.MaxSkewMillis {
		// Logged for the operator, without the payee or the payment's id:
		// the peer, the amount and the day are what the two operators
		// need to settle it between them (anet-hub clear).
		log.Printf("hub: receipt_too_old: %s settled %d credits for an agent here at %s, outside the %s this hub "+
			"clears receipts in; not credited (settle it with %s's operator)",
			peerAID, amt, time.UnixMilli(rec.SettleAt).UTC().Format(time.DateOnly), peerReceiptMaxAge, peerAID)
		return fmt.Errorf("%w: settled at %d", errReceiptOutOfWindow, rec.SettleAt)
	}
	at := ledgerStamp(now)
	// One row per foreign authorization: a peer repeating a receipt must
	// not credit our user twice.
	if _, err := tx.Exec(
		`INSERT INTO credit_cleared(auth_id, peer_aid, pay_to, amount, at, settle_at) VALUES(?,?,?,?,?,?)`,
		rec.AuthID, peerAID, rec.PayTo, amt, at, rec.SettleAt); err != nil {
		// Any failure to write the row other than a concurrent clearing of
		// the same receipt is returned. Reading every insert failure as
		// "already cleared" reported a clearing that had not happened as
		// done, so the entry hub answered success, the merchant stopped
		// retrying, and the payee was never credited.
		if done, qerr := clearedTx(tx, rec.AuthID); qerr == nil && done {
			return nil
		}
		return fmt.Errorf("recording the clearing of %s: %w", rec.AuthID, err)
	}
	// The credit is new supply here, so it must fit what the supply can
	// add up to, not only the payee's row.
	if err := issuanceRoom(tx, amt); err != nil {
		return err
	}
	// addToRow, as in settleAuth: a sum the column cannot hold is refused
	// (invalid_amount) and the whole clearing rolls back.
	if err := addToRow(tx, "credit_balance", "aid", "credits", rec.PayTo, amt); err != nil {
		return err
	}
	// With its ledger entry, for the same reason settlement has one: a
	// payee whose balance rose with nothing in the entries to explain it
	// cannot reconcile its own account.
	if _, err := tx.Exec(
		`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
		rec.PayTo, amt, rec.AuthID, at); err != nil {
		return err
	}
	// The hub's own row falls by what it just created, because supply is
	// counted off that row: crediting the payee without it left the ledger
	// showing more credit on accounts than the hub had ever issued.
	if err := addToRow(tx, "credit_balance", "aid", "credits", s.hubKey.AID(), -amt); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
		s.hubKey.AID(), -amt, rec.AuthID, at); err != nil {
		return err
	}
	// What the peer owes us, kept as a running total rather than netted
	// into anyone's balance: it is a claim on another hub, not credit
	// here, and the two must not be allowed to look alike.
	if err := addToRow(tx, "hub_owed", "peer_aid", "amount", peerAID, amt); err != nil {
		return err
	}
	// This is issuance: the payee's balance rose on this ledger and no
	// account here fell, because the payer's account is on the peer. It is
	// backed by a claim on that peer rather than by nothing, but it is new
	// supply here, recorded with the credit (hub-payment-privacy PAY-S1).
	if err := s.supplyEventTx(tx, supplyIssued, amt); err != nil {
		return err
	}
	return tx.Commit()
}

// clearedTx reports whether a peer's receipt for authID was cleared here.
func clearedTx(tx *sql.Tx, authID string) (bool, error) {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM credit_cleared WHERE auth_id=?`, authID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// Due is what this hub owes each peer hub, by the peer's AID: credit that
// left this ledger when a peer forwarded a settlement for its own agent
// (SettleForPeer).
//
// Reported so an operator can see the obligation before discharging it
// (anet-hub due, anet-hub clear), and so the two hubs' numbers can be
// compared: this hub's due to a peer is that peer's owed from this hub
// (hub_owed), minus what is in flight.
func (s *Store) Due() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT peer_aid, amount FROM hub_due WHERE amount > 0`)
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

// DueTo is what this hub owes the peer hub peerAID.
func (s *Store) DueTo(peerAID string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT amount FROM hub_due WHERE peer_aid=?`, peerAID).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// ErrOverDue is DischargeDue's refusal of a discharge larger than what this
// hub owes the peer (anet-hub clear says clear.over_due).
var ErrOverDue = errors.New("hub: more than this hub owes that peer")

// DischargeDue reduces what this hub owes a peer hub, once the discharge
// has been signed and the peer has accepted it.
//
// Separate from signing the statement, because the statement can be
// signed and the peer can still refuse it — reducing the obligation
// before the peer accepted would leave this hub believing it had paid
// something the other hub still shows as owed.
func (s *Store) DischargeDue(peerAID string, amount int64) error {
	// A discharge reduces what is due. A negative one would raise it, and
	// "amount >= ?" below would let it through.
	if amount <= 0 {
		return fmt.Errorf("a discharge must be positive, got %d", amount)
	}
	res, err := s.db.Exec(
		`UPDATE hub_due SET amount = amount - ? WHERE peer_aid = ? AND amount >= ?`,
		amount, peerAID, amount)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: a discharge of %d to %s", ErrOverDue, amount, peerAID)
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
//
// x402 v2 also asks for the extensions this facilitator implements and
// who signs on each network. Every settlement response carries a receipt
// (payment.ExtReceipt), signed by the hub whose ledger the network names;
// anet.signer_kel says where each signer's KEL is served, which is what a
// receipt is verified against.
func (s *Server) hX402Supported(w http.ResponseWriter, r *http.Request) {
	own := payment.CreditNetwork(s.hubAID)
	kinds := []payment.SupportedKind{{
		X402Version: payment.Version,
		Scheme:      payment.SchemeCredit,
		Network:     own,
	}}
	signers := map[string][]string{}
	kels := map[string]string{}
	if s.hubAID != "" {
		signers[own] = []string{s.hubAID}
		kels[s.hubAID] = s.origin(r) + "/hub/identity"
	}
	for _, aid := range s.store.ClearablePeers() {
		kinds = append(kinds, payment.SupportedKind{
			X402Version: payment.Version,
			Scheme:      payment.SchemeCredit,
			Network:     payment.CreditNetwork(aid),
		})
		signers[payment.CreditNetwork(aid)] = []string{aid}
		if ep := s.peerEndpoint(aid); ep != "" {
			kels[aid] = strings.TrimSuffix(ep, "/") + "/hub/identity"
		}
	}
	writeJSON(w, http.StatusOK, payment.Supported{Kinds: kinds,
		Extensions: []string{payment.ExtReceipt}, Signers: signers, SignerKEL: kels})
}

// readFacilitatorRequest reads a /verify or /settle body: x402 v2's
// {x402Version, paymentPayload, paymentRequirements}.
//
// paymentRequirements is required. Without it this hub would settle
// whatever the payer signed, and could not tell a payment of the quoted
// price to the quoting merchant from a smaller one to somebody else.
func readFacilitatorRequest(w http.ResponseWriter, r *http.Request) (payment.FacilitatorRequest, *Refusal) {
	var req payment.FacilitatorRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		return req, refuse(payment.ReasonMalformed, "malformed request: %v", err)
	}
	if req.PaymentPayload == nil {
		return req, refuse(payment.ReasonMalformed, "paymentPayload is required")
	}
	if req.PaymentRequirements == nil {
		return req, refuse(payment.ReasonInvalidRequirements, "paymentRequirements is required (x402 v2)")
	}
	return req, nil
}

func (s *Server) hX402Verify(w http.ResponseWriter, r *http.Request) {
	req, rf := readFacilitatorRequest(w, r)
	if rf != nil {
		writeJSON(w, http.StatusBadRequest, payment.VerifyResponse{IsValid: false, InvalidReason: rf.Reason})
		return
	}
	writeJSON(w, http.StatusOK, s.store.VerifyWithRequirements(s.hubAID, req.PaymentPayload, req.PaymentRequirements))
}

func (s *Server) hX402Settle(w http.ResponseWriter, r *http.Request) {
	req, rf := readFacilitatorRequest(w, r)
	if rf != nil {
		writeJSON(w, http.StatusBadRequest, refusedSettlement(rf, nil, payment.CreditNetwork(s.hubAID)))
		return
	}
	writeJSON(w, http.StatusOK, s.store.SettleWithRequirements(s.hubAID, req.PaymentPayload, req.PaymentRequirements))
}

// FedSettleBodyLimit bounds a /fed/v3/settle body, as /x402/settle's is.
const FedSettleBodyLimit = 1 << 20

// ServeFedSettle answers POST /fed/v3/settle (core §2.12.2; hub-payment-privacy
// PAY-L4) for a request the peer hub peerAID signed, whose body is body:
// federation's authPeer has checked the peer table, the signature and RC1.
// The body is the x402 v2 {x402Version, paymentPayload, paymentRequirements}
// the peer's merchant asked it to settle, and the answer is the x402
// SettlementResponse with status 200, a refusal included (core G3).
//
// The log names the peer that signed, and nothing of the payment.
func (s *Server) ServeFedSettle(w http.ResponseWriter, peerAID string, body []byte) {
	var req payment.FacilitatorRequest
	var out payment.SettlementResponse
	if err := json.Unmarshal(body, &req); err != nil {
		out = refusedSettlement(refuse(payment.ReasonMalformed, "malformed request: %v", err), nil,
			payment.CreditNetwork(s.hubAID))
	} else {
		out = s.store.SettleForPeer(s.hubAID, peerAID, req.PaymentPayload, req.PaymentRequirements)
	}
	if out.Success {
		log.Printf("hub: fed_settle signed by %s: settled", peerAID)
	} else {
		log.Printf("hub: fed_settle signed by %s: %s", peerAID, out.ErrorReason)
	}
	writeJSON(w, http.StatusOK, out)
}

// hBalance serves an account's balance to the account holder only.
//
// The request must be signed by the AID in the path (relayauth v2, action
// "balance", the preimage binding method, path and query); an unsigned
// request, or one signed by anyone else, gets 401 and no data. The
// balance, the ledger and the redemption list were public, and between
// them showed anyone which accounts paid which, how much and when
// (A2A-DESIGN §3.7). What is public about the ledger is one total per
// supply epoch (supply.go), which names no account and no payment.
func (s *Server) hBalance(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authSelf(w, r, relayauth.ActionBalance, signedBodyLimit)
	if !ok {
		return
	}
	n, err := s.store.Balance(a.AID)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	st, err := s.store.trialStateOf(a.AID)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, Balance{AID: a.AID, Credits: n, ProbationUntil: st.ProbationUntil, Trial: st.Trial})
}

// ---- how credit gets into the system ----

// GrantCredit is the operator's way in (anet-hub grant). It is a supply
// event like the other two ways credit is created on purpose here, the
// admission grant and the trial credit (admission.go); registration itself
// pays nothing (PAY-A5).
func (s *Store) GrantCredit(aid string, amount int64, reason string) error {
	if amount <= 0 {
		return fmt.Errorf("a grant must be positive, got %d", amount)
	}
	if reason == "" {
		reason = "operator grant"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Checked before anything is written: a balance SQLite could only hold
	// as a REAL would leave the account unreadable (addToRow)
	// [redteam:si9].
	var bal int64
	if err := tx.QueryRow(`SELECT COALESCE((SELECT credits FROM credit_balance WHERE aid=?), 0)`, aid).
		Scan(&bal); err != nil {
		return err
	}
	if bal > math.MaxInt64-amount {
		return fmt.Errorf("%s holds %d; a grant of %d would take it past %d, the most this ledger can hold",
			aid, bal, amount, int64(math.MaxInt64))
	}
	if err := s.issueTx(tx, aid, amount, reason); err != nil {
		return err
	}
	return tx.Commit()
}

// LedgerWindow is an account's ledger as /agents/{aid}/ledger serves it:
// the entries of the last LedgerWindowDays days (PAY-L6), the newest limit
// of them, oldest first.
type LedgerWindow struct {
	Entries []LedgerEntry
	// Total and Sum are how many entries the window holds and what they
	// add up to, whatever the page; OldestSeq is the seq of the earliest
	// of them, 0 when there is none.
	Total     int
	Sum       int64
	OldestSeq uint64
}

// LedgerEntries returns an account's movements of the ledger window, the
// newest limit of them, oldest first, with the window's totals.
//
// The point of keeping them is that a balance can be explained rather
// than asserted — by the account holder, without asking the hub to agree
// about anything except what it already published. They are kept 14 days
// (janitor.go): the window explains how the balance moved within it, and
// the supply epochs vouch for the balance itself.
func (s *Store) LedgerEntries(aid string, limit int) (LedgerWindow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	from := windowStart(s.now())
	var w LedgerWindow
	var oldest sql.NullInt64
	if err := s.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(delta),0), MIN(seq) FROM credit_entry WHERE aid=? AND at >= ?`, aid, from).
		Scan(&w.Total, &w.Sum, &oldest); err != nil {
		return w, err
	}
	if oldest.Valid {
		w.OldestSeq = uint64(oldest.Int64)
	}
	rows, err := s.db.Query(
		`SELECT seq, delta, reason, at FROM credit_entry WHERE aid=? AND at >= ? ORDER BY seq DESC LIMIT ?`,
		aid, from, limit)
	if err != nil {
		return w, err
	}
	defer rows.Close()
	w.Entries = []LedgerEntry{}
	for rows.Next() {
		var e LedgerEntry
		if err := rows.Scan(&e.Seq, &e.Delta, &e.Reason, &e.At); err != nil {
			return w, err
		}
		w.Entries = append(w.Entries, e)
	}
	if err := rows.Err(); err != nil {
		return w, err
	}
	slices.Reverse(w.Entries)
	return w, nil
}

// LedgerEntry is one movement on an account. Seq orders an account's
// entries and is never given out twice; At is when it was written (UTC).
type LedgerEntry struct {
	Seq    uint64 `json:"seq"`
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
