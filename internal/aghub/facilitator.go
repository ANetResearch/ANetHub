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
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"
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
// /x402/settle (own ledger and forwarded), /x402/redeem and the gateway.
// An amount above math.MaxInt64 is refused before its signature is even
// looked at, so no path below can book it as the negative number a bare
// int64(…) would make of it.
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
	return auth, nil
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
		return nil, "", nil, rf
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

// currentAuth is what a new settlement needs beyond verifiedAuth: the
// validity window, and the signing key being valid now and not only at
// IssuedAt. Checking the key at IssuedAt alone would let a key the payer
// has rotated away sign a spendable authorization by backdating it.
func currentAuth(auth *payment.Authorization, kel []identity.SignedEvent, now int64) *Refusal {
	if err := auth.Verify(kel, now); err != nil {
		return refuse(verifyReason(err), "%v", err)
	}
	return nil
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
// requirements. /x402/settle and the gateway call it.
//
// On this hub's own ledger the order is: decode and verify the payer's
// signature; compare with the requirements; answer an authorization
// already settled with its original receipt; check the validity window;
// settle. The repeat is answered before the window check, so a charged
// authorization yields its receipt at any time — a merchant whose settle
// call timed out retries until it learns the outcome (A2A-DESIGN §8.3) —
// and after the requirements check, so the receipt is returned only to a
// caller asking on the terms it was settled for.
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
	// A payment on another hub's ledger is that hub's to settle. We ask
	// it, and if it says yes we credit our own payee and record what that
	// hub now owes us — the two hubs clearing against each other rather
	// than one of them minting.
	if p.Accepted.Network != own && s.peerSettle != nil {
		auth, rf := parseAuth(p)
		if rf != nil {
			return refusedSettlement(rf, nil, p.Accepted.Network)
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
	prior, settled, err := s.settledBefore(hubAID, id)
	if err != nil {
		return refusedSettlement(refuse(payment.ReasonSettlementFailed, "%v", err), auth, own)
	}
	if settled {
		return prior
	}
	if rf := currentAuth(auth, kel, time.Now().UnixMilli()); rf != nil {
		return refusedSettlement(rf, auth, own)
	}
	return s.settleAuth(hubAID, auth, id)
}

// payeeIsThisHub refuses requirements that name this hub as the payee.
//
// A payment to the hub is a redemption, and /x402/redeem is the one path
// that books it as one: it records the redemption with its reference and
// puts the retirement on the issuance chain. Settled through /x402/settle
// the same authorization moved the credit to the hub's row with neither,
// so the published supply fell while the signed chain did not and
// chain_agrees stayed false from then on (found by FuzzHubX402Facilitator,
// ANet docs/notes/0033). On a peer's ledger the same payment comes back as
// a peer receipt naming this hub, which ClearFromPeer refuses for the
// same reason, so it is not forwarded either.
func payeeIsThisHub(hubAID string, req *payment.PaymentRequirements) *Refusal {
	if hubAID != "" && req.PayTo == hubAID {
		return refuse(payment.ReasonPayeeMismatch,
			"the requirements name this hub (%s) as the payee; a payment to the hub is a redemption, made at /x402/redeem",
			hubAID)
	}
	return nil
}

// settleAuth moves the credit for an authorization whose caller has
// already done the checks: the signature and the window, and the terms.
// SettleWithRequirements checks the terms against the requirements;
// Redeem checks its one term, that the payee is this hub, itself, because
// requirements built from the authorization's own amount would compare the
// authorization with itself.
//
// Idempotent on the authorization's content id: a settle call repeated
// because a reply was lost must not charge twice, and the id derives from
// the signed bytes so a payer cannot make two different authorizations
// look like one.
//
// At most one authorization per (payer, InteractionID) settles, when the
// InteractionID is not empty. The daemon puts its task binding there
// (A2A-DESIGN X4), so a second authorization for the same task — signed
// because the first one's outcome was lost, or because a payer is paying
// twice — is refused with duplicate_binding and moves nothing.
// Resending the first authorization is a repeat, not a second one, and is
// answered with its receipt.
func (s *Store) settleAuth(hubAID string, auth *payment.Authorization, id string) payment.SettlementResponse {
	network := auth.Network
	fail := func(rf *Refusal) payment.SettlementResponse { return refusedSettlement(rf, auth, network) }
	// parseAuth already refused it; this is the conversion itself, kept
	// behind the same check so no statement below can book a negative
	// amount even if a caller skipped parseAuth.
	amt, ok := amountInt64(auth.Amount)
	if !ok {
		return fail(amountRefusal("authorization", auth.Amount))
	}
	now := time.Now().UTC()
	at := now.Format(time.RFC3339Nano)
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

	// The settled table is the idempotency key, the replay guard and the
	// binding guard: one row per authorization id, and one bound row per
	// (payer, interaction_id), inserted first, so a concurrent second
	// settle loses on a constraint rather than on a check it raced.
	if _, err := tx.Exec(
		`INSERT INTO credit_settled(auth_id, payer, pay_to, amount, interaction_id, at, bound, receipt)
		 VALUES(?,?,?,?,?,?,1,?)`,
		id, auth.Payer, auth.PayTo, amt, auth.InteractionID, at, rec); err != nil {
		_ = tx.Rollback()
		return s.settleConflict(hubAID, auth, id, err)
	}

	var bal int64
	if err := tx.QueryRow(`SELECT COALESCE(credits,0) FROM credit_balance WHERE aid=?`,
		auth.Payer).Scan(&bal); err != nil && err.Error() != "sql: no rows in result set" {
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
	if err := addToRow(tx, "credit_balance", "aid", "credits", auth.Payer, -amt); err != nil {
		return fail(moved(err))
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
			return fail(refuse(payment.ReasonSettlementFailed, "%v", err))
		}
	}
	if local {
		if err := addToRow(tx, "credit_balance", "aid", "credits", auth.PayTo, amt); err != nil {
			return fail(moved(err))
		}
	} else {
		if err := addToRow(tx, "hub_due", "payee_aid", "amount", auth.PayTo, amt); err != nil {
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
	// be matched at all.
	for _, e := range []struct {
		aid   string
		delta int64
	}{
		{auth.Payer, -amt},
		{auth.PayTo, amt},
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
				hubAID, amt, id, at); err != nil {
				return fail(refuse(payment.ReasonSettlementFailed, "%v", err))
			}
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO credit_entry(aid, delta, reason, at) VALUES(?,?,?,?)`,
			e.aid, e.delta, id, at); err != nil {
			return fail(refuse(payment.ReasonSettlementFailed, "%v", err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fail(refuse(payment.ReasonSettlementFailed, "%v", err))
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
		if err := s.appendIssuance(EvCreditRetired, auth.Payer, amt,
			"cross-hub settlement "+id+" to "+auth.PayTo); err != nil {
			log.Printf("hub: cross-hub settlement %s not recorded on the issuance chain: %v",
				id, err)
		}
	}
	out := payment.SettlementResponse{Success: true, Payer: auth.Payer,
		Transaction: id, Network: network, Amount: payment.Amount(auth.Amount)}
	if rec != nil {
		out.Extensions = map[string]any{payment.ExtReceipt: base64.StdEncoding.EncodeToString(rec)}
	}
	return out
}

// settleConflict explains an INSERT into credit_settled that failed.
//
// Either this authorization is already settled — a concurrent repeat
// committed first — and the answer is its original receipt; or its
// (payer, interaction_id) binding is held by another authorization, and
// nothing moves; or the insert failed for another reason, which is
// reported as settlement_failed.
func (s *Store) settleConflict(hubAID string, auth *payment.Authorization, id string,
	insertErr error) payment.SettlementResponse {
	if prior, settled, err := s.settledBefore(hubAID, id); err == nil && settled {
		return prior
	}
	if auth.InteractionID != "" {
		holder, err := s.bindingHolder(auth.Payer, auth.InteractionID)
		if err == nil && holder != "" && holder != id {
			out := refusedSettlement(refuse(payment.ReasonDuplicateBinding,
				"payer %s already settled %s with this interaction id; this authorization moved nothing",
				auth.Payer, holder), auth, auth.Network)
			out.Extensions[payment.ExtOriginalTransaction] = holder
			return out
		}
	}
	return refusedSettlement(refuse(payment.ReasonSettlementFailed, "%v", insertErr), auth, auth.Network)
}

// settledBefore answers a repeated settlement of an authorization this hub
// already settled: the same success, with the original receipt, flagged
// payment.ExtReplayed.
//
// A caller whose first response was lost is the caller most in need of the
// hub's signed statement, because it is the party that has been charged.
// So the answer is the same proof whenever it is asked for, including
// after the authorization's window has closed.
func (s *Store) settledBefore(hubAID, id string) (payment.SettlementResponse, bool, error) {
	var payer, payTo, at string
	var amount int64
	var rec []byte
	err := s.db.QueryRow(
		`SELECT payer, pay_to, amount, at, receipt FROM credit_settled WHERE auth_id=?`, id).
		Scan(&payer, &payTo, &amount, &at, &rec)
	if errors.Is(err, sql.ErrNoRows) {
		return payment.SettlementResponse{}, false, nil
	}
	if err != nil {
		return payment.SettlementResponse{}, false, err
	}
	// Stated back as it was settled, and only an amount that could have
	// been: a row from before the range check (a settlement of 2^64-1000
	// stored as -1000) is not answered as a success, and its receipt is
	// not re-signed.
	settledAmount, ok := storedAmount(amount)
	if !ok {
		return payment.SettlementResponse{}, false, errStoredAmount("credit_settled", id, amount)
	}
	network := payment.CreditNetwork(hubAID)
	out := payment.SettlementResponse{Success: true, Payer: payer, Transaction: id,
		Network: network, Amount: payment.Amount(settledAmount),
		Extensions: map[string]any{payment.ExtReplayed: true}}
	if len(rec) == 0 {
		// A row settled before receipts were stored. The receipt is
		// re-signed from the row, with the row's own time as the
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
	return out, true, nil
}

// authSettled reports whether an authorization id has been settled here.
func (s *Store) authSettled(id string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM credit_settled WHERE auth_id=?`, id).Scan(&n)
	return n > 0, err
}

// bindingHolder is the authorization that holds a payer's binding, or ""
// when none does.
func (s *Store) bindingHolder(payer, interactionID string) (string, error) {
	var id string
	err := s.db.QueryRow(
		`SELECT auth_id FROM credit_settled WHERE payer=? AND interaction_id=? AND bound=1`,
		payer, interactionID).Scan(&id)
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

// migrateSettlement adds what settlement needs beyond the original
// credit_settled table: the stored receipt, and the binding constraint
// UNIQUE(payer, interaction_id) for non-empty interaction ids
// (A2A-DESIGN §8.5).
//
// The constraint is a partial unique index over rows marked bound = 1,
// and every new settlement is inserted bound. A hub upgraded with rows
// already in the table may hold two settlements for one (payer,
// interaction_id): before this constraint nothing stopped a second one.
// An index over all rows would then fail to build and the hub would not
// start. So on the upgrade the earliest settlement of each binding is
// marked bound, which makes it the holder a later authorization collides
// with, and the later duplicates stay in the table as the record of what
// happened. The column, the marking and the index are one transaction,
// so an interrupted upgrade is repeated whole at the next start.
func (s *Store) migrateSettlement() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("hub: migrate settlement: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`ALTER TABLE credit_settled ADD COLUMN bound INTEGER NOT NULL DEFAULT 0`)
	switch {
	case err == nil:
		if _, err := tx.Exec(`UPDATE credit_settled SET bound = 1
			WHERE interaction_id != '' AND rowid IN (
			  SELECT MIN(rowid) FROM credit_settled WHERE interaction_id != ''
			  GROUP BY payer, interaction_id)`); err != nil {
			return fmt.Errorf("hub: migrate settlement: %w", err)
		}
	case !strings.Contains(err.Error(), "duplicate column name"):
		return fmt.Errorf("hub: migrate settlement: %w", err)
	}
	if _, err := tx.Exec(`ALTER TABLE credit_settled ADD COLUMN receipt BLOB`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("hub: migrate settlement: %w", err)
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_settled_binding
		ON credit_settled(payer, interaction_id) WHERE interaction_id != '' AND bound = 1`); err != nil {
		return fmt.Errorf("hub: migrate settlement: %w", err)
	}
	return tx.Commit()
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
	if auth.InteractionID != "" {
		holder, err := s.bindingHolder(auth.Payer, auth.InteractionID)
		if err != nil {
			return invalid(refuse(payment.ReasonSettlementFailed, "%v", err), auth)
		}
		if holder != "" {
			return invalid(refuse(payment.ReasonDuplicateBinding, "binding held by %s", holder), auth)
		}
	}
	if rf := currentAuth(auth, kel, time.Now().UnixMilli()); rf != nil {
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
	kel, err := peerKEL(peerAID)
	if err != nil {
		return SettlementPending(auth, network,
			"settled at "+peerAID+" but not cleared here: "+err.Error(), &out)
	}
	if err := s.ClearFromPeer(peerAID, kel, rec); err != nil {
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
	// and the issuance appended after the commit would be held by no
	// account, so chain_agrees went false (found by FuzzHubClearFromPeer,
	// ANet docs/notes/0033). A payment to a hub is a redemption on that
	// hub's own ledger; SettleWithRequirements does not forward one.
	if s.hubAID != "" && rec.PayTo == s.hubAID {
		return refuse(payment.ReasonPayeeMismatch,
			"%s's receipt pays this hub (%s); a peer's settlement credits an agent here, never the hub's own row",
			peerAID, rec.PayTo)
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
		rec.AuthID, peerAID, rec.PayTo, amt,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		// Already cleared is success: the same statement, not a new one.
		// Any other failure to write the row is returned. Reading every
		// insert failure as "already cleared" reported a clearing that
		// had not happened as done, so the entry hub answered success,
		// the merchant stopped retrying, and the payee was never credited.
		var n int
		if qerr := tx.QueryRow(`SELECT COUNT(1) FROM credit_cleared WHERE auth_id=?`,
			rec.AuthID).Scan(&n); qerr == nil && n > 0 {
			return nil
		}
		return fmt.Errorf("recording the clearing of %s: %w", rec.AuthID, err)
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
		rec.PayTo, amt, rec.AuthID,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
		s.hubKey.AID(), -amt, rec.AuthID,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	// What the peer owes us, kept as a running total rather than netted
	// into anyone's balance: it is a claim on another hub, not credit
	// here, and the two must not be allowed to look alike.
	if err := addToRow(tx, "hub_owed", "peer_aid", "amount", peerAID, amt); err != nil {
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
	if err := s.appendIssuance(EvCreditIssued, rec.PayTo, amt,
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
	// A discharge reduces what is due. A negative one would raise it, and
	// "amount >= ?" below would let it through.
	if amount <= 0 {
		return fmt.Errorf("a discharge must be positive, got %d", amount)
	}
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

// hBalance serves an account's balance to the account holder only.
//
// The request must be signed by the AID in the path (relayauth v2, action
// "balance", the preimage binding method, path and query); an unsigned
// request, or one signed by anyone else, gets 401 and no data. The
// balance, the ledger and the redemption list were public, and between
// them showed anyone which accounts paid which, how much and when
// (A2A-DESIGN §3.7). The public issuance chain still shows amounts, times
// and AIDs of cross-hub payments and redemptions; that is recorded in
// A2A-DESIGN §21 item 9 and left unchanged in this round.
func (s *Server) hBalance(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authSelf(w, r, relayauth.ActionBalance, signedBodyLimit)
	if !ok {
		return
	}
	n, err := s.store.Balance(a.AID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, Balance{AID: a.AID, Credits: n})
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
	// Checked before anything is written: Credit records the issuance
	// first, and a balance SQLite could only hold as a REAL would leave the
	// account unreadable (addToRow) [redteam:si9].
	if bal, err := s.Balance(aid); err != nil {
		return err
	} else if bal > math.MaxInt64-amount {
		return fmt.Errorf("%s holds %d; a grant of %d would take it past %d, the most this ledger can hold",
			aid, bal, amount, int64(math.MaxInt64))
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

// RepairLedger writes one entry so an account's entries sum to its
// balance, and returns what it wrote.
//
// For accounts carrying settlements from before settlement wrote ledger
// entries at all. Those balances moved and left nothing behind, so the
// entries are permanently short by that amount and `anet reconcile`
// reports a discrepancy on every run — which is worse than it sounds,
// because a check that always says something is wrong is a check people
// stop reading.
//
// It records the correction rather than hiding it: one entry, named for
// what it is, visible in the same ledger as everything else. Nobody
// looking at the account later has to wonder where the number came from.
//
// It cannot move money. The balance is not touched, and the amount is
// derived from the gap rather than supplied — an operator can run this
// and cannot aim it. Running it twice is a no-op, because after the first
// run there is no gap.
func (s *Store) RepairLedger(aid string) (int64, error) {
	var bal int64
	if err := s.db.QueryRow(`SELECT COALESCE(credits,0) FROM credit_balance WHERE aid=?`,
		aid).Scan(&bal); err != nil && err.Error() != "sql: no rows in result set" {
		return 0, err
	}
	_, sum, err := s.LedgerTotals(aid)
	if err != nil {
		return 0, err
	}
	delta := bal - sum
	if delta == 0 {
		return 0, nil
	}
	return delta, s.entry(aid, delta,
		"ledger correction: settlements recorded before this hub wrote ledger entries")
}
