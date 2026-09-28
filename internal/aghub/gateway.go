package aghub

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
)

// The x402 resource server: this hub sells access to its agents' work
// without ever touching the work.
//
// The shape is deliberate and was chosen over the obvious one. A gateway
// that took payment and then proxied the call would be simpler for the
// buyer — one address, one round trip — and would put every request and
// every result through the hub. That is a lot of other people's content
// passing through a box whose whole design claim is that it carries bytes
// it cannot read. So the gateway sells and stops: it answers 402, settles
// the credit, and hands back a voucher. The buyer takes the voucher to
// the agent and the agent does the work. The hub never sees either half.
//
// What this costs is real: the buyer must be able to reach the agent. An
// agent behind a NAT cannot be sold this way, and the endpoint says so
// rather than issuing a voucher that cannot be spent.
//
// What the hub cannot do is worth stating too. It cannot set the price
// and it cannot choose where the buyer goes to collect: both come out of
// the agent's own signed card, and this file re-checks that signature on
// every read rather than trusting the row it stored (see verifiedCard).
// So the worst a hub can do is refuse to sell. It cannot forge a voucher
// for an agent it does not host, because the agent checks the signature
// against the hub it registered with. And it cannot spend a voucher
// twice, because the one-time check belongs to the agent, which is the
// only party that knows whether the work was done.

// voucherWindow is how long a voucher stays spendable.
//
// Short, because it is a bearer object: whoever holds it can have the
// work. Long enough for a buyer to make one more HTTP call to a machine
// that might be slow or far away.
const voucherWindow = 10 * time.Minute

// errUnverifiedCard is the class of failure where this hub holds a card
// for the agent but cannot show that the agent signed the bytes it holds.
//
// Kept distinct from "the agent published no card" because the two say
// different things about who has to act. No card is the agent's omission
// and the buyer is told so with a 404. A card that fails its signature is
// this hub's own copy failing an integrity check — a corrupted row, an
// edited database, or a key rotation that left the stored card
// unattributable — and it answers 5xx so that it reaches whoever runs the
// hub instead of reading to the buyer like a product that is not for
// sale.
var errUnverifiedCard = errors.New("the card this hub stores for this agent does not verify against the agent's key history")

// verifiedCard is a stored agent card whose detached signature this hub
// has re-checked against the agent's own key history.
//
// It is a type rather than a convention because the property being
// protected is negative: nothing in the gateway may read a price or an
// address off a card this hub has not just re-verified. Holding the
// parsed card unexported behind this type is what makes that checkable by
// reading the file — the fields are reachable only through the accessors
// below, and the only constructor is verifyStoredCard.
type verifiedCard struct{ card *adp.AgentCard }

// verifyStoredCard loads an agent's card and re-runs the same admission
// check the card passed when it was registered.
//
// The reason for re-verifying on the read path is that everything the
// gateway quotes — the price, and the address the buyer is sent to —
// comes out of this row. A hub that read the row without checking it
// could edit its own agent_card table and quote any price it liked, or
// point buyers at a machine of its own, and the buyer would have no way
// to notice: what the buyer receives is the hub's own words about the
// card, not the card. Re-verifying removes that: the hub does not hold
// the provider's private key, so an edited card fails the signature and
// the sale stops here rather than completing on terms the provider never
// published.
//
// The cost is one Ed25519 verification plus a KEL replay per quote and
// per settlement, on a path that already does a database read and, when
// paid, a signature verification of its own. It is not cached, because a
// cache keyed on the row would have to be invalidated by the same code
// that is being distrusted.
//
// Two deviations from the register-time call are deliberate:
//
//   - high_water is 0. This is a re-check of a card already admitted, not
//     the admission of a newer one; passing the stored seq would make
//     every card fail its own rollback test.
//   - an adp.DispExpired disposition is accepted. Expiry means the card
//     is older than ADP_CARD_TTL, not that the provider did not sign it,
//     and the invariant enforced here is authorship. Refusing on age
//     would stop selling for every provider that has not re-registered
//     this week, which is an availability decision this endpoint has no
//     standing to make. What it does leave open is that a hub can keep
//     serving an old card the provider has since replaced — a rollback,
//     not a forgery. That is not fixable here: the hub is the party that
//     decides when to accept an update.
func (s *Store) verifyStoredCard(aid string) (verifiedCard, error) {
	raw, err := s.AgentCard(aid)
	if err != nil {
		return verifiedCard{}, err
	}
	if len(raw) == 0 {
		return verifiedCard{}, fmt.Errorf(
			"%s has published no signed card, so this hub cannot quote for it", aid)
	}
	var card adp.AgentCard
	if err := json.Unmarshal(raw, &card); err != nil {
		return verifiedCard{}, fmt.Errorf("%w: %s's card is unreadable: %v", errUnverifiedCard, aid, err)
	}
	// The card must speak for the agent being sold. A signature that
	// verifies is not sufficient on its own: ADP's delegated publish
	// allows signer_aid != subject_did, and its baseline authorization
	// check accepts any non-empty delegation proof, so a card this agent
	// signed can describe another agent's prices and address and still
	// pass the check below. Without this comparison the gateway would
	// quote those terms while naming this agent as the payee.
	if card.SubjectDID != aid {
		return verifiedCard{}, fmt.Errorf("%w: the card filed under %s speaks for %s",
			errUnverifiedCard, aid, card.SubjectDID)
	}
	kelBytes, err := s.AgentKEL(aid)
	if err != nil {
		return verifiedCard{}, fmt.Errorf("%w: %v", errUnverifiedCard, err)
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		return verifiedCard{}, fmt.Errorf("%w: %s's key history is unreadable: %v",
			errUnverifiedCard, aid, err)
	}
	if _, err := adp.AdmitCard(&card, time.Now(), 0, kel, cardMajors, nil); err != nil {
		return verifiedCard{}, fmt.Errorf("%w: %v", errUnverifiedCard, err)
	}
	return verifiedCard{card: &card}, nil
}

// price reads what a capability costs out of the agent's own signed card.
//
// The signature is the point. If the hub set the price, a hub could quote
// anything and settle it — the buyer would have paid, the agent would be
// owed less than was taken, and no party could show it. Reading the
// number from inside the agent's signature means the hub can decline to
// sell but cannot sell at a price the agent never agreed to.
func (v verifiedCard) price(capID string) (uint64, error) {
	aid := v.card.SubjectDID
	prices, ok := v.card.Extensions[ExtPricing].(map[string]any)
	if !ok || len(prices) == 0 {
		return 0, fmt.Errorf("%s publishes no prices, so nothing of its can be bought here", aid)
	}
	p, ok := prices[capID]
	if !ok {
		return 0, fmt.Errorf("%s does not sell %q through a gateway", aid, capID)
	}
	var price uint64
	switch n := p.(type) {
	case float64:
		// 2^64 and above do not convert: uint64(n) of such a float is
		// implementation-defined, and n != float64(uint64(n)) is not a
		// test that catches it on every platform.
		if n < 0 || n >= 1<<64 || n != math.Trunc(n) {
			return 0, fmt.Errorf("%s published a price that is not a whole number of credits", aid)
		}
		price = uint64(n)
	case string:
		v, err := payment.ParseAmount(n)
		if err != nil {
			return 0, err
		}
		price = v
	default:
		return 0, fmt.Errorf("%s published a price this hub cannot read", aid)
	}
	// A price the ledger cannot settle is not one to quote, or to put in
	// a signed voucher. See amountInt64.
	if _, ok := amountInt64(price); !ok {
		return 0, fmt.Errorf("%s published a price of %d, which this hub's ledger cannot settle", aid, price)
	}
	return price, nil
}

// redeemEndpoint is where a buyer takes a voucher for this agent.
//
// Read from the agent's signed card, like the price, and for the same
// reason: a hub that could nominate the address would be able to point
// buyers at a machine of its own choosing, which is the proxying this
// design exists to avoid. Because the provider still collects the credit,
// a redirected buyer pays the provider and receives whatever the
// nominated machine answers, so this field needs the signature as much as
// the price does.
func (v verifiedCard) redeemEndpoint() (string, error) {
	for _, ep := range v.card.Endpoints {
		if ep.Protocol == EndpointRedeem && ep.URI != "" {
			return ep.URI, nil
		}
	}
	return "", fmt.Errorf("%s publishes no public address to redeem a voucher at", v.card.SubjectDID)
}

// ExtPricing is the agent-card extension a provider publishes its price
// list under: capability id → credits. It matches the daemon's constant
// of the same name; the two sides agreeing on this string is what makes
// the gateway able to quote at all.
const ExtPricing = "anet.pricing"

// hX402Resource is the resource server.
//
//	GET /x402/resource/{aid}/{capability}
//
// Without a PAYMENT-SIGNATURE header it answers 402 with the price. With
// one it settles and answers 200 with a voucher. That is the whole
// protocol, and it is x402's: the first response is the quote, the second
// carries the goods — except that here the goods are permission, and the
// work happens somewhere this hub cannot see.
func (s *Server) hX402Resource(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	capID := r.PathValue("capability")
	if aid == "" || capID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "give an agent AID and a capability id"})
		return
	}
	if !s.store.KnowsAgent(aid) {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "this hub does not host " + aid})
		return
	}
	// Both terms of the sale come from this one verified card: quoting a
	// price from a card whose address had not been checked, or the other
	// way round, would leave half the offer unattributable.
	card, err := s.store.verifyStoredCard(aid)
	if err != nil {
		code := http.StatusNotFound
		if errors.Is(err, errUnverifiedCard) {
			code = http.StatusInternalServerError
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	price, err := card.price(capID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	// Where the buyer will have to go. A voucher for an agent that has
	// published no reachable address is one the buyer cannot spend, and
	// selling it would be taking money for nothing.
	endpoint, err := card.redeemEndpoint()
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": err.Error(),
			"hint": "this hub does not proxy work — it sells access and the buyer goes to the agent " +
				"directly, so an agent with no public address cannot be bought here. " +
				"Delegate through the relay instead.",
		})
		return
	}

	required := payment.PaymentRequired{
		X402Version: payment.Version,
		Resource: &payment.Resource{
			URL:         "anet:capability/" + capID + "@" + aid,
			Description: capID + " served by " + aid,
		},
		Accepts: []payment.PaymentOption{{
			Scheme:            payment.SchemeCredit,
			Network:           payment.CreditNetwork(s.hubAID),
			Amount:            payment.Amount(price),
			Asset:             payment.AssetCredit,
			PayTo:             aid,
			MaxTimeoutSeconds: int(voucherWindow / time.Second),
		}},
	}

	sig := strings.TrimSpace(r.Header.Get(payment.HeaderPaymentSignature))
	if sig == "" {
		// The quote. 402 with the terms in a header and in the body: the
		// header is what an x402 client reads, the body is what a person
		// with curl reads, and both should be able to find out the price.
		if enc, err := json.Marshal(required); err == nil {
			w.Header().Set(payment.HeaderPaymentRequired, base64.StdEncoding.EncodeToString(enc))
		}
		writeJSON(w, http.StatusPaymentRequired, map[string]any{
			"x402Version": payment.Version,
			"accepts":     required.Accepts,
			"resource":    required.Resource,
			"redeem_at":   endpoint,
			"how": "sign a payment authorization for these terms and send it back in the " +
				payment.HeaderPaymentSignature + " header. You will get a voucher, not a result: " +
				"take the voucher to redeem_at and the agent does the work. This hub never sees it.",
		})
		return
	}

	var pp payment.PaymentPayload
	rawPayload, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		// Tolerated on purpose: a hand-written client sending raw JSON in
		// the header is doing something reasonable, and refusing it would
		// be pedantry rather than security.
		rawPayload = []byte(sig)
	}
	if err := json.Unmarshal(rawPayload, &pp); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": payment.ReasonMalformed, "detail": err.Error()})
		return
	}
	// The buyer signed some terms. They have to be THESE terms — the
	// payee this hub is selling for and at least the amount that agent
	// published. A settlement that succeeds against a smaller
	// authorization would have the hub issuing a full voucher for a
	// partial payment.
	//
	// These two checks read only the accepted option, which the buyer
	// states and does not sign; they answer an obviously wrong request
	// early and with the price. What is settled is the signed
	// authorization, and SettleWithRequirements compares that with the
	// same terms and with the accepted option. Checking the accepted
	// option alone let a buyer state the price while signing a smaller
	// amount to somebody else (R06 D2).
	if pp.Accepted.PayTo != aid {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "this payment is addressed to " + pp.Accepted.PayTo + ", not to " + aid})
		return
	}
	if got, err := payment.ParseAmount(pp.Accepted.Amount); err != nil || got < price {
		writeJSON(w, http.StatusPaymentRequired, map[string]any{
			"error":   "the price is " + strconv.FormatUint(price, 10) + " credits",
			"accepts": required.Accepts,
		})
		return
	}

	// The requirements are the quote itself: this agent, this price, this
	// hub's ledger. A payment on another ledger is refused here rather
	// than forwarded, because the voucher is this hub's statement that it
	// holds the payment.
	req := required.Accepts[0]
	settled := s.store.SettleWithRequirements(s.hubAID, &pp, &req)
	if enc, err := json.Marshal(settled); err == nil {
		w.Header().Set(payment.HeaderPaymentResponse, base64.StdEncoding.EncodeToString(enc))
	}
	if !settled.Success {
		writeJSON(w, http.StatusPaymentRequired, map[string]any{
			"error": settled.ErrorReason, "detail": settled.Extensions[payment.ExtErrorDetail],
			"accepts": required.Accepts})
		return
	}
	// One settlement buys one voucher. The facilitator answers an
	// authorization it already settled with the original success, at any
	// time (A2A-DESIGN §8.5), so a PAYMENT-SIGNATURE header sent again
	// arrives here again. Signing a new voucher for it would give the buyer
	// a second voucher with a new nonce, and the provider's one-use check,
	// which is keyed on the voucher id, would accept it as unspent: one
	// payment would buy the work once per resend, and buy other
	// capabilities of the same provider as well. A repeat is answered with
	// the voucher issued at the settlement, byte for byte, and only for the
	// capability it bought.
	if settled.Extensions[payment.ExtReplayed] == true {
		s.answerRepeatedPurchase(w, settled, aid, capID, endpoint)
		return
	}
	// The voucher states what was settled, not what was quoted. The two
	// differ when the buyer paid more than the price; a voucher stating
	// the price would then understate what the buyer holds a claim for.
	paid, err := payment.ParseAmount(settled.Amount)
	if err != nil || paid < price {
		// SettleWithRequirements refuses an amount below the price, so this
		// is a settlement response this code did not produce. The buyer
		// has been charged; the transaction id is what it can point at.
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":       "payment settled for " + settled.Amount + " credits, which does not cover the price; no voucher issued",
			"transaction": settled.Transaction,
		})
		return
	}

	voucher, notAfter, err := s.store.issueVoucher(settled, aid, capID, paid)
	if err != nil {
		// Settled and cannot issue. Say so plainly with the transaction
		// id: the buyer has been charged and needs something to point at.
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":       "payment settled but the voucher could not be issued: " + err.Error(),
			"transaction": settled.Transaction,
		})
		return
	}
	// Recorded so that a repeat of this purchase gets these bytes rather
	// than a new voucher. A failure to record is logged and the voucher
	// is still handed over: the buyer has paid for it, and a repeat then
	// finds no record and is refused, so the failure cannot produce a
	// second voucher.
	if err := s.store.recordVoucher(settled.Transaction, aid, capID, voucher, notAfter); err != nil {
		log.Printf("hub: voucher for settlement %s not recorded: %v", settled.Transaction, err)
	}
	writeVoucher(w, voucher, endpoint, capID, aid, settled.Transaction, notAfter)
}

// writeVoucher is the gateway's 200: the voucher and where to spend it.
func writeVoucher(w http.ResponseWriter, voucher, endpoint, capID, aid, transaction string, notAfter int64) {
	writeJSON(w, http.StatusOK, map[string]any{
		"voucher":     voucher,
		"redeem_at":   endpoint,
		"capability":  capID,
		"provider":    aid,
		"transaction": transaction,
		"expires_at":  notAfter,
		"how": "POST {\"voucher\":\"…\",\"capability\":\"" + capID + "\",\"args\":{…}} to redeem_at. " +
			"One use, and this hub cannot tell you whether you have spent it — the agent is the only " +
			"party that knows, which is why the check lives there.",
	})
}

// answerRepeatedPurchase answers a PAYMENT-SIGNATURE whose authorization
// is already settled.
//
// When this gateway issued a voucher for that settlement, and the request
// names the same provider and capability, the answer is that voucher,
// unchanged: the buyer whose first response was lost gets what it paid
// for, and the provider sees one voucher id. Any other repeat is refused
// with 409 and moves nothing. That covers the same authorization offered
// for another capability, and an authorization for which no voucher is
// recorded: one settled through /x402/settle by a merchant on the relay
// path, one settled here whose voucher could not be recorded, and a
// concurrent repeat that arrives before the first request has recorded
// its voucher. The cost of the second case is a buyer who was charged and
// holds no voucher, with the transaction id to show for it; the
// alternative, a second voucher, is a second unit of work for one payment.
func (s *Server) answerRepeatedPurchase(w http.ResponseWriter, settled payment.SettlementResponse,
	aid, capID, endpoint string) {
	rec, found, err := s.store.issuedVoucher(settled.Transaction)
	switch {
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "reading the voucher issued for this payment: " + err.Error(), "transaction": settled.Transaction})
	case !found:
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this payment authorization was already settled, and this gateway issued no voucher for " +
				"that settlement; a voucher is issued only with the settlement that pays for it",
			"transaction": settled.Transaction})
	case rec.payTo != aid || rec.capability != capID:
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this payment authorization already bought " + rec.capability + " from " + rec.payTo +
				"; one payment buys one voucher",
			"transaction": settled.Transaction})
	default:
		writeVoucher(w, rec.voucher, endpoint, capID, aid, settled.Transaction, rec.notAfter)
	}
}

// issuedVoucherRow is the voucher this gateway issued for one settlement.
type issuedVoucherRow struct {
	payTo, capability, voucher string
	notAfter                   int64
}

// migrateGateway creates the record of the voucher issued for each
// settlement the gateway made, keyed on the authorization id so that one
// settlement has at most one voucher.
func (s *Store) migrateGateway() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS gateway_voucher (
		auth_id    TEXT PRIMARY KEY,
		pay_to     TEXT NOT NULL,
		capability TEXT NOT NULL,
		voucher    TEXT NOT NULL,
		not_after  INTEGER NOT NULL,
		at         TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("hub: migrate gateway: %w", err)
	}
	return nil
}

// recordVoucher stores the voucher issued for a settlement. A second
// voucher for the same authorization is refused by the primary key.
func (s *Store) recordVoucher(authID, payTo, capID, voucher string, notAfter int64) error {
	_, err := s.db.Exec(
		`INSERT INTO gateway_voucher(auth_id, pay_to, capability, voucher, not_after, at) VALUES(?,?,?,?,?,?)`,
		authID, payTo, capID, voucher, notAfter, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// issuedVoucher is the voucher recorded for a settlement, if any.
func (s *Store) issuedVoucher(authID string) (issuedVoucherRow, bool, error) {
	var r issuedVoucherRow
	err := s.db.QueryRow(
		`SELECT pay_to, capability, voucher, not_after FROM gateway_voucher WHERE auth_id=?`, authID).
		Scan(&r.payTo, &r.capability, &r.voucher, &r.notAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

// issueVoucher signs the hub's statement that the work is paid for, and
// returns it with its expiry. amount is the settled amount.
func (s *Store) issueVoucher(settled payment.SettlementResponse, payTo, capID string,
	amount uint64) (string, int64, error) {
	if s.hubKey == nil {
		return "", 0, fmt.Errorf("this hub holds no signing key, so it cannot issue vouchers")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", 0, err
	}
	v := &payment.Voucher{
		AuthID:     settled.Transaction,
		Payer:      settled.Payer,
		PayTo:      payTo,
		Capability: capID,
		Amount:     amount,
		Network:    settled.Network,
		NotAfter:   time.Now().Add(voucherWindow).UnixMilli(),
		Nonce:      hex.EncodeToString(nonce[:]),
	}
	if err := v.Sign(s.hubKey); err != nil {
		return "", 0, err
	}
	raw, err := v.Marshal()
	if err != nil {
		return "", 0, err
	}
	return base64.StdEncoding.EncodeToString(raw), v.NotAfter, nil
}

// EndpointRedeem is the endpoint protocol name an agent uses to advertise
// its voucher face.
const EndpointRedeem = "x402-redeem"
