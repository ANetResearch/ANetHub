package aghub

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/adp"
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
// What the hub cannot do is worth stating too. It cannot set the price —
// that comes out of the agent's own signed card, so the worst a hub can
// do is refuse to sell. It cannot forge a voucher for an agent it does
// not host, because the agent checks the signature against the hub it
// registered with. And it cannot spend a voucher twice, because the
// one-time check belongs to the agent, which is the only party that knows
// whether the work was done.

// voucherWindow is how long a voucher stays spendable.
//
// Short, because it is a bearer object: whoever holds it can have the
// work. Long enough for a buyer to make one more HTTP call to a machine
// that might be slow or far away.
const voucherWindow = 10 * time.Minute

// gatewayPrice reads what a capability costs out of the agent's own
// signed card.
//
// The signature is the point. If the hub set the price, a hub could quote
// anything and settle it — the buyer would have paid, the agent would be
// owed less than was taken, and no party could show it. Reading the
// number from inside the agent's signature means the hub can decline to
// sell but cannot sell at a price the agent never agreed to.
func (s *Store) gatewayPrice(aid, capID string) (uint64, error) {
	raw, err := s.AgentCard(aid)
	if err != nil {
		return 0, err
	}
	if len(raw) == 0 {
		return 0, fmt.Errorf("%s has published no signed card, so this hub cannot quote a price for it", aid)
	}
	var card adp.AgentCard
	if err := json.Unmarshal(raw, &card); err != nil {
		return 0, fmt.Errorf("%s's card is unreadable: %w", aid, err)
	}
	prices, ok := card.Extensions[ExtPricing].(map[string]any)
	if !ok || len(prices) == 0 {
		return 0, fmt.Errorf("%s publishes no prices, so nothing of its can be bought here", aid)
	}
	v, ok := prices[capID]
	if !ok {
		return 0, fmt.Errorf("%s does not sell %q through a gateway", aid, capID)
	}
	switch n := v.(type) {
	case float64:
		if n < 0 || n != float64(uint64(n)) {
			return 0, fmt.Errorf("%s published a price that is not a whole number of credits", aid)
		}
		return uint64(n), nil
	case string:
		return payment.ParseAmount(n)
	default:
		return 0, fmt.Errorf("%s published a price this hub cannot read", aid)
	}
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
	price, err := s.store.gatewayPrice(aid, capID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	// Where the buyer will have to go. A voucher for an agent that has
	// published no reachable address is one the buyer cannot spend, and
	// selling it would be taking money for nothing.
	endpoint, err := s.store.redeemEndpoint(aid)
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
	// payee this hub is selling for and the amount that agent published.
	// A settlement that succeeds against a smaller authorization would
	// have the hub issuing a full voucher for a partial payment.
	if pp.Accepted.PayTo != aid {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "this payment is addressed to " + pp.Accepted.PayTo + ", not to " + aid})
		return
	}
	if got, err := payment.ParseAmount(pp.Accepted.Amount); err != nil || got != price {
		writeJSON(w, http.StatusPaymentRequired, map[string]any{
			"error":   "the price is " + strconv.FormatUint(price, 10) + " credits",
			"accepts": required.Accepts,
		})
		return
	}

	settled := s.store.SettlePayment(s.hubAID, &pp)
	if enc, err := json.Marshal(settled); err == nil {
		w.Header().Set(payment.HeaderPaymentResponse, base64.StdEncoding.EncodeToString(enc))
	}
	if !settled.Success {
		writeJSON(w, http.StatusPaymentRequired, map[string]any{
			"error": settled.ErrorReason, "accepts": required.Accepts})
		return
	}

	voucher, err := s.store.issueVoucher(settled, aid, capID, price)
	if err != nil {
		// Settled and cannot issue. Say so plainly with the transaction
		// id: the buyer has been charged and needs something to point at.
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":       "payment settled but the voucher could not be issued: " + err.Error(),
			"transaction": settled.Transaction,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"voucher":     voucher,
		"redeem_at":   endpoint,
		"capability":  capID,
		"provider":    aid,
		"transaction": settled.Transaction,
		"expires_at":  time.Now().Add(voucherWindow).UnixMilli(),
		"how": "POST {\"voucher\":\"…\",\"capability\":\"" + capID + "\",\"args\":{…}} to redeem_at. " +
			"One use, and this hub cannot tell you whether you have spent it — the agent is the only " +
			"party that knows, which is why the check lives there.",
	})
}

// issueVoucher signs the hub's statement that the work is paid for.
func (s *Store) issueVoucher(settled payment.SettlementResponse, payTo, capID string,
	price uint64) (string, error) {
	if s.hubKey == nil {
		return "", fmt.Errorf("this hub holds no signing key, so it cannot issue vouchers")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	v := &payment.Voucher{
		AuthID:     settled.Transaction,
		Payer:      settled.Payer,
		PayTo:      payTo,
		Capability: capID,
		Amount:     price,
		Network:    settled.Network,
		NotAfter:   time.Now().Add(voucherWindow).UnixMilli(),
		Nonce:      hex.EncodeToString(nonce[:]),
	}
	if err := v.Sign(s.hubKey); err != nil {
		return "", err
	}
	raw, err := v.Marshal()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// redeemEndpoint is where a buyer takes a voucher for this agent.
//
// Read from the agent's signed card, like the price, and for the same
// reason: a hub that could nominate the address would be able to point
// buyers at a machine of its own choosing, which is the proxying this
// design exists to avoid.
func (s *Store) redeemEndpoint(aid string) (string, error) {
	raw, err := s.AgentCard(aid)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("%s has published no signed card", aid)
	}
	var card adp.AgentCard
	if err := json.Unmarshal(raw, &card); err != nil {
		return "", err
	}
	for _, ep := range card.Endpoints {
		if ep.Protocol == EndpointRedeem && ep.URI != "" {
			return ep.URI, nil
		}
	}
	return "", fmt.Errorf("%s publishes no public address to redeem a voucher at", aid)
}

// EndpointRedeem is the endpoint protocol name an agent uses to advertise
// its voucher face.
const EndpointRedeem = "x402-redeem"
