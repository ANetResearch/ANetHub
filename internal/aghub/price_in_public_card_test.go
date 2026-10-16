package aghub_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
)

// Prices are not public in 0.3.0: they travel only in the provider-signed
// extended card, end to end. A public A2A card
// that carries the v0.2 price list (anet-pricing/v1) or the extended
// card's price extension (anet-price/v1) is refused by the hub:
//
//   - registered here: card_status invalid, card_error price_in_public_card;
//     the registration itself stands, and nothing of the card is stored or
//     listed (a card already listed stays as it was);
//   - learned from a peer: the entry is refused for good (not "for now",
//     so the sync moves past it) and nothing of it is kept.
//
// Any other extension, the a2a-x402 declaration a public card makes among
// them, is the provider's business.

const (
	pricingV1URI = "https://agentnetwork.org.cn/a2a/ext/anet-pricing/v1"
	priceV1URI   = "https://agentnetwork.org.cn/a2a/ext/anet-price/v1"
	x402URI      = "https://github.com/google-agentic-commerce/a2a-x402/blob/main/spec/v0.2"
)

// withExtension adds an extension to the card's capabilities.extensions,
// after the anet-card extension.
func withExtension(ext map[string]any) func(map[string]any) {
	return func(card map[string]any) {
		caps := card["capabilities"].(map[string]any)
		caps["extensions"] = append(caps["extensions"].([]any), ext)
	}
}

// priceExtension is a price list for the card's echo skill under uri.
func priceExtension(uri string) map[string]any {
	if uri == pricingV1URI {
		// v0.2's shape: skill id to credits.
		return map[string]any{"uri": uri, "params": map[string]any{"echo": "3"}}
	}
	return map[string]any{"uri": uri, "params": map[string]any{
		"network": "hub:did:anet:some-hub", "asset": "credit",
		"prices": []any{map[string]any{"skillId": "echo", "amount": "3"}},
	}}
}

func TestAPublicCardWithPricesIsRefusedAtRegistration(t *testing.T) {
	for _, uri := range []string{pricingV1URI, priceV1URI} {
		t.Run(uri, func(t *testing.T) {
			srv, store := newHubWithStore(t)
			c, _ := twoAgents(t)
			priced := signA2A(t, c, a2aCardFor(c, 1, withExtension(priceExtension(uri))))
			out := registerA2A(t, srv, c, "Seller", []string{"declared.cap"}, priced)
			if out.Status != "registered" || out.CardStatus != aghub.CardStatusInvalid ||
				out.CardError != aghub.CardErrorPriceInPublicCard {
				t.Fatalf("a public card with prices: %+v", out)
			}
			if l := registry(t, srv, ""); len(l.Agents) != 0 {
				t.Errorf("a refused card is listed: %+v", l.Agents)
			}
			if code, b := getJSON(t, srv.URL+"/a2a/v1/agents/"+c.AID()+"/card"); code != http.StatusNotFound {
				t.Errorf("a refused card is served: %d %s", code, b)
			}
			if n := countRows(t, store, `SELECT COUNT(*) FROM agent_a2a_card WHERE aid=?`, c.AID()); n != 0 {
				t.Errorf("a refused card is stored (%d rows)", n)
			}
			// The registration stands: the agent is in the directory under
			// the name and capabilities it declared.
			if d := directoryEntry(t, srv, "declared.cap", c.AID()); d == nil {
				t.Error("the registration that carried the refused card did not take effect")
			}

			// The same card without the prices is admitted; a priced one
			// after it is refused and leaves it listed.
			plain := signA2A(t, c, a2aCardFor(c, 2))
			if out := registerA2A(t, srv, c, "Seller", nil, plain); out.CardStatus != aghub.CardStatusOK {
				t.Fatalf("the card without prices: %+v", out)
			}
			again := signA2A(t, c, a2aCardFor(c, 3, withExtension(priceExtension(uri))))
			out = registerA2A(t, srv, c, "Seller", nil, again)
			if out.CardStatus != aghub.CardStatusInvalid || out.CardError != aghub.CardErrorPriceInPublicCard {
				t.Fatalf("a priced card after a plain one: %+v", out)
			}
			if l := registry(t, srv, ""); len(l.Agents) != 1 || string(l.Agents[0].Card) != string(plain) {
				t.Errorf("the listed card changed: %+v", l.Agents)
			}
		})
	}
}

// A card that declares a2a-x402 (as a public card with priced skills
// does, §2.6) and an extension of the provider's own are admitted: only the
// two price extensions are refused.
func TestAPublicCardMayDeclareA2AX402(t *testing.T) {
	srv := newHub(t)
	c, _ := twoAgents(t)
	card := signA2A(t, c, a2aCardFor(c, 1,
		withExtension(map[string]any{"uri": x402URI, "required": true}),
		withExtension(map[string]any{"uri": "https://example.org/ext/my-price-notes/v1", "description": "not anet's"})))
	if out := registerA2A(t, srv, c, "Seller", nil, card); out.CardStatus != aghub.CardStatusOK || out.CardError != "" {
		t.Fatalf("a public card declaring a2a-x402: %+v", out)
	}
}

func TestAFederatedPublicCardWithPricesIsRefusedForGood(t *testing.T) {
	for _, uri := range []string{pricingV1URI, priceV1URI} {
		t.Run(uri, func(t *testing.T) {
			peer := openPeerStore(t)
			agent, _ := twoAgents(t)
			priced := signA2A(t, agent, a2aCardFor(agent, 1, withExtension(priceExtension(uri))))
			err := peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, agent, priced))
			if !errors.Is(err, aghub.ErrPriceInPublicCard) {
				t.Fatalf("a peer's public card with prices: %v, want %v", err, aghub.ErrPriceInPublicCard)
			}
			if errors.Is(err, federation.ErrRefusedForNow) {
				t.Error("the refusal holds the sync cursor; a card with prices never becomes admissible")
			}
			if len(fedRegistry(t, peer, aghub.RegistryQuery{})) != 0 {
				t.Error("a refused card is listed")
			}
			if n := countRows(t, peer, `SELECT COUNT(*) FROM fed_a2a_card WHERE aid=?`, agent.AID()); n != 0 {
				t.Errorf("a refused card is stored (%d rows)", n)
			}
			// The same agent's card without prices is admitted.
			if err := peer.AdmitFedA2ACard(homePeerAID, a2aEntry(t, agent, signA2A(t, agent, a2aCardFor(agent, 2)))); err != nil {
				t.Fatalf("the card without prices: %v", err)
			}
		})
	}
}

// countRows runs a COUNT(*) query on a store's database.
func countRows(t *testing.T, st *aghub.Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := st.DBForTest().QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
