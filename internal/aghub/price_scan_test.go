package aghub_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// Neither the registry nor hub.db holds a price (0.3.0 removed the public
// prices): /register and /profile take no pricing member (and
// /register no ADP card), no response of the public registry names one, no
// table has a price column or holds the ADP cards, the vouchers or the
// public price list, and a card refused for its prices leaves none of its
// bytes on disk.
func TestNoPriceInTheRegistryOrTheDatabase(t *testing.T) {
	srv, store, _, dir := hubInDir(t)
	seller, other := twoAgents(t)
	card := signA2A(t, seller, a2aCardFor(seller, 1))
	if out := registerA2A(t, srv, seller, "Seller", []string{"echo"}, card); out.CardStatus != aghub.CardStatusOK {
		t.Fatalf("register: %+v", out)
	}
	setVisibility(t, srv, seller, aghub.VisibilityPublic)
	if code, b := signedDo(t, srv, seller, relayauth.ActionProfile, http.MethodPost, "/profile",
		map[string]any{"aid": seller.AID(), "summary": "Echoes text.", "readme": "Send text, get it back."}); code != http.StatusOK {
		t.Fatalf("profile: %d %s", code, b)
	}

	// The members that carried prices and the ADP card are refused as any
	// member a route does not take is (CORE-E7).
	for _, c := range []struct {
		name, path, action string
		body               map[string]any
	}{
		{"/profile pricing", "/profile", relayauth.ActionProfile,
			map[string]any{"aid": seller.AID(), "summary": "s", "readme": "r", "pricing": "3 credits a call"}},
		{"/register pricing", "/register", relayauth.ActionRegister,
			withMember(registerBody(t, seller, "Seller", nil), "pricing", "3 credits a call")},
		{"/register card", "/register", relayauth.ActionRegister,
			withMember(registerBody(t, seller, "Seller", nil), "card", map[string]any{"subject_did": seller.AID()})},
	} {
		code, b := signedDo(t, srv, seller, c.action, http.MethodPost, c.path, c.body)
		var out struct{ Reason, Error string }
		_ = json.Unmarshal(b, &out)
		if code != http.StatusBadRequest || out.Reason != "bad_request" || !strings.Contains(out.Error, "remove it") {
			t.Errorf("%s: %d %s, want 400 bad_request naming the member", c.name, code, b)
		}
	}

	// A card refused for its prices.
	admitForTest(t, srv, other.AID())
	priced := signA2A(t, other, a2aCardFor(other, 1, withExtension(priceExtension(priceV1URI)),
		withExtension(priceExtension(pricingV1URI))))
	if out := registerA2A(t, srv, other, "Other", nil, priced); out.CardError != aghub.CardErrorPriceInPublicCard {
		t.Fatalf("a priced card: %+v", out)
	}

	// No public answer names a price.
	for _, p := range []string{"/agents", "/agents?cap=echo", "/agents/" + seller.AID(), "/a2a/v1/agents",
		"/a2a/v1/agents?skill=echo", "/a2a/v1/agents/" + seller.AID() + "/card", "/graph", "/stats"} {
		code, b := getJSON(t, srv.URL+p)
		if code != http.StatusOK {
			t.Errorf("GET %s: %d %s", p, code, b)
			continue
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Errorf("GET %s: not JSON: %s", p, b)
			continue
		}
		for _, k := range jsonKeys(v) {
			if strings.Contains(strings.ToLower(k), "pric") {
				t.Errorf("GET %s names %q: %s", p, k, b)
			}
		}
		for _, s := range []string{"anet-price", "anet-pricing", "anet.pricing"} {
			if strings.Contains(string(b), s) {
				t.Errorf("GET %s carries %q: %s", p, s, b)
			}
		}
	}

	// No table holds a price, an ADP card or a voucher.
	db := store.DBForTest()
	rows, err := db.Query(`SELECT m.name, p.name FROM sqlite_master m JOIN pragma_table_info(m.name) p
	                        WHERE m.type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	tables := map[string]bool{}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		tables[table] = true
		if strings.Contains(strings.ToLower(column), "pric") {
			t.Errorf("hub.db: %s.%s", table, column)
		}
	}
	rows.Close()
	for _, gone := range []string{"agent_card", "fed_card", "gateway_voucher"} {
		if tables[gone] {
			t.Errorf("hub.db still has the table %s", gone)
		}
	}
	for name := range tables {
		if strings.Contains(name, "pric") || strings.Contains(name, "voucher") {
			t.Errorf("hub.db has the table %s", name)
		}
	}
	// Nothing of the refused card reached the disk (hub.db, its WAL).
	for _, needle := range []string{"anet-price/v1", "anet-pricing/v1", "did:anet:some-hub"} {
		if hits := filesContaining(t, dir, []byte(needle)); len(hits) > 0 {
			t.Errorf("%q is on disk: %v", needle, hits)
		}
	}
}

// withMember returns body with one more member.
func withMember(body map[string]any, k string, v any) map[string]any {
	body[k] = v
	return body
}

// jsonKeys lists every object member name in v, at any depth.
func jsonKeys(v any) []string {
	var out []string
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			out = append(out, k)
			out = append(out, jsonKeys(e)...)
		}
	case []any:
		for _, e := range x {
			out = append(out, jsonKeys(e)...)
		}
	}
	return out
}
