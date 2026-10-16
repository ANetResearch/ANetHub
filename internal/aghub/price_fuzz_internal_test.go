package aghub

import (
	"encoding/json"
	"testing"
)

// carriesPricesByWalk is carriesPrices written another way: the card
// decoded whole and walked, member names compared exactly.
func carriesPricesByWalk(card []byte) bool {
	var top any
	if json.Unmarshal(card, &top) != nil {
		return false
	}
	obj, _ := top.(map[string]any)
	caps, _ := obj["capabilities"].(map[string]any)
	exts, _ := caps["extensions"].([]any)
	for _, x := range exts {
		e, _ := x.(map[string]any)
		if uri, ok := e["uri"].(string); ok && (uri == extPricingV1URI || uri == extPriceV1URI) {
			return true
		}
	}
	return false
}

// FuzzCarriesPrices feeds carriesPrices arbitrary bytes, card-shaped or
// not. Properties: no panic, and the answer is the one a whole-document
// walk gives, so neither a member spelled in another case, a duplicate, an
// escape nor a non-object entry makes a price extension go unseen or a
// card without one read as priced.
func FuzzCarriesPrices(f *testing.F) {
	for _, s := range []string{
		`{"capabilities":{"extensions":[{"uri":"https://agentnetwork.org.cn/a2a/ext/anet-card/v1","params":{}}]}}`,
		`{"capabilities":{"extensions":[{"uri":"https://agentnetwork.org.cn/a2a/ext/anet-card/v1"},{"uri":"https://agentnetwork.org.cn/a2a/ext/anet-price/v1","params":{"prices":[]}}]}}`,
		`{"capabilities":{"extensions":[{"uri":"https:\/\/agentnetwork.org.cn\/a2a\/ext\/anet-pricing\/v1"}]}}`,
		`{"Capabilities":{"extensions":[{"uri":"https://agentnetwork.org.cn/a2a/ext/anet-price/v1"}]}}`,
		`{"capabilities":{"extensions":[1,"x",null,{"uri":"https://agentnetwork.org.cn/a2a/ext/anet-price/v1"}]}}`,
		`{"capabilities":{"extensions":[{"uri":"https://agentnetwork.org.cn/a2a/ext/anet-price/v1"}]},"capabilities":{}}`,
		`{"capabilities":{"extensions":[{"uri":7}]}}`,
		`[]`, `null`, ``, `{`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, card []byte) {
		if got, want := carriesPrices(card), carriesPricesByWalk(card); got != want {
			t.Fatalf("carriesPrices(%q) = %v, a whole-document walk says %v", card, got, want)
		}
	})
}
