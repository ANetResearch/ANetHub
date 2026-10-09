package aghub_test

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// publicRoute is one route a request reaches unsigned (most of them need
// no signature; POST /reviews, /agents/{aid}/liability-proof and
// /agents/{aid}/deregister refuse one without it): method and path with
// {aid} standing for a fuzzed or known AID.
type publicRoute struct{ method, path string }

var publicRoutes = []publicRoute{
	{http.MethodPost, "/reviews"},
	{http.MethodGet, "/agents/{aid}"},
	{http.MethodGet, "/agents/{aid}/kel"},
	{http.MethodGet, "/agents/{aid}/liability-proof"},
	{http.MethodGet, "/agents/{aid}/reputation"},
	{http.MethodPost, "/directory:bucket"},
	{http.MethodGet, "/a2a/v1/agents"},
	{http.MethodGet, "/x402/supported"},
	{http.MethodGet, "/x402/supply"},
	{http.MethodGet, "/x402/issuance"},
	{http.MethodGet, "/x402/issuance/head"},
	{http.MethodPost, "/x402/witness"},
	{http.MethodGet, "/x402/witnesses"},
	{http.MethodGet, "/x402/resource/{aid}/work.do"},
	{http.MethodPost, "/federation/clear"},
	{http.MethodGet, "/graph"},
	{http.MethodGet, "/stats"},
	{http.MethodGet, "/healthz"},
	{http.MethodGet, "/llms.txt"},
	{http.MethodPost, "/agents/{aid}/deregister"},
	{http.MethodPost, "/register"},
	{http.MethodOptions, "/relay/send"},
}

// FuzzHubPublicRoutes sends fuzzed bodies, queries and path AIDs to every
// route that a request reaches without a signature, and uploads reviews
// built from a real interaction (evidence v2), signed by the requester, with
// fuzzed ratings, comments and mutations. Properties:
//
//   - no answer is a 5xx;
//   - a review is accepted only when the receipt and the review interlock
//     under the provider's key history and the uploader is the requester
//     the receipt committed to; it is accepted once per interaction; and
//     what the hub stores is what was signed (subject, rating, comment)
//     with the uploader's tag, never the uploader.
func FuzzHubPublicRoutes(f *testing.F) {
	h := newFZ(f)
	prov, _ := h.agent(f, "fuzz-provider", []string{"work.do"}, false)
	req, _ := h.agent(f, "fuzz-reviewer", nil, false)
	stranger, _ := aghub.NewAgentForTest()
	f.Add(uint8(0), "", "", []byte(`{"receipt":"AAAA","review":"AAAA","rsalt":"AAAA"}`), uint8(0), int64(5), "fine", "ix-1")
	f.Add(uint8(0), "", "", []byte(nil), uint8(1), int64(5), "fine", "ix-2")
	f.Add(uint8(0), "", "", []byte(nil), uint8(2), int64(0), "", "ix-3")
	f.Add(uint8(0), "", "", []byte(nil), uint8(3), int64(6), strings.Repeat("长", 600), "ix-4")
	f.Add(uint8(0), "", "", []byte(nil), uint8(4), int64(-1), "x", "ix-5")
	f.Add(uint8(0), "", "", []byte(nil), uint8(5), int64(3), "x", "")
	f.Add(uint8(0), "", "", []byte(nil), uint8(6), int64(4), "", "ix-6")
	f.Add(uint8(0), "", "", []byte(nil), uint8(7), int64(2), "", "ix-7")
	f.Add(uint8(0), "", "", []byte(`{"receipt":"x","review":"y","request_doc":"z"}`), uint8(0), int64(0), "", "")
	for i := range publicRoutes {
		f.Add(uint8(i), "bafyrei-nobody", "from=18446744073709551615&cursor=-1", []byte(`{"attestation":"AAAA","peer_aid":"x","receipt":"AAAA"}`), uint8(0), int64(0), "", "")
	}
	f.Add(uint8(1), "%2e%2e", "", []byte(nil), uint8(0), int64(0), "", "")

	f.Fuzz(func(t *testing.T, route uint8, aid, rawQuery string, body []byte, reviewMode uint8,
		rating int64, comment, ix string) {
		aid, rawQuery, body = clip(aid, 512), clip(rawQuery, 1024), clipB(body, 32<<10)
		comment, ix = clip(comment, 4096), clip(ix, 256)
		rt := publicRoutes[int(route)%len(publicRoutes)]
		if rt.path == "/reviews" && len(body) == 0 {
			fuzzReview(t, h, prov, req, stranger, reviewMode, rating, comment, ix)
			return
		}
		if aid == "" {
			aid = prov.AID()
		}
		path := strings.ReplaceAll(rt.path, "{aid}", url.PathEscape(aid))
		rec := h.serve(h.request(rt.method, path, rawQuery, body))
		if rec.Code >= 500 {
			t.Fatalf("%s %s?%s: %d %s", rt.method, path, rawQuery, rec.Code, rec.Body.Bytes())
		}
		if rt.path == "/agents/{aid}/deregister" && rec.Code == http.StatusOK {
			t.Fatalf("an unsigned deregister was accepted")
		}
		if rt.path == "/register" && rec.Code == http.StatusOK {
			t.Fatalf("an unsigned registration was accepted")
		}
	})
}

// fuzzReview uploads one review of a real interaction between prov and
// req, changed as mode says, and checks what the hub did with it.
func fuzzReview(t *testing.T, h *fz, prov, req, stranger *identity.Controller, mode uint8, rating int64,
	comment, ix string) {
	t.Helper()
	ix = strings.ToValidUTF8(strings.ReplaceAll(ix, "\x00", ""), "?") + "-" + h.nonce()
	comment = strings.ToValidUTF8(comment, "?")
	provider, reviewer := prov, req
	switch mode % 8 {
	case 1:
		provider = stranger // the provider is unknown here
	case 2:
		reviewer = stranger // the uploader is not registered here
	case 4:
		provider, reviewer = req, prov // roles swapped: still a real interaction
	}
	k := aghub.NewReviewKitForTest(t, provider, reviewer, ix, uint64(rating%1000))
	k.Review.Comment = comment
	switch mode % 8 {
	case 3:
		k.Review.Subject = req.AID() // the review names someone other than the provider
		if provider == req {
			k.Review.Subject = prov.AID()
		}
	case 6:
		k.RSalt = bytes.Repeat([]byte{7}, evidence.RSaltSize) // not the salt the receipt committed to
	case 7:
		k.Review.CreatedDay = k.Receipt.CompletedDay + aghub.ReviewWindowDays + 1
	}
	if rating < 1 || rating > 5 || len([]rune(comment)) > evidence.MaxCommentChars {
		t.Skip() // no review body can be signed with these
	}
	body := k.Body(t)
	if mode%8 == 5 {
		raw := []byte(body["review"])
		raw[len(raw)/2] ^= 1
		body["review"] = string(raw)
	}
	raw := fzJSON(t, body)
	rec := h.signedDo(reviewer, relayauth.ActionReview, http.MethodPost, "/reviews", "", raw)
	if !allowed(rec.Code, 200, 400, 401, 403, 409) {
		t.Fatalf("review: unexpected %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec.Code != http.StatusOK {
		return
	}
	// Accepted: the provider is known here, the objects interlock under
	// its key history, and the uploader is the requester.
	pk, err := h.store.AgentKEL(provider.AID())
	if err != nil {
		t.Fatalf("a review of an interaction with an unregistered provider %s was accepted", provider.AID())
	}
	pkel, _ := identity.UnmarshalKEL(pk)
	rcB, rvB := k.Wires(t)
	rcw, _ := evidence.UnmarshalReceiptWire(rcB)
	rvw, err := evidence.UnmarshalReviewWire(rvB)
	if err != nil {
		t.Fatalf("an undecodable review was accepted: %v", err)
	}
	if _, _, err := evidence.CheckV2(rcw, rvw, pkel); err != nil {
		t.Fatalf("a review that does not interlock was accepted: %v", err)
	}
	if mode%8 == 6 || mode%8 == 7 {
		t.Fatalf("mode %d was accepted", mode%8)
	}
	var stored struct {
		Subject, Comment string
		Rating           uint64
		Tag              []byte
	}
	if err := h.db.QueryRow(`SELECT subject_aid, rating, comment, tag FROM review WHERE ix_commit=?`, k.IXCommit()).
		Scan(&stored.Subject, &stored.Rating, &stored.Comment, &stored.Tag); err != nil {
		t.Fatalf("accepted review not stored: %v", err)
	}
	key, _, err := h.store.ReviewTagKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	tag, _ := aghub.ReviewTagForTest(key, reviewer.AID(), k.Review.Subject)
	if stored.Subject != k.Review.Subject || stored.Rating != k.Review.Rating || stored.Comment != k.Review.Comment ||
		!bytes.Equal(stored.Tag, tag) {
		t.Fatalf("stored %+v, signed %+v", stored, k.Review)
	}
	again := h.signedDo(reviewer, relayauth.ActionReview, http.MethodPost, "/reviews", "", raw)
	if again.Code != http.StatusConflict {
		t.Fatalf("the same review again: %d %s, want 409 review_exists", again.Code, again.Body.Bytes())
	}
}
