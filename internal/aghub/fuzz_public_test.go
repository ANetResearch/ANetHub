package aghub_test

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
)

// publicRoute is one unauthenticated route: method and path with {aid}
// standing for a fuzzed or known AID.
type publicRoute struct{ method, path string }

var publicRoutes = []publicRoute{
	{http.MethodPost, "/reviews"},
	{http.MethodGet, "/agents/{aid}"},
	{http.MethodGet, "/agents/{aid}/kel"},
	{http.MethodGet, "/agents/{aid}/card"},
	{http.MethodGet, "/agents/{aid}/reputation"},
	{http.MethodGet, "/agents/{aid}/p2p"},
	{http.MethodGet, "/p2p/peers"},
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
// route that needs no signature, and posts reviews built from a real
// interaction with fuzzed ratings, comments and mutations. Properties:
//
//   - no answer is a 5xx;
//   - a review is accepted only when the receipt and review interlock and
//     both signers are known here, it is accepted once per interaction,
//     and what the hub stores is what was signed (subject, reviewer,
//     rating).
func FuzzHubPublicRoutes(f *testing.F) {
	h := newFZ(f)
	prov, _ := h.agent(f, "fuzz-provider", []string{"work.do"}, false)
	req, _ := h.agent(f, "fuzz-reviewer", nil, false)
	stranger, _ := identity.Incept()
	f.Add(uint8(0), "", "", []byte(`{"receipt":"AAAA","review":"AAAA"}`), uint8(0), int64(5), "fine", "ix-1")
	f.Add(uint8(0), "", "", []byte(nil), uint8(1), int64(5), "fine", "ix-2")
	f.Add(uint8(0), "", "", []byte(nil), uint8(2), int64(0), "", "ix-3")
	f.Add(uint8(0), "", "", []byte(nil), uint8(3), int64(6), strings.Repeat("长", 600), "ix-4")
	f.Add(uint8(0), "", "", []byte(nil), uint8(4), int64(-1), "x", "ix-5")
	f.Add(uint8(0), "", "", []byte(nil), uint8(5), int64(3), "x", "")
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
	ix = strings.ToValidUTF8(ix, "?") + "-" + h.nonce()
	comment = strings.ToValidUTF8(comment, "?")
	reqCID, _ := anetcid.Sum([]byte("request " + ix))
	resCID, _ := anetcid.Sum([]byte("result " + ix))
	provider, reviewer, subject := prov, req, prov.AID()
	switch mode % 6 {
	case 1:
		provider = stranger // the provider is unknown here
	case 2:
		reviewer = stranger // the reviewer is unknown here
	case 3:
		subject = req.AID() // the review names someone other than the provider
	case 4:
		provider, reviewer = req, prov // roles swapped: still a real interaction
		subject = req.AID()
	}
	rc := &evidence.Receipt{InteractionID: ix, RequesterAID: reviewer.AID(), ProviderAID: provider.AID(),
		RequestCID: reqCID, ResultCID: resCID, CompletedAt: 1000}
	if err := rc.Sign(provider); err != nil {
		t.Fatal(err)
	}
	rcid, _ := rc.CID()
	rv := &evidence.Review{InteractionID: ix, SubjectAID: subject, ReviewerAID: reviewer.AID(),
		Rating: int(rating % 1000), Comment: comment, ReceiptCID: rcid, CreatedAt: 2000}
	if err := rv.Sign(reviewer); err != nil {
		t.Skip()
	}
	rcB, _ := rc.Marshal()
	rvB, _ := rv.Marshal()
	if mode%6 == 5 && len(rvB) > 0 {
		rvB[len(rvB)/2] ^= 1
	}
	body := fzJSON(t, map[string]string{
		"receipt": base64.StdEncoding.EncodeToString(rcB), "review": base64.StdEncoding.EncodeToString(rvB)})
	rec := h.serve(h.request(http.MethodPost, "/reviews", "", body))
	if !allowed(rec.Code, 200, 400, 409) {
		t.Fatalf("review: unexpected %d %s", rec.Code, rec.Body.Bytes())
	}
	if rec.Code != http.StatusOK {
		return
	}
	// Accepted: it must interlock against the KELs the hub holds, and be
	// stored as signed.
	pk, err := h.store.AgentKEL(rc.ProviderAID)
	if err != nil {
		t.Fatalf("a review of an interaction with an unregistered provider %s was accepted", rc.ProviderAID)
	}
	rk, err := h.store.AgentKEL(rv.ReviewerAID)
	if err != nil {
		t.Fatalf("a review by an unregistered reviewer was accepted")
	}
	pkel, _ := identity.UnmarshalKEL(pk)
	rkel, _ := identity.UnmarshalKEL(rk)
	grc, _ := evidence.UnmarshalReceipt(rcB)
	grv, err := evidence.UnmarshalReview(rvB)
	if err != nil {
		t.Fatalf("an undecodable review was accepted: %v", err)
	}
	if err := evidence.VerifyInterlock(grc, grv, nil, nil, pkel, rkel); err != nil {
		t.Fatalf("a review that does not interlock was accepted: %v", err)
	}
	var stored struct {
		Subject, Reviewer string
		Rating            int
	}
	if err := h.db.QueryRow(`SELECT subject_aid, reviewer_aid, rating FROM review WHERE interaction_id=?`, ix).
		Scan(&stored.Subject, &stored.Reviewer, &stored.Rating); err != nil {
		t.Fatalf("accepted review not stored: %v", err)
	}
	if stored.Subject != grv.SubjectAID || stored.Reviewer != grv.ReviewerAID || stored.Rating != grv.Rating {
		t.Fatalf("stored %+v, signed %+v", stored, grv)
	}
	again := h.serve(h.request(http.MethodPost, "/reviews", "", body))
	if again.Code == http.StatusOK {
		t.Fatalf("the same review was accepted twice")
	}

}
