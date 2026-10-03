package wire3

import (
	"net/http"
	"net/url"
	"strings"
)

// U+0000 in text fields (core CORE-E9).
//
// Several hashes and signatures (relayauth, the session MAC, the review
// tag, the settlement guard, …) join variable-length text fields with a
// 0x00 byte, and rely on no field containing one: otherwise ("a\0b", "c")
// and ("a", "b\0c") would hash alike. So no AID, method or path a hub
// accepts may contain U+0000, and the check is made where the value is
// decoded, before anything is verified or computed from it:
//
//   - the request path (and with it every {aid} path value) and the query,
//     and every X-ANet-* header (X-ANet-AID, X-ANet-Home, …): Contract,
//     through CheckRequest, before any handler runs;
//   - every text in a JSON request body: DecodeStrict;
//   - any other text the hub decodes itself (a CBOR text field, a value
//     taken from a binary body): the handler calls CheckText.
//
// Each is a 400 bad_request. The functions that build those preimages
// refuse such input too; that is the second line, not this one.

// CheckText returns a *DecodeError when s contains U+0000. name says
// where s came from (a member name, "X-ANet-Home", "path"); it is quoted
// in the error sentence.
func CheckText(name, s string) error {
	if strings.IndexByte(s, 0) >= 0 {
		return &DecodeError{Kind: KindNUL, Member: name}
	}
	return nil
}

// CheckRequest returns a *DecodeError when the request's path, its query
// (decoded) or an X-ANet-* header contains U+0000.
func CheckRequest(r *http.Request) error {
	// Path is the decoded path, the one {aid} path values come from.
	if err := CheckText("path", r.URL.Path); err != nil {
		return err
	}
	if q := r.URL.RawQuery; q != "" {
		dq, err := url.QueryUnescape(q)
		if err != nil {
			// Not decodable as a whole: still refuse an escaped NUL in it.
			dq = strings.ReplaceAll(strings.ToLower(q), "%00", "\x00")
		}
		if err := CheckText("query", dq); err != nil {
			return err
		}
	}
	for name, vs := range r.Header {
		if !strings.HasPrefix(strings.ToLower(name), "x-anet-") {
			continue
		}
		for _, v := range vs {
			if err := CheckText(headerName(name), v); err != nil {
				return err
			}
		}
	}
	return nil
}

// headerSpelling is how core §2.12.1 spells the X-ANet-* headers, for a
// sentence that names one (the request carries the canonical form,
// X-Anet-Aid).
var headerSpelling = map[string]string{}

func init() {
	for _, h := range []string{"X-ANet-Wire", "X-ANet-AID", "X-ANet-TS", "X-ANet-Seq", "X-ANet-Sig",
		"X-ANet-Access", "X-ANet-Session", "X-ANet-MAC", "X-ANet-Home", "X-ANet-TS-Floor"} {
		headerSpelling[http.CanonicalHeaderKey(h)] = h
	}
}

func headerName(name string) string {
	if s, ok := headerSpelling[http.CanonicalHeaderKey(name)]; ok {
		return s
	}
	return http.CanonicalHeaderKey(name)
}
