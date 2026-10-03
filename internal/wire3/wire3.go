// Package wire3 is the hub side of hub wire 3 that every route shares:
// the X-ANet-Wire negotiation (Contract), the one error body every refusal
// is written with (Refusal, Write), the hub reason codes (reasons.go), the
// strict JSON request decoding (DecodeStrict, ReadStrict) and the U+0000
// check of the text fields that reach a signature or a hash (CheckText).
//
// It sits apart from internal/aghub so that the kernel, the federation
// module and the hub identity endpoint use one implementation without
// importing each other (K207). It imports nothing of this repository.
//
// The contract, in one place:
//
//   - Every hub request carries X-ANet-Wire: 3 and every hub response
//     carries it back.
//   - A caller that declares a newer wire is refused everywhere (400
//     wire_too_new): it may send members this hub would not understand.
//   - A caller that declares an older wire, or none, is refused (426
//     wire_too_old, with required_wire and required_anet) on every route
//     that writes (any method but GET, HEAD and OPTIONS) and on every
//     /relay/* and /fed/* route. Read-only GET routes stay open to browsers
//     and people, and a CORS preflight (OPTIONS) is not asked for it.
//   - An error body is {"reason": <code>, "error": <one English sentence>,
//     …more members}; a refusal that asks the caller to wait carries
//     Retry-After. A daemon branches on reason only; error is shown only
//     for a code it does not know.
//   - A JSON request body is decoded strictly: a member the route does not
//     take, a member given twice, U+0000 in any text, invalid UTF-8,
//     nesting deeper than MaxDepth or anything after the one JSON value is
//     400 bad_request.
package wire3

import (
	"net/http"
	"path"
	"strconv"
	"strings"
)

const (
	// Version is the hub wire contract this hub speaks.
	Version = 3
	// Header carries the wire version on every request and response.
	Header = "X-ANet-Wire"
	// RequiredAnet is the first anet release that speaks Version. A 426
	// names it, so the node's operator knows what to install.
	RequiredAnet = "0.3.0"
)

// versionText is Version as the header value.
var versionText = strconv.Itoa(Version)

// declared is what a request says about its wire version.
type declared int

const (
	declaredCurrent declared = iota // exactly Version
	declaredOlder                   // a smaller number, nothing, or nothing readable
	declaredNewer                   // a larger number
	declaredTwice                   // the header more than once
)

// declaredWire reads X-ANet-Wire. A value that is not a decimal number is
// read as "does not speak this wire", like a missing header: the caller
// is told which wire to speak rather than that its header is malformed.
func declaredWire(r *http.Request) declared {
	vs := r.Header.Values(Header)
	switch {
	case len(vs) == 0:
		return declaredOlder
	case len(vs) > 1:
		return declaredTwice
	}
	v := vs[0]
	if v == "" {
		return declaredOlder
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return declaredOlder
		}
	}
	v = strings.TrimLeft(v, "0")
	if len(v) > 9 { // larger than any int this hub could compare against
		return declaredNewer
	}
	n, _ := strconv.Atoi(v) // "" (all zeros) is 0
	switch {
	case n == Version:
		return declaredCurrent
	case n > Version:
		return declaredNewer
	}
	return declaredOlder
}

// gated reports whether a caller of an older wire is refused here: every
// route that can change something, and the relay and federation planes
// whatever the method.
func gated(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		return true
	}
	p := path.Clean("/" + r.URL.Path)
	for _, plane := range []string{"/relay", "/fed"} {
		if p == plane || strings.HasPrefix(p, plane+"/") {
			return true
		}
	}
	return false
}

// Contract enforces the wire-3 contract in front of next: it stamps
// X-ANet-Wire on every response, refuses a caller of another wire as the
// package comment describes, and refuses U+0000 in the request path, the
// query and the X-ANet-* headers before any handler parses them (CheckRequest).
//
// A CORS preflight (OPTIONS) is not asked for the header: a browser sends
// it without custom headers, and it carries no body. It is refused like
// any other request when it declares a newer wire, the header twice, or
// U+0000.
//
// Applying Contract twice is harmless: the second application sees a
// request the first one let through and decides the same way.
func Contract(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(Header, versionText)
		switch declaredWire(r) {
		case declaredNewer:
			Write(w, Refusal{Reason: ReasonWireTooNew})
			return
		case declaredTwice:
			Write(w, Refusal{Reason: ReasonBadRequest,
				Error: Header + " appears more than once; send it once, with the value " + versionText + "."})
			return
		case declaredOlder:
			if r.Method != http.MethodOptions && gated(r) {
				Write(w, Refusal{Reason: ReasonWireTooOld})
				return
			}
		}
		if err := CheckRequest(r); err != nil {
			RefuseDecode(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Transport returns a RoundTripper that adds X-ANet-Wire: 3 to every
// request that does not carry the header, for the requests this hub makes
// to other hubs (federation): a hub's own requests are hub requests too.
// base nil means http.DefaultTransport.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return stamping{base}
}

type stamping struct{ base http.RoundTripper }

func (s stamping) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get(Header) != "" {
		return s.base.RoundTrip(req)
	}
	// A RoundTripper must not modify the request it is given.
	r2 := req.Clone(req.Context())
	r2.Header.Set(Header, versionText)
	return s.base.RoundTrip(r2)
}
