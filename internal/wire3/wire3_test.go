package wire3

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ok is a handler that answers 200 and records that it ran.
type ok struct{ ran bool }

func (h *ok) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.ran = true
	w.WriteHeader(http.StatusOK)
}

func serve(h http.Handler, method, target string, hdr map[string][]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func reasonOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("not a G1 body: %s", rec.Body)
	}
	return b.Reason
}

func TestDeclaredWire(t *testing.T) {
	for v, want := range map[string]declared{
		"3": declaredCurrent, "03": declaredCurrent, "0003": declaredCurrent,
		"2": declaredOlder, "0": declaredOlder, "000": declaredOlder, "1": declaredOlder,
		"4": declaredNewer, "99": declaredNewer, "1000000000": declaredNewer,
		"99999999999999999999999": declaredNewer,
		"":                        declaredOlder, "two": declaredOlder, "-1": declaredOlder, "+3": declaredOlder,
		"3.0": declaredOlder, " 3": declaredOlder, "3 ": declaredOlder, "3,3": declaredOlder,
		"0x3": declaredOlder, "３": declaredOlder,
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header["X-Anet-Wire"] = []string{v}
		if got := declaredWire(req); got != want {
			t.Errorf("X-ANet-Wire %q: %v, want %v", v, got, want)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if declaredWire(req) != declaredOlder {
		t.Error("a missing header is an older wire")
	}
	req.Header.Add(Header, "3")
	req.Header.Add(Header, "3")
	if declaredWire(req) != declaredTwice {
		t.Error("a repeated header is not read as one value")
	}
}

func TestGated(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"POST", "/register", true}, {"POST", "/x402/settle", true}, {"PUT", "/agents", true},
		{"DELETE", "/agents/x", true}, {"PATCH", "/", true},
		{"GET", "/relay/poll", true}, {"GET", "/relay", true}, {"HEAD", "/relay/x", true},
		{"GET", "/fed/v3/cards", true}, {"GET", "/fed", true}, {"GET", "//fed/v3/cards", true},
		{"GET", "/relay/../fed/x", true}, {"GET", "/a/../relay/send", true},
		{"GET", "/agents", false}, {"GET", "/hub/identity", false}, {"HEAD", "/stats", false},
		{"GET", "/relayx", false}, {"GET", "/federation/clear", false}, {"GET", "/", false},
	} {
		req := httptest.NewRequest(tc.method, "/", nil)
		req.URL.Path = tc.path
		if got := gated(req); got != tc.want {
			t.Errorf("%s %s: gated %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

// CORE-V1, route by route.
func TestContractNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name, method, path string
		wire               []string
		status             int
		reason             string
	}{
		{"current POST", "POST", "/register", []string{"3"}, 200, ""},
		{"current GET relay", "GET", "/relay/x", []string{"3"}, 200, ""},
		{"missing POST", "POST", "/register", nil, 426, "wire_too_old"},
		{"older POST", "POST", "/register", []string{"2"}, 426, "wire_too_old"},
		{"garbage POST", "POST", "/register", []string{"three"}, 426, "wire_too_old"},
		{"missing relay GET", "GET", "/relay/poll", nil, 426, "wire_too_old"},
		{"older fed GET", "GET", "/fed/v3/cards", []string{"2"}, 426, "wire_too_old"},
		{"missing read GET", "GET", "/agents", nil, 200, ""},
		{"older read GET", "GET", "/stats", []string{"2"}, 200, ""},
		{"garbage read GET", "GET", "/stats", []string{"x"}, 200, ""},
		{"missing HEAD", "HEAD", "/stats", nil, 200, ""},
		{"newer POST", "POST", "/register", []string{"4"}, 400, "wire_too_new"},
		{"newer read GET", "GET", "/agents", []string{"99"}, 400, "wire_too_new"},
		{"twice", "GET", "/agents", []string{"3", "3"}, 400, "bad_request"},
		{"twice, different", "POST", "/register", []string{"3", "2"}, 400, "bad_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := &ok{}
			rec := serve(Contract(next), tc.method, tc.path, map[string][]string{Header: tc.wire})
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d (%s)", rec.Code, tc.status, rec.Body)
			}
			if got := rec.Header().Values(Header); len(got) != 1 || got[0] != "3" {
				t.Errorf("%s on the response: %q", Header, got)
			}
			if tc.reason == "" {
				if !next.ran {
					t.Error("the handler did not run")
				}
				return
			}
			if next.ran {
				t.Error("a refused request reached the handler")
			}
			if got := reasonOf(t, rec); got != tc.reason {
				t.Errorf("reason %s, want %s", got, tc.reason)
			}
		})
	}
}

// A CORS preflight carries no custom header and no body: it is passed on,
// and still answered with the wire header.
func TestContractPassesPreflight(t *testing.T) {
	next := &ok{}
	rec := serve(Contract(next), http.MethodOptions, "/relay/send", nil)
	if !next.ran || rec.Code != 200 || rec.Header().Get(Header) != "3" {
		t.Fatalf("%d %v %q", rec.Code, next.ran, rec.Header().Get(Header))
	}
}

// The header is on every response, including the handler's own errors.
func TestContractStampsEveryResponse(t *testing.T) {
	h := Contract(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusTeapot)
	}))
	rec := serve(h, http.MethodGet, "/agents", nil)
	if rec.Code != http.StatusTeapot || rec.Header().Get(Header) != "3" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get(Header))
	}
}

// Wrapping twice decides the same way as wrapping once.
func TestContractTwice(t *testing.T) {
	next := &ok{}
	h := Contract(Contract(next))
	if rec := serve(h, "POST", "/register", map[string][]string{Header: {"3"}}); rec.Code != 200 || !next.ran {
		t.Fatalf("%d", rec.Code)
	}
	rec := serve(h, "POST", "/register", nil)
	if rec.Code != 426 || len(rec.Header().Values(Header)) != 1 {
		t.Fatalf("%d %q", rec.Code, rec.Header().Values(Header))
	}
}

// CORE-E9 at the door: U+0000 in the path, the query or an X-ANet-*
// header is 400 bad_request before any handler runs, on read-only routes
// too.
func TestContractRefusesNUL(t *testing.T) {
	for _, tc := range []struct {
		name, method, target string
		hdr                  map[string][]string
	}{
		{"path aid", "GET", "/agents/%00/kel", nil},
		{"path middle", "GET", "/agents/bafy%00rei", nil},
		{"query", "GET", "/fed/v3/reviews?cursor=%00", map[string][]string{Header: {"3"}}},
		{"query, bad escape", "GET", "/agents?q=%zz%00", nil},
		{"X-ANet-AID", "POST", "/relay/poll", map[string][]string{Header: {"3"}, "X-ANet-AID": {"bafy\x00x"}}},
		{"X-ANet-Home", "POST", "/relay/send", map[string][]string{Header: {"3"}, "X-ANet-Home": {"\x00"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := &ok{}
			rec := serve(Contract(next), tc.method, tc.target, tc.hdr)
			if rec.Code != 400 || next.ran {
				t.Fatalf("status %d, handler ran %v", rec.Code, next.ran)
			}
			if got := reasonOf(t, rec); got != "bad_request" {
				t.Fatalf("reason %s", got)
			}
			if !strings.Contains(rec.Body.String(), "U+0000") {
				t.Errorf("the sentence does not say why: %s", rec.Body)
			}
		})
	}
	// Not NUL: a percent sign followed by 00 as text, and other headers.
	for _, target := range []string{"/agents/x%2500", "/agents?q=%2500"} {
		next := &ok{}
		if rec := serve(Contract(next), "GET", target, nil); rec.Code != 200 {
			t.Errorf("%s: %d %s", target, rec.Code, rec.Body)
		}
	}
}

// The federation client's transport adds the header and leaves the
// caller's request alone.
func TestTransport(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get(Header))
	}))
	defer srv.Close()
	c := &http.Client{Transport: Transport(nil)}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if req.Header.Get(Header) != "" {
		t.Error("the transport modified the caller's request")
	}
	req2, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req2.Header.Set(Header, "7")
	resp, err = c.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Join(seen, ",") != "3,7" {
		t.Fatalf("sent %q", seen)
	}
}
