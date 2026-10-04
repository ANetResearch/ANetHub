package wire3

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzDecodeStrict: DecodeStrict never panics; whatever it accepts is
// valid UTF-8 JSON that the standard decoder reads to the same value, with
// no member given twice and no U+0000 anywhere; it accepts nothing the
// standard decoder (with unknown members disallowed) refuses.
func FuzzDecodeStrict(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"aid":"a","kel":"k"}`, `{"pow":{"seed":"s","nonce":"n"}}`, `{"items":[{"id":1,"handle":"h"}]}`,
		`{"labels":{"a":"b"}}`, `{"a2a_card":{"x":[1,{"y":null}]}}`, `{"any":[true,false,null,1.5,"s"]}`,
		`{"aid":"a","aid":"b"}`, `{"AID":"a"}`, `{"aid":"\u0000"}`, `{"prev_seq":-1}`, `{"Untagged":1e3}`,
		`{"aid":"a"} {}`, `null`, `[]`, "{\"name\":\"\xff\"}", `{"caps":["a",1]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var got req
		err := DecodeStrict(body, &got)
		var std req
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		stdErr := dec.Decode(&std)
		if err != nil {
			var de *DecodeError
			if !errors.As(err, &de) {
				t.Fatalf("error %T is not a *DecodeError", err)
			}
			if s := de.Sentence(); len(s) > 240 || !utf8.ValidString(s) || strings.ContainsAny(s, "\n\x00") {
				t.Fatalf("sentence %q", s)
			}
			return
		}
		if stdErr != nil {
			t.Fatalf("accepted %q, which the standard decoder refuses: %v", body, stdErr)
		}
		if !utf8.Valid(body) || !json.Valid(body) {
			t.Fatalf("accepted %q, not valid UTF-8 JSON", body)
		}
		if !reflect.DeepEqual(got, std) {
			t.Fatalf("%q decodes to %+v, the standard decoder to %+v", body, got, std)
		}
		var free any
		if err := json.Unmarshal(body, &free); err != nil || hasNUL(free) {
			t.Fatalf("accepted %q, which has U+0000", body)
		}
		if dup := duplicateMember(body); dup != "" {
			t.Fatalf("accepted %q, which has %q twice", body, dup)
		}
	})
}

// hasNUL reports whether any text in v, member names included, has U+0000.
func hasNUL(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.IndexByte(x, 0) >= 0
	case []any:
		for _, e := range x {
			if hasNUL(e) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if strings.IndexByte(k, 0) >= 0 || hasNUL(e) {
				return true
			}
		}
	}
	return false
}

// duplicateMember is a reference check: the first member name that occurs
// twice in one object, or "".
func duplicateMember(body []byte) string {
	dec := json.NewDecoder(bytes.NewReader(body))
	type frame struct {
		obj  bool
		keys map[string]bool
		key  bool // the next string token in this object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		isKey := top != nil && top.obj && top.key
		if top != nil && top.obj {
			top.key = !top.key
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, &frame{obj: true, keys: map[string]bool{}, key: true})
			case '[':
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].key = true
				}
			}
		case string:
			if isKey {
				if top.keys[v] {
					return v
				}
				top.keys[v] = true
			}
		}
	}
}

// FuzzContract: whatever the method, path and wire header, every response
// carries X-ANet-Wire: 3; a request reaches the handler only if it speaks
// wire 3, is a CORS preflight, or is a read outside the relay and
// federation planes, declares a wire once and no newer one, and has no
// U+0000 in its path, query or X-ANet-* headers; a refusal is a G1 body
// with a registered reason sent with that reason's status.
func FuzzContract(f *testing.F) {
	f.Add(uint8(0), "/register", "3", "", false)
	f.Add(uint8(1), "/agents", "", "", false)
	f.Add(uint8(1), "/relay/poll", "2", "", false)
	f.Add(uint8(1), "/fed/v3/cards", "4", "", true)
	f.Add(uint8(2), "/agents/%00/kel", "3", "", false)
	f.Add(uint8(0), "/relay/send", "3", "bafy\x00", false)
	f.Add(uint8(3), "/x", "03", "", false)
	methods := []string{"POST", "GET", "HEAD", "OPTIONS", "PUT", "DELETE"}
	f.Fuzz(func(t *testing.T, m uint8, target, wire, home string, twice bool) {
		u, err := url.ParseRequestURI(target)
		if err != nil || u.Host != "" || !strings.HasPrefix(target, "/") {
			return
		}
		method := methods[int(m)%len(methods)]
		req := httptest.NewRequest(method, "/", nil)
		req.URL = u
		if wire != "" || twice {
			req.Header["X-Anet-Wire"] = []string{wire}
			if twice {
				req.Header["X-Anet-Wire"] = append(req.Header["X-Anet-Wire"], wire)
			}
		}
		if home != "" {
			req.Header.Set("X-ANet-Home", home)
		}
		next := &ok{}
		rec := httptest.NewRecorder()
		Contract(next).ServeHTTP(rec, req)
		if got := rec.Header().Values(Header); len(got) != 1 || got[0] != "3" {
			t.Fatalf("%s %s: %s %q", method, target, Header, got)
		}
		d := declaredWire(req)
		preflight := method == http.MethodOptions
		mayPass := d != declaredNewer && d != declaredTwice && (d == declaredCurrent || preflight || !gated(req)) && CheckRequest(req) == nil
		if next.ran != mayPass {
			t.Fatalf("%s %s wire %q twice %v home %q: handler ran %v, want %v", method, target, wire, twice, home, next.ran, mayPass)
		}
		if next.ran {
			if strings.IndexByte(req.URL.Path, 0) >= 0 || strings.IndexByte(home, 0) >= 0 {
				t.Fatal("U+0000 reached the handler")
			}
			return
		}
		var b struct {
			Reason Reason `json:"reason"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil || !Known(b.Reason) || b.Error == "" {
			t.Fatalf("refusal %s is not G1", rec.Body)
		}
		if rec.Code != Status(b.Reason) {
			t.Fatalf("%s sent with %d", b.Reason, rec.Code)
		}
	})
}

// FuzzDecodeB64URL: DecodeB64URL never panics; it accepts a string exactly
// when the string is the one spelling of some bytes (only the 64 characters
// of base64url, and re-encoding what it decodes to gives the string back),
// and then it returns those bytes; a refusal is a *DecodeError of
// KindB64URL. DecodeB64URLSize accepts exactly the accepted strings of n
// bytes.
func FuzzDecodeB64URL(f *testing.F) {
	for _, s := range []string{"", "AA", "AB", "AAA", "AAB", "AAAA", "A", "AA==", "+/", "-_", "AA\nAA",
		"AA\rAA", " AA", "AAECAwQFBgcICQoLDA0ODw", "_x", "\x00", "é"} {
		f.Add(s, uint8(16))
	}
	f.Fuzz(func(t *testing.T, s string, n uint8) {
		got, err := DecodeB64URL("m", s)
		// The oracle: alphabet first (the standard decoder skips "\r" and
		// "\n"), then the lenient decoder, then the round trip.
		canonical := true
		for i := 0; i < len(s); i++ {
			if !b64urlChar(s[i]) {
				canonical = false
			}
		}
		var ref []byte
		if canonical {
			var rerr error
			ref, rerr = base64.RawURLEncoding.DecodeString(s)
			canonical = rerr == nil && base64.RawURLEncoding.EncodeToString(ref) == s
		}
		if canonical != (err == nil) {
			t.Fatalf("%q: accepted %v, but it is the one spelling of some bytes: %v", s, err == nil, canonical)
		}
		if err != nil {
			var de *DecodeError
			if !errors.As(err, &de) || de.Kind != KindB64URL || de.Member != "m" {
				t.Fatalf("%q: error %#v", s, err)
			}
		} else if !bytes.Equal(got, ref) || EncodeB64URL(got) != s {
			t.Fatalf("%q decoded to %x, want %x", s, got, ref)
		}
		sized, serr := DecodeB64URLSize("m", s, int(n))
		if (serr == nil) != (err == nil && len(got) == int(n)) {
			t.Fatalf("%q, %d bytes: sized accepted %v", s, n, serr == nil)
		}
		if serr == nil && !bytes.Equal(sized, got) {
			t.Fatalf("%q: sized %x, plain %x", s, sized, got)
		}
	})
}
