package wire3

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type pow struct {
	Seed  string `json:"seed"`
	Nonce string `json:"nonce"`
}

type item struct {
	ID     uint64 `json:"id"`
	Handle string `json:"handle,omitempty"`
}

type base struct {
	AID string `json:"aid"`
}

type req struct {
	base
	KEL      string            `json:"kel"`
	Name     string            `json:"name,omitempty"`
	Caps     []string          `json:"caps,omitempty"`
	PrevSeq  *uint64           `json:"prev_seq,omitempty"`
	Pow      *pow              `json:"pow,omitempty"`
	Items    []item            `json:"items,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Card     json.RawMessage   `json:"a2a_card,omitempty"`
	Any      any               `json:"any,omitempty"`
	Untagged int
	Skipped  string `json:"-"`
	hidden   string //nolint:unused // an unexported field is not a member
}

func decodeErr(t *testing.T, body string) *DecodeError {
	t.Helper()
	var r req
	err := DecodeStrict([]byte(body), &r)
	if err == nil {
		return nil
	}
	var de *DecodeError
	if !errors.As(err, &de) {
		t.Fatalf("%s: error %T is not a *DecodeError", body, err)
	}
	return de
}

func TestDecodeStrictAccepts(t *testing.T) {
	body := `{"aid":"a","kel":"k","name":"n","caps":["x","y"],"prev_seq":0,"pow":{"seed":"s","nonce":"n"},
	  "items":[{"id":1},{"id":2,"handle":"h"}],"labels":{"any":"thing","Other":"x"},
	  "a2a_card":{"name":"c","extra":{"deep":[1,2]}},"any":{"x":[null,true]},"Untagged":5}`
	var r req
	if err := DecodeStrict([]byte(body), &r); err != nil {
		t.Fatal(err)
	}
	if r.AID != "a" || r.Pow.Nonce != "n" || len(r.Items) != 2 || r.Items[1].Handle != "h" ||
		r.Labels["Other"] != "x" || r.PrevSeq == nil || *r.PrevSeq != 0 || r.Untagged != 5 {
		t.Fatalf("decoded %+v", r)
	}
	if err := DecodeStrict([]byte(" {} \n"), &r); err != nil {
		t.Fatalf("an empty object with whitespace: %v", err)
	}
	m := map[string]int{}
	if err := DecodeStrict([]byte(`{"a":1,"b":2}`), &m); err != nil || m["b"] != 2 {
		t.Fatalf("map target: %v %v", err, m)
	}
}

func TestDecodeStrictRefuses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		kind       DecodeErrorKind
		member     string
	}{
		{"empty", ``, KindSyntax, ""},
		{"whitespace", "  \n", KindSyntax, ""},
		{"null", `null`, KindSyntax, ""},
		{"array", `[]`, KindSyntax, ""},
		{"string", `"x"`, KindSyntax, ""},
		{"truncated", `{"aid":"a"`, KindSyntax, ""},
		{"trailing value", `{"aid":"a"}{}`, KindSyntax, ""},
		{"trailing junk", `{"aid":"a"} x`, KindSyntax, ""},
		{"trailing comma", `{"aid":"a",}`, KindSyntax, ""},
		{"bad utf-8", "{\"name\":\"\xff\"}", KindUTF8, ""},
		{"unknown", `{"aid":"a","invite":"x"}`, KindUnknownMember, "invite"},
		{"unknown nested", `{"pow":{"seed":"s","nonce":"n","bits":22}}`, KindUnknownMember, "pow.bits"},
		{"unknown in array", `{"items":[{"id":1},{"id":2,"dack":"d"}]}`, KindUnknownMember, "items[1].dack"},
		{"case folded", `{"AID":"a"}`, KindUnknownMember, "AID"},
		{"case folded nested", `{"pow":{"Seed":"s"}}`, KindUnknownMember, "pow.Seed"},
		{"skipped field", `{"Skipped":"x"}`, KindUnknownMember, "Skipped"},
		{"unexported field", `{"hidden":"x"}`, KindUnknownMember, "hidden"},
		{"embedded struct name", `{"base":{}}`, KindUnknownMember, "base"},
		{"duplicate", `{"aid":"a","aid":"b"}`, KindDuplicateMember, "aid"},
		{"duplicate nested", `{"pow":{"seed":"s","seed":"t"}}`, KindDuplicateMember, "pow.seed"},
		{"duplicate in map", `{"labels":{"a":"1","a":"2"}}`, KindDuplicateMember, "labels.a"},
		{"duplicate in raw", `{"a2a_card":{"n":1,"n":2}}`, KindDuplicateMember, "a2a_card.n"},
		{"duplicate in any", `{"any":[{"k":1,"k":1}]}`, KindDuplicateMember, "any[0].k"},
		{"nul", `{"aid":"a\u0000b"}`, KindNUL, "aid"},
		{"nul in array", `{"caps":["x","\u0000"]}`, KindNUL, "caps[1]"},
		{"nul in map value", `{"labels":{"a":"\u0000"}}`, KindNUL, "labels.a"},
		{"nul in raw", `{"a2a_card":{"name":"\u0000"}}`, KindNUL, "a2a_card.name"},
		{"nul in key", `{"labels":{"a\u0000":"x"}}`, KindNUL, "labels.a?"},
		{"nul in unknown key", `{"\u0000":1}`, KindNUL, "?"},
		{"wrong type", `{"aid":1}`, KindType, "aid"},
		{"wrong type, spaced", "{ \"kel\" :\n 12 }", KindType, "kel"},
		{"negative uint", `{"prev_seq":-1}`, KindType, "prev_seq"},
		{"fraction uint", `{"prev_seq":1.5}`, KindType, "prev_seq"},
		{"overflow uint", `{"prev_seq":18446744073709551616}`, KindType, "prev_seq"},
		{"object for string", `{"name":{"x":1}}`, KindType, "name"},
		{"array element type", `{"items":[{"id":1},{"id":"1"}]}`, KindType, "items[1].id"},
		{"embedded", `{"aid":["a"]}`, KindType, "aid"},
		{"array for map", `{"labels":[]}`, KindType, "labels"},
		{"bool for int", `{"Untagged":true}`, KindType, "Untagged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			de := decodeErr(t, tc.body)
			if de == nil {
				t.Fatalf("%s was accepted", tc.body)
			}
			if de.Kind != tc.kind {
				t.Errorf("kind %d, want %d (%v)", de.Kind, tc.kind, de)
			}
			if tc.member != "" && de.Member != tc.member {
				t.Errorf("member %q, want %q", de.Member, tc.member)
			}
			if s := de.Sentence(); !strings.Contains(s, "; ") || !strings.HasSuffix(s, ".") {
				t.Errorf("sentence %q", s)
			}
		})
	}
}

// /register answers its one removed member with its own code; the error
// says which member it was.
func TestUnknownMember(t *testing.T) {
	de := decodeErr(t, `{"aid":"a","invite":"x"}`)
	if de.UnknownMember() != "invite" {
		t.Fatalf("%q", de.UnknownMember())
	}
	if decodeErr(t, `{"aid":1}`).UnknownMember() != "" {
		t.Fatal("a type error names no unknown member")
	}
}

// The sentence quotes at most 64 printable ASCII bytes of a member name,
// so a caller cannot put arbitrary text in the response.
func TestSentenceQuotesSafely(t *testing.T) {
	long := strings.Repeat("z", 500)
	de := decodeErr(t, `{"`+long+`":1}`)
	if s := de.Sentence(); len(s) > 200 || !strings.Contains(s, "...") {
		t.Fatalf("%q", s)
	}
	de = decodeErr(t, `{"<script>\"é\n":1}`)
	if s := de.Sentence(); strings.ContainsAny(s, "é\n\\") || !strings.Contains(s, `"<script>???"`) {
		t.Fatalf("%q", s)
	}
}

func TestDecodeStrictNeedsAPointer(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic for a non-pointer")
		}
	}()
	_ = DecodeStrict([]byte(`{}`), req{})
}

// ReadStrict: 413 too_large past the limit, 400 bad_request for a body
// that breaks a rule, the decoded value otherwise.
func TestReadStrict(t *testing.T) {
	run := func(body string, limit int64) (*httptest.ResponseRecorder, bool, req) {
		var v req
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
		ok := ReadStrict(rec, r, limit, &v)
		return rec, ok, v
	}
	if rec, ok, v := run(`{"aid":"a"}`, 64); !ok || v.AID != "a" || rec.Body.Len() != 0 {
		t.Fatalf("%v %+v %s", ok, v, rec.Body)
	}
	rec, ok, _ := run(`{"aid":"`+strings.Repeat("a", 100)+`"}`, 64)
	if ok || rec.Code != 413 || reasonOf(t, rec) != "too_large" {
		t.Fatalf("%v %d %s", ok, rec.Code, rec.Body)
	}
	rec, ok, _ = run(`{"aid":"a","zz":1}`, 64)
	if ok || rec.Code != 400 || reasonOf(t, rec) != "bad_request" || !strings.Contains(rec.Body.String(), `\"zz\"`) {
		t.Fatalf("%v %d %s", ok, rec.Code, rec.Body)
	}
}

// CheckText is the same rule for text the hub decodes itself.
func TestCheckText(t *testing.T) {
	if CheckText("X-ANet-Home", "bafyrei") != nil {
		t.Fatal("clean text refused")
	}
	err := CheckText("X-ANet-Home", "a\x00")
	var de *DecodeError
	if !errors.As(err, &de) || de.Kind != KindNUL || !strings.Contains(de.Sentence(), "X-ANet-Home") {
		t.Fatalf("%v", err)
	}
	rec := httptest.NewRecorder()
	RefuseDecode(rec, err)
	if rec.Code != 400 || reasonOf(t, rec) != "bad_request" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
