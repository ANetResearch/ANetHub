package wire3

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Strict JSON request decoding (core CORE-E7).
//
// A wire-3 request body is decoded against the Go type of the request:
//
//   - one JSON value, of the kind the type expects (an object for a
//     struct or a map; never null), and nothing after it;
//   - valid UTF-8;
//   - every object member is one the type takes, spelled exactly (the
//     standard decoder matches member names case-insensitively, so it
//     would read "AID" as "aid"), and given once (it would let the last
//     of two win, and a proxy or a second implementation might take the
//     first);
//   - no text, member names included, contains U+0000 (CORE-E9);
//   - objects and arrays nest at most MaxDepth levels;
//   - every value fits its field (the standard decoder's type checks).
//
// Any of these failing is 400 bad_request. Members of a map, of an
// interface{} value or of a json.RawMessage are not checked against a
// type, but are still checked for duplicates and U+0000.
//
// The other direction is lenient on purpose: a daemon ignores members it
// does not know in a hub response (CORE-E7), so a hub can add one.

// DecodeErrorKind says which rule a body broke.
type DecodeErrorKind int

const (
	// KindSyntax: not exactly one well-formed JSON value of the expected
	// kind (empty, truncated, trailing data, null, an array for an object).
	KindSyntax DecodeErrorKind = iota + 1
	// KindUTF8: the body is not valid UTF-8.
	KindUTF8
	// KindUnknownMember: an object member the request type does not take.
	KindUnknownMember
	// KindDuplicateMember: an object member given twice.
	KindDuplicateMember
	// KindNUL: U+0000 in a text value or a member name (or, through
	// CheckText and CheckRequest, in a path, a query or a header).
	KindNUL
	// KindType: a value of the wrong JSON type, or out of range for its field.
	KindType
	// KindRead: the body could not be read (the connection broke).
	KindRead
	// KindDepth: objects and arrays nested deeper than MaxDepth.
	KindDepth
	// KindB64URL: a binary value that is not base64url without padding in
	// its one spelling (DecodeB64URL, core CORE-E5).
	KindB64URL
	// KindSize: a binary value of the wrong length (DecodeB64URLSize); Size
	// is the length the member takes.
	KindSize
)

// MaxDepth is how deeply objects and arrays may nest in a request body
// (the body itself is level 1). No wire-3 request comes near it; the bound
// keeps the walk's stack and the member paths it builds small whatever a
// caller sends.
const MaxDepth = 64

// maxMemberPath bounds the member path a DecodeError carries. A path is
// only ever quoted (64 bytes of it) or compared with a short member name,
// so a longer one is cut here rather than built in full at every level.
const maxMemberPath = 128

// DecodeError is why a request was not accepted. It is always sent as 400
// bad_request with the sentence Sentence() gives.
type DecodeError struct {
	Kind DecodeErrorKind
	// Member is where: a dotted path into the body ("pow.nonce",
	// "items[2].dack"), or what CheckText was given ("path",
	// "X-Anet-Home"); "" for the body as a whole.
	Member string
	// Size is the number of bytes the member takes (KindSize only).
	Size int
	// Detail is for the log only.
	Detail string
}

func (e *DecodeError) Error() string {
	s := "wire3: " + e.Sentence()
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	return s
}

// UnknownMember is the path of the member a KindUnknownMember error names,
// or "" for any other error. A route that answers a removed member with
// its own code (for /register, "invite" is invite_removed) tests this.
func (e *DecodeError) UnknownMember() string {
	if e.Kind != KindUnknownMember {
		return ""
	}
	return e.Member
}

// Sentence is the one English sentence a 400 bad_request carries for e.
func (e *DecodeError) Sentence() string {
	m := quoteMember(e.Member)
	switch e.Kind {
	case KindUTF8:
		return "The request body is not valid UTF-8; encode it as UTF-8 and send again."
	case KindUnknownMember:
		return "The request body has the member " + m + ", which this route does not take; remove it and send again."
	case KindDuplicateMember:
		return "The request body has the member " + m + " more than once; give each member once and send again."
	case KindNUL:
		return "The " + m + " of this request contains U+0000, which no hub field may contain; remove it and send again."
	case KindType:
		if e.Member == "" {
			return "A value in the request body has the wrong type or is out of range; fix it and send again."
		}
		return "The member " + m + " has the wrong type or is out of range; fix it and send again."
	case KindRead:
		return "The request body could not be read in full; send the request again."
	case KindDepth:
		return "The request body nests objects and arrays more than " + strconv.Itoa(MaxDepth) +
			" levels deep; send the shape this route takes."
	case KindB64URL:
		return "The member " + m + " is not base64url (the URL-safe alphabet, no padding, no white space); " +
			"encode it that way and send again."
	case KindSize:
		return "The member " + m + " must be " + strconv.Itoa(e.Size) + " bytes; send a value of that length."
	}
	return "The request body is not one well-formed JSON object of the expected shape; fix it and send again."
}

// quoteMember quotes a member path for a sentence: at most 64 bytes,
// printable ASCII only, so a caller cannot put arbitrary text in a hub
// response.
func quoteMember(m string) string {
	if m == "" {
		return `""`
	}
	var b strings.Builder
	for _, r := range m {
		if b.Len() >= 64 {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return `"` + b.String() + `"`
}

// DecodeStrict decodes body into v, which must be a non-nil pointer, under
// the rules above. The error is always a *DecodeError.
func DecodeStrict(body []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		panic("wire3.DecodeStrict: v must be a non-nil pointer")
	}
	if !utf8.Valid(body) {
		return &DecodeError{Kind: KindUTF8}
	}
	target := deref(rv.Type().Elem())
	if err := walk(body, rv.Type().Elem(), target, nil); err != nil {
		return err
	}

	// The shape is proven (every member is one the type takes, under its
	// exact name, once); now the values, with the standard decoder.
	if err := json.Unmarshal(body, v); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			// Name the member as the body spells it: the standard
			// decoder's Field goes through embedded struct names and
			// leaves out array indexes. A second walk finds the value
			// that starts where the error is; only a refused body pays
			// for it.
			find := &finding{offset: te.Offset}
			_ = walk(body, rv.Type().Elem(), target, find)
			member := find.path
			if !find.ok {
				member = te.Field
			}
			return &DecodeError{Kind: KindType, Member: member, Detail: err.Error()}
		}
		var se *json.SyntaxError
		if errors.As(err, &se) { // the walk above would have refused it first
			return &DecodeError{Kind: KindSyntax, Detail: err.Error()}
		}
		return &DecodeError{Kind: KindType, Detail: err.Error()}
	}
	return nil
}

// walk checks body, one JSON value of type t (target is t without
// pointers), and that nothing follows it. With find non-nil it also
// records the path of the value whose first token ends at find.offset.
func walk(body []byte, t, target reflect.Type, find *finding) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	wk := &walker{dec: dec, find: find}
	tok, err := dec.Token()
	if err != nil {
		return &DecodeError{Kind: KindSyntax, Detail: err.Error()}
	}
	if tok == nil {
		return &DecodeError{Kind: KindSyntax, Detail: "null body"}
	}
	if (target.Kind() == reflect.Struct || target.Kind() == reflect.Map) && tok != json.Delim('{') {
		return &DecodeError{Kind: KindSyntax, Detail: "the body is not a JSON object"}
	}
	if err := wk.value(tok, t, "", 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return &DecodeError{Kind: KindSyntax, Detail: "data after the JSON value"}
	}
	return nil
}

// finding is the value a second walk looks for: the one whose first token
// ends at offset (what json.UnmarshalTypeError.Offset points at).
type finding struct {
	offset int64
	path   string
	ok     bool
}

// walker checks a token stream against a Go type. It keeps no state per
// value: what it holds at any time is bounded by MaxDepth levels of
// member paths of at most maxMemberPath bytes, whatever the body.
type walker struct {
	dec  *json.Decoder
	find *finding
}

// next reads one value starting at its first token, at nesting level depth.
func (w *walker) next(t reflect.Type, path string, depth int) error {
	tok, err := w.dec.Token()
	if err != nil {
		return &DecodeError{Kind: KindSyntax, Member: path, Detail: err.Error()}
	}
	return w.value(tok, t, path, depth)
}

// value checks the value that starts with tok, at nesting level depth (the
// body is level 1). t nil means "anything".
func (w *walker) value(tok json.Token, t reflect.Type, path string, depth int) error {
	if f := w.find; f != nil && !f.ok && w.dec.InputOffset() == f.offset {
		f.path, f.ok = path, true
	}
	t = deref(t)
	if t != nil && opaque(t) {
		t = nil
	}
	switch v := tok.(type) {
	case json.Delim:
		if depth > MaxDepth {
			return &DecodeError{Kind: KindDepth, Detail: "nested deeper than " + strconv.Itoa(MaxDepth)}
		}
		switch v {
		case '{':
			return w.object(t, path, depth)
		case '[':
			return w.array(t, path, depth)
		}
		return &DecodeError{Kind: KindSyntax, Member: path, Detail: "unexpected " + v.String()}
	case string:
		if strings.IndexByte(v, 0) >= 0 {
			return &DecodeError{Kind: KindNUL, Member: memberOrBody(path)}
		}
	}
	return nil
}

func (w *walker) object(t reflect.Type, path string, depth int) error {
	var fields map[string]reflect.Type // nil: members are not checked against a type
	var elem reflect.Type
	if t != nil {
		switch t.Kind() {
		case reflect.Struct:
			fields = jsonFields(t)
		case reflect.Map:
			elem = t.Elem()
		}
		// Any other kind: a type mismatch, which the standard decoder
		// reports with the member's name; walk it as free-form.
	}
	seen := map[string]bool{}
	for w.dec.More() {
		kt, err := w.dec.Token()
		if err != nil {
			return &DecodeError{Kind: KindSyntax, Member: path, Detail: err.Error()}
		}
		key, ok := kt.(string)
		if !ok {
			return &DecodeError{Kind: KindSyntax, Member: path, Detail: "object key is not a string"}
		}
		p := join(path, key)
		if strings.IndexByte(key, 0) >= 0 {
			return &DecodeError{Kind: KindNUL, Member: join(path, strings.ReplaceAll(key, "\x00", "?"))}
		}
		if seen[key] {
			return &DecodeError{Kind: KindDuplicateMember, Member: p}
		}
		seen[key] = true
		ft := elem
		if fields != nil {
			var known bool
			if ft, known = fields[key]; !known {
				return &DecodeError{Kind: KindUnknownMember, Member: p}
			}
		}
		if err := w.next(ft, p, depth+1); err != nil {
			return err
		}
	}
	if _, err := w.dec.Token(); err != nil { // the closing brace
		return &DecodeError{Kind: KindSyntax, Member: path, Detail: err.Error()}
	}
	return nil
}

func (w *walker) array(t reflect.Type, path string, depth int) error {
	var elem reflect.Type
	if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
		elem = t.Elem()
	}
	for i := 0; w.dec.More(); i++ {
		if err := w.next(elem, index(path, i), depth+1); err != nil {
			return err
		}
	}
	if _, err := w.dec.Token(); err != nil { // the closing bracket
		return &DecodeError{Kind: KindSyntax, Member: path, Detail: err.Error()}
	}
	return nil
}

// join is the path of member key of the object at path, cut to
// maxMemberPath bytes (a path already that long is not extended).
func join(path, key string) string {
	if len(path) >= maxMemberPath {
		return path
	}
	if path != "" {
		key = "." + key
	}
	if len(path)+len(key) > maxMemberPath {
		key = key[:maxMemberPath-len(path)]
	}
	return path + key
}

// index is the path of element i of the array at path, cut like join.
func index(path string, i int) string {
	if len(path) >= maxMemberPath {
		return path
	}
	return path + "[" + strconv.Itoa(i) + "]"
}

func memberOrBody(path string) string {
	if path == "" {
		return "body"
	}
	return path
}

func deref(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

var (
	rawMessageType      = reflect.TypeFor[json.RawMessage]()
	jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()
)

// opaque reports whether values of t decode themselves, so their members
// cannot be checked against a Go type: interface{}, json.RawMessage, and
// types with their own UnmarshalJSON. (A TextUnmarshaler takes a JSON
// string, which is still checked for U+0000.)
func opaque(t reflect.Type) bool {
	if t.Kind() == reflect.Interface || t == rawMessageType {
		return true
	}
	pt := reflect.PointerTo(t)
	return t.Implements(jsonUnmarshalerType) || pt.Implements(jsonUnmarshalerType)
}

// fieldCache maps a struct type to its JSON member names.
var fieldCache sync.Map // reflect.Type -> map[string]reflect.Type

// jsonFields returns the JSON member names a struct takes, as
// encoding/json reads them: exported fields under their tag name (or
// their Go name), "-" skipped, the fields of untagged embedded structs
// promoted. Where embedding gives one name to several fields, the
// shallowest wins, and among equally shallow ones the only one named by a
// tag; if there is no such one, encoding/json reads none of them, so the
// name is not a member here either (accepting it would drop its value
// without a word).
func jsonFields(t reflect.Type) map[string]reflect.Type {
	if m, ok := fieldCache.Load(t); ok {
		return m.(map[string]reflect.Type)
	}
	type candidate struct {
		typ    reflect.Type
		depth  int
		tagged bool
	}
	cands := map[string][]candidate{}
	var collect func(t reflect.Type, d int, visiting map[reflect.Type]bool)
	collect = func(t reflect.Type, d int, visiting map[reflect.Type]bool) {
		if visiting[t] {
			return
		}
		visiting[t] = true
		defer delete(visiting, t)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			if f.Anonymous && name == "" {
				if ft := deref(f.Type); ft.Kind() == reflect.Struct {
					collect(ft, d+1, visiting)
					continue
				}
			}
			if !f.IsExported() {
				continue
			}
			tagged := name != ""
			if !tagged {
				name = f.Name
			}
			cands[name] = append(cands[name], candidate{f.Type, d, tagged})
		}
	}
	collect(t, 0, map[reflect.Type]bool{})
	out := map[string]reflect.Type{}
	for name, cs := range cands {
		shallowest := cs[0].depth
		for _, c := range cs {
			shallowest = min(shallowest, c.depth)
		}
		var at, tagged []candidate
		for _, c := range cs {
			if c.depth == shallowest {
				at = append(at, c)
				if c.tagged {
					tagged = append(tagged, c)
				}
			}
		}
		switch {
		case len(at) == 1:
			out[name] = at[0].typ
		case len(tagged) == 1:
			out[name] = tagged[0].typ
		}
	}
	fieldCache.Store(t, out)
	return out
}

// ReadBody reads r's body, at most limit bytes. Past the limit it sends
// 413 too_large; a body that cannot be read in full is 400 bad_request.
// On a refusal it returns false and the handler returns.
func ReadBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			Write(w, Refusal{Reason: ReasonTooLarge,
				Error: fmt.Sprintf("The request body is larger than the %d bytes this route accepts; send a smaller one.", limit)})
			return nil, false
		}
		RefuseDecode(w, &DecodeError{Kind: KindRead, Detail: err.Error()})
		return nil, false
	}
	return body, true
}

// RefuseDecode sends 400 bad_request for an error of DecodeStrict,
// DecodeB64URL, CheckText or CheckRequest, with that error's sentence.
func RefuseDecode(w http.ResponseWriter, err error) {
	var de *DecodeError
	if !errors.As(err, &de) {
		de = &DecodeError{Kind: KindSyntax, Detail: err.Error()}
	}
	Write(w, Refusal{Reason: ReasonBadRequest, Error: de.Sentence()})
}

// ReadStrict reads r's body (ReadBody) and decodes it strictly into v
// (DecodeStrict). On a refusal it has sent the answer and returns false.
func ReadStrict(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	body, ok := ReadBody(w, r, limit)
	if !ok {
		return false
	}
	if err := DecodeStrict(body, v); err != nil {
		RefuseDecode(w, err)
		return false
	}
	return true
}
