// Package wire3test runs the hub wire-3 contract fixtures (core §5.2
// WIRE3-*): JSON files, by convention in internal/aghub/testdata/wire3/,
// each holding the error bodies of reason codes, or request and response
// pairs run against a hub, or both. It is imported by tests only.
//
// A file:
//
//	{
//	  "format": "wire3-fixture/1",
//	  "about":  "what the file pins and where the rules are (core CORE-V1, …)",
//	  "setup":  "hub",                  // the environment the cases run in (default "hub")
//	  "errors": [ <response>, … ],      // error bodies, see below
//	  "cases":  [ <case>, … ]
//	}
//
// An "errors" entry is the response one hub reason code is written with by
// wire3.Write: {"status", "headers"?, "body"}. The body's reason picks the
// code; its other members (besides error) are passed as the refusal's extra
// members, and a Retry-After header in "headers" as its wait. Across all
// files every code has exactly one entry, and its error is the code's
// default sentence: that is the fixture of each error body.
//
// A case:
//
//	{
//	  "name": "…", "cite": "CORE-V1",
//	  "request": {
//	    "method": "POST", "path": "/relay/poll",
//	    "headers": {"X-ANet-Wire": "3", "X-Twice": ["a", "b"]},
//	    "json": {…} | "text": "…" | "b64url": "…",   // the body, at most one
//	    "sign": {"action": "poll", "as": "alice"}    // relayauth v2 headers, by the setup
//	  },
//	  "response": {
//	    "status": 400,
//	    "headers": {"Retry-After": "*", "X-Other": null},  // exact; "*" present; null absent
//	    "body": {…},          // equal as JSON values
//	    "body_has": {…}       // these members (recursively) equal
//	  }
//	}
//
// ${name} in the path, a header value or a body (sent or expected) is
// replaced by the setup's variable of that name (an AID, say); a "b64url"
// body may be such a variable as a whole (bytes the setup made, an envelope
// say). The JSON of "json" is sent byte for byte as it appears in the file,
// so a duplicate member or an escaped U+0000 reaches the hub as written.
//
// Every response of every case is also checked against the contract
// itself: it carries X-ANet-Wire: 3, and an error (status 400 or more) is
// a G1 body whose reason is a hub code sent with that code's status, with
// a non-empty error, the code's required members, and Retry-After when the
// status asks the caller to wait. A case therefore cannot pin a non-G1
// error body.
package wire3test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Format is the format id every fixture file states.
const Format = "wire3-fixture/1"

// File is one fixture file.
type File struct {
	Format string     `json:"format"`
	About  string     `json:"about"`
	Setup  string     `json:"setup,omitempty"`
	Errors []Response `json:"errors,omitempty"`
	Cases  []Case     `json:"cases,omitempty"`

	name string // the file name, for messages
}

// Name is the file's base name.
func (f *File) Name() string { return f.name }

// Case is one request and the response it must get.
type Case struct {
	Name     string   `json:"name"`
	Cite     string   `json:"cite,omitempty"`
	Request  Request  `json:"request"`
	Response Response `json:"response"`
}

// Request is what a case sends.
type Request struct {
	Method  string          `json:"method"`
	Path    string          `json:"path"`
	Headers Headers         `json:"headers,omitempty"`
	JSON    json.RawMessage `json:"json,omitempty"`
	Text    *string         `json:"text,omitempty"`
	B64URL  string          `json:"b64url,omitempty"`
	Sign    *Sign           `json:"sign,omitempty"`
}

// Sign asks the setup to sign the request with relayauth v2 headers.
type Sign struct {
	Action string `json:"action"`
	As     string `json:"as"`
}

// Response is what a case expects, or an error body entry.
type Response struct {
	Status  int             `json:"status"`
	Headers Headers         `json:"headers,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
	BodyHas json.RawMessage `json:"body_has,omitempty"`
}

// Headers maps a header name to a JSON value: a string, an array of
// strings (a request header sent more than once), or null (an expected
// header that must be absent).
type Headers map[string]json.RawMessage

// Env is a hub a file's cases run against.
type Env struct {
	// Handler is the hub as it serves: its root, under wire3.Contract.
	Handler http.Handler
	// Vars are substituted for ${name}.
	Vars map[string]string
	// Sign adds relayauth v2 headers to req, whose body is body, as the
	// identity named as. Nil when the setup has no identities.
	Sign func(req *http.Request, body []byte, action, as string) error
}

// Setup builds an Env for one file; the test's cleanup tears it down.
type Setup func(t *testing.T) *Env

// Load reads every *.json file in dir, in name order.
func Load(t testing.TB, dir string) []*File {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatalf("no fixture files in %s", dir)
	}
	var out []*File
	for _, n := range names {
		raw, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		f := &File{}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(f); err != nil {
			t.Fatalf("%s: %v", filepath.Base(n), err)
		}
		f.name = filepath.Base(n)
		if f.Format != Format {
			t.Fatalf("%s: format %q, want %q", f.name, f.Format, Format)
		}
		if f.About == "" {
			t.Errorf("%s: say in \"about\" what the file pins and where its rules are", f.name)
		}
		out = append(out, f)
	}
	return out
}

// Run runs every file in dir: the error bodies through wire3.Write, the
// cases against the setup each file names. It also checks that the error
// bodies of all files together cover every hub reason code once.
func Run(t *testing.T, dir string, setups map[string]Setup) {
	files := Load(t, dir)
	covered := map[wire3.Reason]string{}
	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			for i, e := range f.Errors {
				reason := checkErrorEntry(t, f.name, i, e)
				if reason == "" {
					continue
				}
				if prev, dup := covered[reason]; dup {
					t.Errorf("%s errors[%d]: %s already has an error body in %s", f.name, i, reason, prev)
				}
				covered[reason] = f.name
			}
			if len(f.Cases) == 0 {
				return
			}
			name := f.Setup
			if name == "" {
				name = "hub"
			}
			setup, ok := setups[name]
			if !ok {
				t.Fatalf("%s: no setup %q in this test", f.name, name)
			}
			env := setup(t)
			seen := map[string]bool{}
			for _, c := range f.Cases {
				if c.Name == "" || seen[c.Name] {
					t.Errorf("%s: every case needs a unique name (%q)", f.name, c.Name)
				}
				seen[c.Name] = true
				t.Run(c.Name, func(t *testing.T) { runCase(t, env, c) })
			}
		})
	}
	for _, r := range wire3.Reasons() {
		if _, ok := covered[r]; !ok {
			t.Errorf("hub reason %s has no error body fixture (add it to an \"errors\" list)", r)
		}
	}
}

// checkErrorEntry writes one error body entry with wire3.Write and compares.
func checkErrorEntry(t *testing.T, file string, i int, e Response) wire3.Reason {
	t.Helper()
	where := fmt.Sprintf("%s errors[%d]", file, i)
	var body map[string]any
	if err := json.Unmarshal(e.Body, &body); err != nil {
		t.Errorf("%s: body: %v", where, err)
		return ""
	}
	code, _ := body["reason"].(string)
	reason := wire3.Reason(code)
	if !wire3.Known(reason) {
		t.Errorf("%s: %q is not a hub reason code", where, code)
		return ""
	}
	if got, _ := body["error"].(string); got != wire3.Sentence(reason) {
		t.Errorf("%s: error %q, want the default sentence of %s %q", where, got, reason, wire3.Sentence(reason))
	}
	rf := wire3.Refusal{Reason: reason, Extra: map[string]any{}}
	for k, v := range body {
		if k != "reason" && k != "error" && !(reason == wire3.ReasonWireTooOld && (k == "required_wire" || k == "required_anet")) {
			rf.Extra[k] = v
		}
	}
	if raw, ok := e.Headers["Retry-After"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Errorf("%s: Retry-After: %v", where, err)
		} else if n, err := strconv.Atoi(s); err == nil {
			rf.RetryAfter = time.Duration(n) * time.Second
		}
	}
	rec := httptest.NewRecorder()
	wire3.Write(rec, rf)
	check(t, where, nil, e, rec.Result().StatusCode, rec.Header(), rec.Body.Bytes())
	return reason
}

// runCase sends one case's request and checks the response.
func runCase(t *testing.T, env *Env, c Case) {
	sub := func(s string) string {
		for k, v := range env.Vars {
			s = strings.ReplaceAll(s, "${"+k+"}", v)
		}
		return s
	}
	rq := c.Request
	var body []byte
	n := 0
	if len(rq.JSON) > 0 {
		body = []byte(sub(string(rq.JSON)))
		n++
	}
	if rq.Text != nil {
		body = []byte(sub(*rq.Text))
		n++
	}
	if rq.B64URL != "" {
		b, err := base64.RawURLEncoding.DecodeString(sub(rq.B64URL))
		if err != nil {
			t.Fatalf("b64url: %v", err)
		}
		body = b
		n++
	}
	if n > 1 {
		t.Fatal("give the request body once: json, text or b64url")
	}
	req := httptest.NewRequest(rq.Method, sub(rq.Path), bytes.NewReader(body))
	if len(rq.JSON) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, raw := range rq.Headers {
		vals, err := headerValues(raw)
		if err != nil {
			t.Fatalf("header %s: %v", name, err)
		}
		req.Header.Del(name)
		for _, v := range vals {
			req.Header.Add(name, sub(v))
		}
	}
	if rq.Sign != nil {
		if env.Sign == nil {
			t.Fatal("this setup cannot sign requests")
		}
		if err := env.Sign(req, body, rq.Sign.Action, rq.Sign.As); err != nil {
			t.Fatalf("sign: %v", err)
		}
	}
	rec := httptest.NewRecorder()
	env.Handler.ServeHTTP(rec, req)
	want := c.Response
	want.Body = json.RawMessage(sub(string(want.Body)))
	want.BodyHas = json.RawMessage(sub(string(want.BodyHas)))
	check(t, c.Name, sub, want, rec.Result().StatusCode, rec.Header(), rec.Body.Bytes())
}

func headerValues(raw json.RawMessage) ([]string, error) {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("a request header is a string or an array of strings")
	}
	return many, nil
}

// check compares one response with what is expected, then holds it to the
// wire-3 contract (G1, CORE-V1).
func check(t *testing.T, where string, sub func(string) string, want Response, status int, hdr http.Header, body []byte) {
	t.Helper()
	if status != want.Status {
		t.Errorf("%s: status %d, want %d (body %s)", where, status, want.Status, body)
	}
	for name, raw := range want.Headers {
		got := hdr.Values(name)
		if string(raw) == "null" {
			if len(got) != 0 {
				t.Errorf("%s: header %s = %q, want it absent", where, name, got)
			}
			continue
		}
		var w string
		if err := json.Unmarshal(raw, &w); err != nil {
			t.Errorf("%s: expected header %s: a string, \"*\" or null", where, name)
			continue
		}
		if sub != nil {
			w = sub(w)
		}
		switch {
		case w == "*" && len(got) == 0:
			t.Errorf("%s: header %s is missing", where, name)
		case w != "*" && (len(got) != 1 || got[0] != w):
			t.Errorf("%s: header %s = %q, want %q", where, name, got, w)
		}
	}
	var gotBody any
	gotJSON := json.Valid(body)
	if gotJSON {
		gotBody = decode(body)
	}
	if len(want.Body) > 0 {
		if !gotJSON {
			t.Errorf("%s: body %q is not JSON", where, body)
		} else if wb := decode(want.Body); !reflect.DeepEqual(gotBody, wb) {
			t.Errorf("%s: body\n got %s\nwant %s", where, body, want.Body)
		}
	}
	if len(want.BodyHas) > 0 {
		if !gotJSON {
			t.Errorf("%s: body %q is not JSON", where, body)
		} else if missing := subset(decode(want.BodyHas), gotBody, ""); missing != "" {
			t.Errorf("%s: body %s\ndoes not have %s (%s)", where, body, want.BodyHas, missing)
		}
	}
	for _, p := range Contract(status, hdr, body) {
		t.Errorf("%s: %s", where, p)
	}
}

// Contract lists how one hub response breaks the wire-3 contract: it must
// carry X-ANet-Wire: 3, and an error must be a G1 body (see the package
// comment). It is exported for tests that check responses outside a
// fixture file.
func Contract(status int, hdr http.Header, body []byte) []string {
	var out []string
	if got := hdr.Values(wire3.Header); len(got) != 1 || got[0] != strconv.Itoa(wire3.Version) {
		out = append(out, fmt.Sprintf("%s is %q, want %q on every response (CORE-V1)", wire3.Header, got, strconv.Itoa(wire3.Version)))
	}
	if status < 400 {
		return out
	}
	var g1 map[string]any
	if err := json.Unmarshal(body, &g1); err != nil {
		return append(out, fmt.Sprintf("error body %q is not a JSON object (G1)", body))
	}
	code, _ := g1["reason"].(string)
	reason := wire3.Reason(code)
	if !wire3.Known(reason) {
		return append(out, fmt.Sprintf("error body reason %q is not a hub reason code (G1, core §2.15.1)", code))
	}
	if want := wire3.Status(reason); status != want {
		out = append(out, fmt.Sprintf("%s is sent with %d, not %d", reason, want, status))
	}
	if msg, _ := g1["error"].(string); strings.TrimSpace(msg) == "" {
		out = append(out, "error body without an error sentence (G1)")
	}
	for _, m := range wire3.ExtraMembers(reason) {
		if _, ok := g1[m]; !ok {
			out = append(out, fmt.Sprintf("%s body without its member %s", reason, m))
		}
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		out = append(out, fmt.Sprintf("error body with Content-Type %q, want application/json", ct))
	}
	if wire3.Waits(status) {
		if s, err := strconv.Atoi(hdr.Get("Retry-After")); err != nil || s < 1 {
			out = append(out, fmt.Sprintf("%d without a Retry-After of at least 1 second", status))
		}
	}
	return out
}

func decode(raw []byte) any {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	return v
}

// subset reports the first place where want is not contained in got: an
// object's members are compared recursively, anything else by equality.
func subset(want, got any, path string) string {
	wm, ok := want.(map[string]any)
	if !ok {
		if !reflect.DeepEqual(want, got) {
			return "at " + orRoot(path)
		}
		return ""
	}
	gm, ok := got.(map[string]any)
	if !ok {
		return orRoot(path) + " is not an object"
	}
	for k, wv := range wm {
		gv, ok := gm[k]
		if !ok {
			return "no member " + join(path, k)
		}
		if m := subset(wv, gv, join(path, k)); m != "" {
			return m
		}
	}
	return ""
}

func join(p, k string) string {
	if p == "" {
		return k
	}
	return p + "." + k
}

func orRoot(p string) string {
	if p == "" {
		return "the top"
	}
	return p
}

// ErrorEntries builds an "errors" list with one entry for every hub reason
// code, as wire3.Write sends it today: samples gives the extra members of
// the codes that carry some (ExtraMembers), retry the Retry-After of a
// waiting status. Used to (re)write the fixture file of the error bodies.
func ErrorEntries(samples map[wire3.Reason]map[string]any, retry time.Duration) ([]Response, error) {
	var out []Response
	for _, r := range wire3.Reasons() {
		rf := wire3.Refusal{Reason: r, Extra: samples[r]}
		for _, m := range wire3.ExtraMembers(r) {
			if _, ok := rf.Extra[m]; !ok && r != wire3.ReasonWireTooOld {
				return nil, fmt.Errorf("no sample value of %s for %s", m, r)
			}
		}
		rec := httptest.NewRecorder()
		if wire3.Waits(wire3.Status(r)) {
			rf.RetryAfter = retry
		}
		wire3.Write(rec, rf)
		// The hub HTML-escapes <, > and & as every Go JSON encoder does; the
		// file spells them plainly (the same JSON value) to be readable.
		body := bytes.TrimSpace(rec.Body.Bytes())
		body = []byte(strings.NewReplacer(`\u003c`, "<", `\u003e`, ">", `\u0026`, "&").Replace(string(body)))
		e := Response{Status: rec.Code, Body: body}
		if ra := rec.Header().Get("Retry-After"); ra != "" {
			v, _ := json.Marshal(ra)
			e.Headers = Headers{"Retry-After": v}
		}
		out = append(out, e)
	}
	return out, nil
}

// WriteFile writes f as an indented fixture file (without HTML escapes,
// so a sentence reads as it is).
func WriteFile(path string, f *File) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}
