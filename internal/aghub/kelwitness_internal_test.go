package aghub

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"unicode"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
)

// KEL-5 (KEL R-3, hub-payment-privacy PAY-R3): the X-ANet-AID of a signed
// request is an AID in its one spelling (identity.ValidAID), or the request
// is refused as an authentication failure, 401 unauthorized, before the
// signer is looked up, the signature checked or RC1 asked: a string that
// names nobody leaves no signer state in the hub. On every signed route.
func TestHubRefusesMalformedXANetAID(t *testing.T) {
	h := newRC1Hub(t, nil)
	c := h.agent()
	for _, bad := range []string{
		"x; echo admitted",
		strings.ToUpper(c.AID()),
		c.AID()[:58],
		c.AID() + "a",
		"did:anet:" + c.AID(),
		c.AID()[:57] + "z", // the last character carries two bits that must be zero
		"b" + strings.Repeat("a", 58),
	} {
		if identity.ValidAID(bad) {
			t.Fatalf("setup: %q is an AID", bad)
		}
		for _, rt := range []struct{ action, method, path string }{
			{relayauth.ActionPoll, http.MethodPost, "/relay/poll"},
			{relayauth.ActionRegister, http.MethodPost, "/register"},
			{relayauth.ActionSession, http.MethodPost, "/relay/session"},
			{relayauth.ActionProfile, http.MethodPost, "/profile"},
			{relayauth.ActionKeys, http.MethodPost, "/agents/" + c.AID() + "/keys"},
			{relayauth.ActionBalance, http.MethodGet, "/agents/" + c.AID() + "/balance"},
			{relayauth.ActionRevoke, http.MethodPost, "/mailbox/revoke"},
		} {
			before := h.s.replay.signerCount()
			raw := []byte(`{}`)
			if rt.method == http.MethodGet {
				raw = nil
			}
			req, _ := http.NewRequest(rt.method, h.srv.URL+rt.path, bytes.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
			ts := nowMS()
			// A good signature by c over the request, under the bad name.
			sig, seq := c.Sign(relayauth.PreimageV2(rt.action, bad, h.id.AID, ts, req.Method, req.URL.RequestURI(), raw))
			req.Header.Set(relayauth.HeaderAID, bad)
			req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
			req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
			req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(b), `"reason":"unauthorized"`) ||
				!strings.Contains(string(b), "is not an AID") {
				t.Errorf("%s %s as %q: %d %s, want 401 unauthorized naming X-ANet-AID", rt.method, rt.path, bad, resp.StatusCode, b)
			}
			if after := h.s.replay.signerCount(); after != before {
				t.Errorf("%s %s as %q: RC1 holds state for %d more signers", rt.method, rt.path, bad, after-before)
			}
		}
	}
	// The AID itself still signs.
	if a := h.poll(c, nowMS()); a.code != http.StatusOK {
		t.Fatalf("the agent's own poll: %d %s", a.code, a.body)
	}
}

// ---- KEL C-58 for ANetHub ----

// ksnProblems lists, for the non-test Go files of fsys, each identifier
// that is ksn or has ksn as one of its words, and each JSON or CBOR field
// tagged ksn (KEL C-58, core §0.3, G8).
func ksnProblems(fsys fs.FS) ([]string, error) {
	var out []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if hasKSNWord(x.Name) {
					out = append(out, fmt.Sprintf("%s: identifier %s", fset.Position(x.Pos()), x.Name))
				}
			case *ast.Field:
				if x.Tag == nil {
					return true
				}
				tag, err := strconv.Unquote(x.Tag.Value)
				if err != nil {
					return true
				}
				for _, key := range []string{"json", "cbor"} {
					if name, _, _ := strings.Cut(reflect.StructTag(tag).Get(key), ","); strings.EqualFold(name, "ksn") {
						out = append(out, fmt.Sprintf("%s: %s field tagged %q", fset.Position(x.Pos()), key, name))
					}
				}
			}
			return true
		})
		return nil
	})
	return out, err
}

// hasKSNWord reports whether name has ksn as one of its words: split at
// underscores and at case changes, so ksnCache, KSNCache, ksn_cache and
// lastKSN hold it and ksnow does not.
func hasKSNWord(name string) bool {
	rs := []rune(name)
	start := 0
	word := func(i int) bool {
		return i > start && strings.EqualFold(string(rs[start:i]), "ksn")
	}
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '_':
			if word(i) {
				return true
			}
			start = i + 1
		case i > start && unicode.IsUpper(r) && (unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1]) ||
			i+1 < len(rs) && unicode.IsUpper(rs[i-1]) && unicode.IsLower(rs[i+1])):
			if word(i) {
				return true
			}
			start = i
		}
	}
	return word(len(rs))
}

// KEL C-58 (core §0.3, G8) for ANetHub: no identifier of the non-test code
// is named ksn or has ksn as one of its words, and no JSON or CBOR field is
// tagged ksn. The term is "witness notice" (notice, key_state_notice) in
// code and on the wire, "key confirmation" for users.
func TestNoKSNIdentifiers(t *testing.T) {
	probs, err := ksnProblems(os.DirFS(hubRoot(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probs {
		t.Error(p)
	}
}

// The KSN scan finds what it must, and only in non-test files.
func TestKSNScanCatches(t *testing.T) {
	for src, bad := range map[string]bool{
		"package x\nvar ksn = 1\n":                                              true,
		"package x\nfunc f(lastKSN int) {}\n":                                   true,
		"package x\ntype T struct{ ksnCache int }\n":                            true,
		"package x\nvar ksn_cache = 1\n":                                        true,
		"package x\ntype T struct{ A int `json:\"ksn\"` }":                      true,
		"package x\ntype T struct{ A int `cbor:\"KSN,keyasint\"` }":             true,
		"package x\nvar ksnow, keySeq, Ksnap = 1, 2, 3\n":                       false,
		"package x\ntype T struct{ Notice []byte `json:\"key_state_notice\"` }": false,
	} {
		probs, err := ksnProblems(fstest.MapFS{"x.go": &fstest.MapFile{Data: []byte(src)}})
		if err != nil {
			t.Fatal(err)
		}
		if (len(probs) > 0) != bad {
			t.Errorf("%q: %q, want bad = %v", src, probs, bad)
		}
	}
	if probs, _ := ksnProblems(fstest.MapFS{"x_test.go": &fstest.MapFile{Data: []byte("package x\nvar ksn = 1\n")}}); len(probs) != 0 {
		t.Errorf("a test file was scanned: %q", probs)
	}
}

// ---- running one fixture file ----

// A run of TestWire3Fixtures narrowed to one fixture file
// (go test -run 'TestWire3Fixtures/<file>') is green on code that is: the
// check that every hub reason code has an error body needs all the files
// and is made only when they all ran (wire3test.Run). So a mutation entry
// can run the one file whose cases hold its rule. The run is this test
// binary again, as go test would run it.
func TestWire3RunFilteredIsGreen(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"kel.json", "errors.json", "register.json"} {
		// The filter selects TestWire3Fixtures only, so the child does
		// not run this test again.
		cmd := exec.Command(exe, "-test.run", "^TestWire3Fixtures$/^"+regexp.QuoteMeta(file)+"$", "-test.count=1", "-test.v")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("TestWire3Fixtures/%s alone: %v\n%s", file, err, tail(out))
			continue
		}
		if !bytes.Contains(out, []byte("--- PASS: TestWire3Fixtures/"+file)) {
			t.Errorf("TestWire3Fixtures/%s alone did not run the file:\n%s", file, tail(out))
		}
		if !bytes.Contains(out, []byte("checked only when all of them run")) {
			t.Errorf("TestWire3Fixtures/%s alone did not say the coverage check was left out:\n%s", file, tail(out))
		}
	}
}

// tail is the last lines of a child's output.
func tail(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 30 {
		lines = lines[len(lines)-30:]
	}
	return strings.Join(lines, "\n")
}
