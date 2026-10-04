package wire3

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDecodeB64URLStrict (core CORE-E5): the hub's one base64url decoder
// takes each value in exactly one spelling: the URL-safe alphabet, no
// padding, no white space (not even the "\r" and "\n" the standard decoder
// skips), no length that no encoding has and no non-zero trailing bits.
func TestDecodeB64URLStrict(t *testing.T) {
	for _, c := range []struct {
		name string
		in   string
		want []byte // nil: refused
	}{
		{"empty is no bytes", "", []byte{}},
		{"one byte", "AA", []byte{0}},
		{"two bytes", "AAA", []byte{0, 0}},
		{"three bytes", "AAAA", []byte{0, 0, 0}},
		{"the two URL-safe characters", "-_-_", []byte{0xfb, 0xff, 0xbf}},
		{"every value of a byte's high bits", "_w", []byte{0xff}},
		{"a 16-byte capability id", "AAECAwQFBgcICQoLDA0ODw", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},

		{"padding", "AA==", nil},
		{"one padding character", "AAA=", nil},
		{"padding alone", "====", nil},
		{"the standard alphabet's +", "+w", nil},
		{"the standard alphabet's /", "/w", nil},
		{"a space", "AA AA", nil},
		{"a leading space", " AA", nil},
		{"a trailing newline", "AA\n", nil},
		{"a newline inside", "AA\nAA", nil},
		{"a carriage return", "AA\rAA", nil},
		{"a tab", "AA\tAA", nil},
		{"U+0000", "AA\x00A", nil},
		{"a non-ASCII letter", "AAé", nil},
		{"a dot", "AA.A", nil},
		{"a length of 4n+1", "AAAAA", nil},
		{"one character", "A", nil},
		{"non-zero trailing bits after one byte", "AB", nil},
		{"non-zero trailing bits after two bytes", "AAB", nil},
		{"the last character's low bits set", "_x", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := DecodeB64URL("x", c.in)
			if c.want == nil {
				var de *DecodeError
				if err == nil {
					t.Fatalf("%q decoded to %x", c.in, got)
				}
				if !errors.As(err, &de) || de.Kind != KindB64URL || de.Member != "x" {
					t.Fatalf("%q: error %#v, want a *DecodeError of KindB64URL naming x", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q: %v", c.in, err)
			}
			if !bytes.Equal(got, c.want) {
				t.Fatalf("%q decoded to %x, want %x", c.in, got, c.want)
			}
			if EncodeB64URL(got) != c.in {
				t.Fatalf("%q decoded to %x, which encodes as %q", c.in, got, EncodeB64URL(got))
			}
		})
	}
}

// DecodeB64URLSize takes a value of exactly n bytes and names the length in
// its refusal; a value that is not base64url is still refused as such.
func TestDecodeB64URLSize(t *testing.T) {
	id := EncodeB64URL(bytes.Repeat([]byte{7}, 16))
	if got, err := DecodeB64URLSize("cap_ids[0]", id, 16); err != nil || len(got) != 16 {
		t.Fatalf("a 16-byte id: %x %v", got, err)
	}
	for _, in := range []string{EncodeB64URL(make([]byte, 15)), EncodeB64URL(make([]byte, 17)), ""} {
		_, err := DecodeB64URLSize("cap_ids[0]", in, 16)
		var de *DecodeError
		if !errors.As(err, &de) || de.Kind != KindSize || de.Size != 16 {
			t.Fatalf("%q: %#v, want KindSize 16", in, err)
		}
		if s := de.Sentence(); !strings.Contains(s, `"cap_ids[0]"`) || !strings.Contains(s, "16 bytes") {
			t.Fatalf("the sentence does not name the member and its length: %s", s)
		}
	}
	_, err := DecodeB64URLSize("cap_ids[0]", id+"=", 16)
	var de *DecodeError
	if !errors.As(err, &de) || de.Kind != KindB64URL {
		t.Fatalf("a padded id: %#v, want KindB64URL", err)
	}
}

// A refused value is a 400 bad_request whose one sentence names the member
// and says what to send instead.
func TestARefusedBinaryValueIsBadRequest(t *testing.T) {
	_, err := DecodeB64URL(`cap_ids[2]`, "AA==")
	rec := httptest.NewRecorder()
	RefuseDecode(rec, err)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"reason":"bad_request"`, `cap_ids[2]`, "base64url", "send again"} {
		if !strings.Contains(body, want) {
			t.Errorf("the body %s lacks %q", body, want)
		}
	}
}

// pendingB64URLDecoders are the files that still decode base64url without
// DecodeB64URL, each with the work item that moves it here. A file listed
// here that no longer does fails, so that its entry goes too.
var pendingB64URLDecoders = map[string]string{
	"internal/aghub/registry.go": "v030-todo(SS-5)", // the /a2a/v1/agents cursor
}

// b64urlDecodeRe matches a call that decodes base64url with the standard
// library.
var b64urlDecodeRe = regexp.MustCompile(`base64\.(Raw)?URLEncoding\b.*\.Decode|base64\.NewDecoder\(base64\.(Raw)?URLEncoding`)

// TestHubDecodesBase64URLOnlyHere (core CORE-E5): no hub code but this file
// decodes base64url, so every binary value of the hub wire is read under the
// same rules. Tests and the fixture runner (wire3test) are not hub code.
func TestHubDecodesBase64URLOnlyHere(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("%s is not the repository root: %v", root, err)
	}
	found := map[string]bool{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") && rel != "." || rel == "internal/wire3/wire3test" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || rel == "internal/wire3/b64url.go" {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var b strings.Builder
			if err := printer.Fprint(&b, fset, call); err != nil {
				t.Fatal(err)
			}
			if !b64urlDecodeRe.MatchString(b.String()) {
				return true
			}
			found[rel] = true
			if _, pending := pendingB64URLDecoders[rel]; !pending {
				t.Errorf("%s: %s decodes base64url itself; use wire3.DecodeB64URL", fset.Position(call.Pos()), b.String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for file, todo := range pendingB64URLDecoders {
		if !found[file] {
			t.Errorf("%s decodes no base64url of its own any more: drop it (%s) from pendingB64URLDecoders", file, todo)
		}
	}
}
