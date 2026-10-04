package hubid_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoFiles parses every Go file of this repository, skipping testdata and hidden directories, and
// calls fn with each and whether it is a test file.
func repoFiles(t *testing.T, fn func(fset *token.FileSet, f *ast.File, isTest bool)) {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		up := filepath.Dir(root)
		if up == root {
			t.Fatal("no go.mod above the test directory")
		}
		root = up
	}
	fset := token.NewFileSet()
	files := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		fn(fset, f, strings.HasSuffix(p, "_test.go"))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 10 {
		t.Fatalf("parsed %d files: the check looks at nothing", files)
	}
}

// KEL C-23: Controller.CurrentPrivateKey is deleted; no identifier of that name exists anywhere in
// this repository, tests included. The hub signs through its identity's Controller (an
// identity.Signer) and never holds the key itself.
func TestNoCurrentPrivateKey(t *testing.T) {
	repoFiles(t, func(fset *token.FileSet, f *ast.File, _ bool) {
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "CurrentPrivateKey" {
				t.Errorf("%s: identifier CurrentPrivateKey (KEL C-23 deletes it)", fset.Position(id.Pos()))
			}
			return true
		})
	})
}

// KEL C-31, C-32: the hub holds no next key beyond its icp's hot key. ANetCore's
// identity/identitytest keeps the next keys of the test identities it rotates in process memory,
// so no non-test file of this repository imports it.
func TestIdentitytestOnlyInTests(t *testing.T) {
	const identitytest = "github.com/ANetResearch/ANetCore/identity/identitytest"
	repoFiles(t, func(fset *token.FileSet, f *ast.File, isTest bool) {
		if isTest {
			return
		}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, "`\"") == identitytest {
				t.Errorf("%s: imports %s, which is for tests only", fset.Position(imp.Pos()), identitytest)
			}
		}
	})
}
