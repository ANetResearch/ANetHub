package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/version"
)

// --version names the build, not only the release.
//
// It printed version.V alone. That constant is hand-maintained and identical
// for every binary cut between two releases, so it could not answer "is this
// artifact the one I just built" — which is the question a deploy has to
// answer before it ships. The deploy script greps this line for "unknown" to
// refuse an unstamped binary, so the two fields have to be in it.
func TestVersionLineNamesTheBuild(t *testing.T) {
	line := versionLine()
	if !strings.Contains(line, version.V) {
		t.Errorf("--version does not report the release: %q", line)
	}
	for _, want := range []string{"commit=" + version.Commit, "built_at=" + version.BuiltAt} {
		if !strings.Contains(line, want) {
			t.Errorf("--version does not report %q: %q", want, line)
		}
	}
	// An unstamped build has to be recognisable as one, because that is what
	// the deploy script keys on.
	if version.Commit == "unknown" && !strings.Contains(line, "unknown") {
		t.Errorf("an unstamped build does not say so: %q", line)
	}
}

// The release path for this binary stamps the build into it.
//
// deploy/deploy-admin.sh is the documented way to ship the operator plane and
// it used a bare `go build`. version.Commit and version.BuiltAt then keep their
// "unknown" defaults, so /admin/healthz — whose only purpose is to say which
// build is answering — reported "unknown" for every deployment made that way,
// and an operator plane a release behind the hub was indistinguishable from a
// current one. The script cannot be executed from a test (it ssh's into
// production), so what is pinned here is that the stamping and the verification
// are in it.
func TestDeployScriptStampsAndVerifiesTheBuild(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "deploy-admin.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"PKG=github.com/ANetResearch/ANetHub/internal/version",
		"-X $PKG.Commit=$COMMIT",
		"-X $PKG.BuiltAt=$BUILT",
		"--version", // the artifact is checked before it is shipped
		"healthz",   // and the running service after
	} {
		if !strings.Contains(s, want) {
			t.Errorf("deploy-admin.sh is missing %q", want)
		}
	}
	// Both checks have to fail on "unknown", or they report nothing.
	if strings.Count(s, "unknown") < 2 {
		t.Errorf("deploy-admin.sh does not reject an unknown build in both places "+
			"(built artifact and running service); found %d mentions", strings.Count(s, "unknown"))
	}
}
