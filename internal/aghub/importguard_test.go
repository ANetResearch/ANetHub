package aghub_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The hub kernel and the admin plane must not be able to decode task
// content (A2A-DESIGN §9 row 静态护栏).
//
// ANetCore/delegation holds the DelegateReq, ChatMsg and ResultResp
// codecs, and ANetCore/tsir the TaskDoc codec. Every place the hub ever
// read task content (the guest broker, the admin relay harvester, the
// goal extraction on review upload) did it through one of these two
// packages. Since wire 2 the hub carries only sealed envelopes and has no
// reason to decode either type, so a dependency on them reappearing is the
// earliest sign of a content path coming back.
//
// The check is on the full dependency closure of the non-test code, as
// `go list -deps` reports it, so an indirect import through another
// package is caught as well as a direct one, and a subpackage of either
// codec counts as the codec. Besides the two packages the design names,
// the two binaries are checked, which covers the modules they link in
// (federation among them): no part of the default hub build has a reason
// to decode task content. `go test` puts the go tool of the running
// toolchain first on PATH, so the command is available here.
func TestTheKernelAndAdminDoNotDependOnContentCodecs(t *testing.T) {
	forbidden := []string{
		"github.com/ANetResearch/ANetCore/delegation",
		"github.com/ANetResearch/ANetCore/tsir",
		// a2a-go holds the A2A Message and Task types. The hub verifies
		// A2A cards with ANetCore a2acard (A2A-DESIGN §10.3) and has no
		// use for the rest.
		"github.com/a2aproject/a2a-go",
	}
	for _, pkg := range []string{
		"github.com/ANetResearch/ANetHub/internal/aghub",
		"github.com/ANetResearch/ANetHub/internal/admin",
		"github.com/ANetResearch/ANetHub/cmd/anet-hub",
		"github.com/ANetResearch/ANetHub/cmd/anet-hub-admin",
	} {
		out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
		}
		deps := strings.Fields(string(out))
		if len(deps) < 10 {
			// A closure this small means the command listed something
			// other than the package; an empty list must not pass.
			t.Fatalf("go list -deps %s returned %d packages: %s", pkg, len(deps), out)
		}
		for _, d := range deps {
			for _, f := range forbidden {
				if d == f || strings.HasPrefix(d, f+"/") {
					t.Errorf("%s depends on %s, a task-content codec the hub must not hold", pkg, f)
				}
			}
		}
	}
}
