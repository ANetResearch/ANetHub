package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/version"
)

// releaseAtLeast reports whether release a is not older than b, for the
// plain MAJOR.MINOR.PATCH numbers both constants use.
func releaseAtLeast(t *testing.T, a, b string) bool {
	t.Helper()
	parse := func(s string) [3]int {
		var out [3]int
		parts := strings.Split(s, ".")
		if len(parts) != 3 {
			t.Fatalf("%q is not MAJOR.MINOR.PATCH", s)
		}
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 {
				t.Fatalf("%q is not MAJOR.MINOR.PATCH", s)
			}
			out[i] = n
		}
		return out
	}
	x, y := parse(a), parse(b)
	for i := range x {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return true
}

// The hub's release number, the wire it speaks and the anet release its
// refusals name have to agree. A wire-2 hub that called itself 0.1.x, or
// that told nodes to upgrade to a release newer than itself, would give an
// operator reading a 426 two numbers that cannot both be right.
func TestTheVersionLineNamesTheWireAndTheAnetItNeeds(t *testing.T) {
	if aghub.WireVersion != 2 || aghub.RequiredAnet != "0.2.0" {
		t.Fatalf("wire %d / anet >= %s: wire 2 is the contract anet 0.2.0 introduced (A2A-DESIGN §18)",
			aghub.WireVersion, aghub.RequiredAnet)
	}
	if !releaseAtLeast(t, version.V, aghub.RequiredAnet) {
		t.Errorf("anet-hub %s speaks wire %d, which needs anet >= %s: the hub cannot be older than the release that introduced its own wire",
			version.V, aghub.WireVersion, aghub.RequiredAnet)
	}
	line := versionLine()
	for _, want := range []string{
		"anet-hub " + version.V + " ",
		"wire " + strconv.Itoa(aghub.WireVersion),
		"anet >= " + aghub.RequiredAnet,
		"commit " + version.Commit,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("-version prints %q, which does not contain %q", line, want)
		}
	}
}
