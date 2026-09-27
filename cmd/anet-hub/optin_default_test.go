//go:build !taskboard

package main

import (
	"net/http"
	"testing"
)

// The default build must not contain the task board. Checked here as well
// as by symbol count in CI, because this is the assertion that fails at the
// moment somebody adds an untagged import of internal/taskboard or drops
// the tag from wire_taskboard.go — which is how a default hub would start
// storing and publishing task titles and notes again.
func TestTheDefaultBuildHasNoTaskboard(t *testing.T) {
	for _, m := range mounts {
		if m.name == "taskboard" {
			t.Fatal("the default build registered the taskboard mount; it is reachable only with -tags taskboard")
		}
	}
	if got := notBuilt(mountNames()); got != " taskboard" {
		t.Errorf("the startup log would report opt-in modules not built as %q, want \" taskboard\"", got)
	}
	// What a client sees: /stats does not name the board, and its route
	// is not served.
	h, _ := wiredHub(t)
	for _, m := range statsModules(t, h) {
		if m == "taskboard" {
			t.Error("/stats.modules names the taskboard in the default build")
		}
	}
	if code, body := get(t, h, "/tasks/board"); code != http.StatusNotFound {
		t.Errorf("GET /tasks/board in the default build = %d %.80s, want 404", code, body)
	}
}
