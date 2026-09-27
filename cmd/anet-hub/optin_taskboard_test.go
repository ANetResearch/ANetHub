//go:build taskboard

package main

import (
	"net/http"
	"strings"
	"testing"
)

// With -tags taskboard the board is compiled in and registered as a mount.
// The other direction of TestTheDefaultBuildHasNoTaskboard: without it, a
// tag that linked nothing would look like a working opt-in.
func TestTheTaskboardTagBuildsTheBoard(t *testing.T) {
	found := false
	for _, m := range mounts {
		if m.name == "taskboard" {
			found = true
		}
	}
	if !found {
		t.Fatal("-tags taskboard did not register the taskboard mount")
	}
	var names []string
	for _, m := range mounts {
		names = append(names, m.name)
	}
	if got := notBuilt(names); got != " none" {
		t.Errorf("with the board built, opt-in modules not built = %q, want \" none\"", got)
	}
	// What a client sees: /stats names the board, which is what makes the
	// web UI show it, and the board's route answers.
	h, _ := wiredHub(t)
	named := false
	for _, m := range statsModules(t, h) {
		if m == "taskboard" {
			named = true
		}
	}
	if !named {
		t.Error("/stats.modules does not name the taskboard in a -tags taskboard build; the web UI would hide it")
	}
	if code, body := get(t, h, "/tasks/board"); code != http.StatusOK || !strings.Contains(string(body), `"columns"`) {
		t.Errorf("GET /tasks/board with -tags taskboard = %d %.80s, want the board", code, body)
	}
}
