package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// wiredHub wires every module compiled into this test binary against a
// fresh kernel, the way main does, and returns the root handler and the
// names wireMounts reported.
func wiredHub(t *testing.T) (http.Handler, []string) {
	t.Helper()
	dir := t.TempDir()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv0 := aghub.NewServer(store)
	srv0.SetHubAID(id.AID)
	root := http.NewServeMux()
	root.Handle("/hub/identity", id.Handler())
	root.Handle("/", srv0.Handler())
	wired, closers, err := wireMounts(&hubDeps{data: dir, store: store, hubID: id, srv0: srv0, root: root})
	t.Cleanup(func() {
		for i := len(closers) - 1; i >= 0; i-- {
			_ = closers[i]()
		}
		store.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
	return root, wired
}

// get answers one GET against h.
func get(t *testing.T, h http.Handler, path string) (int, []byte) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Code, w.Body.Bytes()
}

// statsModules is /stats.modules as a client reads it.
func statsModules(t *testing.T, h http.Handler) []string {
	t.Helper()
	code, body := get(t, h, "/stats")
	if code != http.StatusOK {
		t.Fatalf("/stats: %d %s", code, body)
	}
	var st struct {
		Modules []string `json:"modules"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	return st.Modules
}

func mountNames() []string {
	var out []string
	for _, m := range mounts {
		out = append(out, m.name)
	}
	return out
}

// /stats.modules is the list of modules this build wired, in order. The
// web UI shows the task board only when the list names it, so a build
// that wired the board but did not report it would hide a working board,
// and one that reported a module it lacks would send the page to routes
// that do not exist. Checked in every tag configuration CI runs.
func TestStatsNamesTheWiredModules(t *testing.T) {
	h, wired := wiredHub(t)
	want := strings.Join(mountNames(), ",")
	if got := strings.Join(wired, ","); got != want {
		t.Errorf("wireMounts wired %q, want every compiled-in module %q", got, want)
	}
	if got := strings.Join(statsModules(t, h), ","); got != want {
		t.Errorf("/stats.modules = %q, want the wired modules %q", got, want)
	}
}
