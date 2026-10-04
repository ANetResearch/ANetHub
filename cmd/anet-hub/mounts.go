package main

import (
	"fmt"
	"net/http"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// hubDeps is what optional hub modules may wire against (K207: modules see
// the kernel and the mux, never each other).
type hubDeps struct {
	data  string
	store *aghub.Store
	hubID *hubid.Identity
	srv0  *aghub.Server
	root  *http.ServeMux
}

// newRoot is the hub's root mux: hub modules mount beside the
// registry/relay kernel. The taskboard authenticates against the same
// agent registry (one KEL, one auth scheme); /hub/identity is the
// federation trust anchor (K208).
func newRoot(id *hubid.Identity, srv0 *aghub.Server) *http.ServeMux {
	root := http.NewServeMux()
	root.Handle("/hub/identity", id.Handler())
	root.Handle("/", srv0.Handler())
	return root
}

// hubHandler is what the hub serves: the root, kernel and modules alike,
// under the wire-3 contract (core CORE-V1). Every response states the
// wire, and a caller of another wire is refused on /fed/* and on a
// module's routes exactly as on the kernel's.
func hubHandler(root http.Handler) http.Handler { return wire3.Contract(root) }

// mount is one compiled-in optional module. A subtractive tag
// (`-tags no_<name>`) removes the file that registers it from the default
// build; an additive tag (`-tags <name>`, see optin_tags.go) is needed to
// compile that file in at all.
type mount struct {
	name string
	wire func(*hubDeps) (func() error, error) // returns optional closer
}

var mounts []mount

func registerMount(m mount) { mounts = append(mounts, m) }

// wireMounts wires every compiled-in module against d, in registration
// order, and records their names on the kernel server, which reports them
// as /stats.modules. That list is how a client (the web UI's task board)
// tells a module this build lacks from one that is present and empty.
//
// It returns the names wired and the closers of the modules that have
// one. On an error the modules wired before the failing one are in the
// returned lists, so the caller can still close them, and the module list
// is not recorded.
func wireMounts(d *hubDeps) (wired []string, closers []func() error, err error) {
	for _, m := range mounts {
		closer, err := m.wire(d)
		if err != nil {
			return wired, closers, fmt.Errorf("module %s: %w", m.name, err)
		}
		if closer != nil {
			closers = append(closers, closer)
		}
		wired = append(wired, m.name)
	}
	d.srv0.SetModules(wired)
	return wired, closers, nil
}
