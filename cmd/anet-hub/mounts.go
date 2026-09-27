package main

import (
	"fmt"
	"net/http"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// hubDeps is what optional hub modules may wire against (K207: modules see
// the kernel and the mux, never each other).
type hubDeps struct {
	data  string
	store *aghub.Store
	hubID *hubid.Identity
	srv0  *aghub.Server
	root  *http.ServeMux
	// noFedKeyLookup is -test-no-fed-key-lookup: federation does not
	// install the /fed/v2/keys lookup on the kernel (test runs only).
	noFedKeyLookup bool
}

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
