package main

import (
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
}

// mount is one compiled-in optional module; a `no_<name>` build tag
// subtracts its file and with it the module (拔插头 in the build).
type mount struct {
	name string
	wire func(*hubDeps) (func() error, error) // returns optional closer
}

var mounts []mount

func registerMount(m mount) { mounts = append(mounts, m) }
