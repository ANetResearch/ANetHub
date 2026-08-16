// Package hubid gives the hub a first-class identity: an Ed25519 KEL of its
// own, persisted in the data dir (the guest-broker precedent, promoted).
// This AID is what federation peers verify (K208 §2) and what the hub will
// sign ForwardEnvelopes with.
package hubid

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ANetResearch/ANetCore/identity"
)

// Identity is the hub's own KEL-backed identity.
type Identity struct {
	Ctrl *identity.Controller
	AID  string
	KEL  []byte // marshaled KEL (CoreDet-CBOR)
}

// LoadOrIncept restores the persisted hub identity or incepts one on first
// run (stable AID across restarts).
func LoadOrIncept(dir string) (*Identity, error) {
	path := filepath.Join(dir, "hub_identity.kel")
	var ctrl *identity.Controller
	if b, err := os.ReadFile(path); err == nil {
		ctrl, err = identity.Restore(b)
		if err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		var ierr error
		ctrl, ierr = identity.Incept()
		if ierr != nil {
			return nil, ierr
		}
		blob, ierr := ctrl.Export()
		if ierr != nil {
			return nil, ierr
		}
		if ierr := os.WriteFile(path, blob, 0o600); ierr != nil {
			return nil, ierr
		}
	}
	kel, err := identity.MarshalKEL(ctrl.KEL())
	if err != nil {
		return nil, err
	}
	return &Identity{Ctrl: ctrl, AID: ctrl.AID(), KEL: kel}, nil
}

// Sign signs a preimage with the hub's current key.
func (i *Identity) Sign(preimage []byte) (sig []byte, keyStateSeq uint64) {
	return i.Ctrl.Sign(preimage)
}

// Handler serves GET /hub/identity: the hub's AID + KEL so peers and agents
// can verify hub-signed objects.
func (i *Identity) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write([]byte(`{"aid":"` + i.AID + `","kel":"` + base64.StdEncoding.EncodeToString(i.KEL) + `"}`))
	})
}
