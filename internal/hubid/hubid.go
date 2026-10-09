// Package hubid gives the hub a first-class identity: an Ed25519 KEL of its
// own, persisted in the data dir (the guest-broker precedent, promoted).
// This AID is what federation peers verify (K208 §2) and what the hub will
// sign ForwardEnvelopes with.
package hubid

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Identity is the hub's own KEL-backed identity.
type Identity struct {
	Ctrl *identity.Controller
	AID  string
	KEL  []byte // marshaled KEL (CoreDet-CBOR)
	// DirMaxBits, when set, is the widest directory bucket prefix this hub
	// answers (dir_max_bits; aghub.Server.DirMaxBits). Set it before
	// serving; unset, /hub/identity states 0, the whole directory.
	DirMaxBits func() int
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
		ctrl, ierr = identity.InceptHub(uint64(time.Now().UnixMilli()))
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

// IdentityResponse is the body of GET /hub/identity.
type IdentityResponse struct {
	AID string `json:"aid"`
	// KEL is the hub's key history, CoreDet CBOR in base64url without
	// padding, like every binary value of hub wire 3 (core CORE-E5).
	KEL string `json:"kel"`
	// Wire is the hub wire contract this hub speaks (core CORE-V1): a
	// daemon or a peer can tell before its first signed request whether
	// it can talk to this hub at all.
	Wire int `json:"wire"`
	// DirMaxBits is the widest prefix, in bits, this hub answers a
	// directory bucket for (sealed-sender SSR-W18). A daemon caps what it
	// asks for at a constant of its own whatever this says (SSR-D15a).
	DirMaxBits int `json:"dir_max_bits"`
}

// Handler serves GET /hub/identity: the hub's AID + KEL so peers and agents
// can verify hub-signed objects, the wire it speaks and the widest directory
// bucket it answers. Any other method is 404 not_found in the wire-3 error
// body.
//
// The body is built per request from the identity as it is then, so a KEL
// that grows (a rotation) is served as it is, never as it was when the
// handler was made.
func (i *Identity) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Normally stamped by wire3.Contract around the whole hub; stated
		// here too so the answer is right wherever it is mounted.
		w.Header().Set(wire3.Header, strconv.Itoa(wire3.Version))
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			wire3.Refuse(w, wire3.ReasonNotFound)
			return
		}
		out := IdentityResponse{AID: i.AID, KEL: wire3.EncodeB64URL(i.KEL), Wire: wire3.Version}
		if i.DirMaxBits != nil {
			out.DirMaxBits = i.DirMaxBits()
		}
		body, err := json.Marshal(out)
		if err != nil {
			wire3.Internal(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(body)
	})
}
