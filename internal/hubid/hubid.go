// Package hubid gives the hub a first-class identity: an Ed25519 KEL of its
// own, persisted in the data dir (the guest-broker precedent, promoted).
// This AID is what federation peers verify (K208 §2) and what the hub will
// sign ForwardEnvelopes with.
//
// The identity is a hub identity (toad 0, KEL H-30): no witness, ever. Its
// file is the identity file v2 (KEL §2.9, hub_identity.kel), written
// temporary file, fsync, rename. Its icp commits a hot key (C-32), which
// `anet-hub identity setup-recovery` reveals in the first rotation; every
// later next key comes from the recovery seed, which only the anet-hub
// command holds, outside the data directory (cmd/anet-hub identity_ops.go).
// Rotations happen while the hub is stopped (H-32): the hub holds the data
// directory's lock (Lock) for as long as it runs.
package hubid

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// FileName is the hub identity file in the hub data directory.
const FileName = "hub_identity.kel"

// ErrIdentityV02 is a hub identity file that is not an identity file v2: a
// 0.2 hub's, which 0.3.0 does not carry over (KEL S-2; core CORE-V4). The
// hub refuses to start on it (hub_identity_v02) and leaves it where it is.
var ErrIdentityV02 = identity.ErrNotIdentityV2

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

// path is the identity file of the hub data directory dir.
func path(dir string) string { return filepath.Join(dir, FileName) }

// CheckFile reports whether the hub identity file in dir, if there is one,
// is one this release opens, without writing anything: nil when there is
// none or it is an identity file v2, ErrIdentityV02 for a 0.2 file (or any
// file that is not an identity file v2 at all). The hub checks it before it
// opens or creates anything in dir.
func CheckFile(dir string) error {
	b, err := os.ReadFile(path(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = identity.ParseIdentityFile(b)
	return err
}

// Exists reports whether dir holds a hub identity file.
func Exists(dir string) bool {
	_, err := os.Stat(path(dir))
	return err == nil
}

// Load restores the hub identity of dir. A directory without one is
// os.ErrNotExist; a 0.2 identity file is ErrIdentityV02.
func Load(dir string) (*Identity, error) {
	b, err := os.ReadFile(path(dir))
	if err != nil {
		return nil, err
	}
	ctrl, err := identity.Restore(b)
	if err != nil {
		return nil, err
	}
	if ctrl.Toad() != identity.ToadHub {
		return nil, fmt.Errorf("hubid: %s is an agent's identity (toad %d), not a hub's", path(dir), ctrl.Toad())
	}
	return newIdentity(ctrl)
}

// LoadOrIncept restores the persisted hub identity or incepts one on first
// run (stable AID across restarts). The new identity file is written
// temporary file, fsync, rename (KEL §2.9), so a crash leaves either no file
// or a whole one.
func LoadOrIncept(dir string) (*Identity, error) {
	id, err := Load(dir)
	if !errors.Is(err, os.ErrNotExist) {
		return id, err
	}
	ctrl, err := identity.InceptHub(uint64(time.Now().UnixMilli()))
	if err != nil {
		return nil, err
	}
	id, err = newIdentity(ctrl)
	if err != nil {
		return nil, err
	}
	if err := id.Save(dir); err != nil {
		return nil, err
	}
	return id, nil
}

func newIdentity(ctrl *identity.Controller) (*Identity, error) {
	kel, err := identity.MarshalKEL(ctrl.KEL())
	if err != nil {
		return nil, err
	}
	return &Identity{Ctrl: ctrl, AID: ctrl.AID(), KEL: kel}, nil
}

// Save writes the identity file of i into dir: temporary file, fsync,
// rename, fsync of the directory (KEL §2.9). The file holds the hub's
// private key and is written 0600.
func (i *Identity) Save(dir string) error {
	blob, err := i.Ctrl.Export()
	if err != nil {
		return err
	}
	return WriteFileAtomic(path(dir), blob, 0o600)
}

// RecoverySet reports whether the hub's recovery seed is set up: the icp's
// hot key has been revealed (anet-hub identity setup-recovery, KEL H-31), so
// the next key of the hub is no longer in its data directory. Until then
// the hub says hub_recovery_setup_required at every start.
func (i *Identity) RecoverySet() bool { return len(i.Ctrl.Accepted()) > 1 }

// Seq is the key state the hub signs under: the seq of its KEL's last event.
func (i *Identity) Seq() uint64 { return i.Ctrl.CurrentSeq() }

// Commitment is the next-key digest the KEL's last event commits (KeyEvent
// key 6): the key the next rotation must reveal.
func (i *Identity) Commitment() []byte {
	kel := i.Ctrl.Accepted()
	return append([]byte(nil), kel[len(kel)-1].Event.NextDigest...)
}

// Rotate rotates the hub identity in memory (KEL H-31, H-32): a rot at ts,
// or one millisecond after the last event when ts is not later than it,
// that reveals revealed (nil: the icp's hot key, which only the first
// rotation reveals) and commits next, with key 12 when emergency. A hub's
// rot needs no witness, so it is the hub's at once. The caller saves the
// identity (Save) before it relies on the rotation.
func (i *Identity) Rotate(revealed ed25519.PrivateKey, next []byte, emergency bool, ts uint64) error {
	kel := i.Ctrl.Accepted()
	if last := kel[len(kel)-1].Event.Timestamp; ts <= last {
		ts = last + 1
	}
	ev, err := i.Ctrl.BuildRotation(revealed, next, "", emergency, ts)
	if err != nil {
		return err
	}
	if err := i.Ctrl.Adopt(ev); err != nil {
		return err
	}
	b, err := identity.MarshalKEL(i.Ctrl.KEL())
	if err != nil {
		return err
	}
	i.KEL = b
	return nil
}

// WriteFileAtomic writes data to name through a temporary file in the same
// directory: write, fsync, rename over name, fsync the directory. A crash
// leaves either the old file or the new one, never a torn one.
func WriteFileAtomic(name string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(name)
	f, err := os.CreateTemp(dir, "."+filepath.Base(name)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once renamed
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		return err
	}
	return SyncDir(dir)
}

// SyncDir fsyncs the directory dir, so a rename in it is durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
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
