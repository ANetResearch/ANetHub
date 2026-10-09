package hubid

import (
	"fmt"
	"sync"
)

// The secrets a hub emergency rotation replaces (kel-rotation H-33, core
// G18).
//
// An emergency rotation says the hub's identity key may be in somebody
// else's hands, and with it whatever else lay in the same data directory.
// Every persistent secret there that authenticates or tags something is
// therefore made anew together with the key. Each area that keeps such a
// secret registers it here, with its name and the function that makes a new
// one; the rotation runs every entry and names them to the operator
// (hub_identity.secrets_regenerated). A secret that lives only in the hub
// process's memory (the proof-of-work key, a first-contact session key) is
// gone at the restart the rotation needs anyway and is not listed.

// EmergencySecret is one persistent secret of the hub's data directory.
type EmergencySecret struct {
	// Name is how the operator is told about it, e.g. hub_tag_key.
	Name string
	// Regenerate replaces the secret in the data directory dir with a new
	// one. It runs while the hub is stopped (KEL H-32), and returns only
	// once the old secret is no longer usable.
	Regenerate func(dir string) error
}

var emergency struct {
	mu   sync.Mutex
	list []EmergencySecret
}

// RegisterEmergencySecret adds s to the list an emergency rotation
// regenerates. The package that owns the secret calls it from init. A
// second secret of the same name, or one without a name or a function, is a
// programming error and panics.
func RegisterEmergencySecret(s EmergencySecret) {
	if s.Name == "" || s.Regenerate == nil {
		panic("hubid: an emergency secret needs a name and a Regenerate function")
	}
	emergency.mu.Lock()
	defer emergency.mu.Unlock()
	for _, e := range emergency.list {
		if e.Name == s.Name {
			panic(fmt.Sprintf("hubid: emergency secret %s registered twice", s.Name))
		}
	}
	emergency.list = append(emergency.list, s)
}

// EmergencySecrets is the list an emergency rotation regenerates, in the
// order the secrets were registered.
func EmergencySecrets() []EmergencySecret {
	emergency.mu.Lock()
	defer emergency.mu.Unlock()
	return append([]EmergencySecret(nil), emergency.list...)
}
