package hubid

import (
	"fmt"
	"slices"
	"sync"
)

// The secrets an emergency rotation of the hub identity replaces (KEL H-33,
// core G18).
//
// An emergency rotation says the hub's data directory may have leaked. A
// new identity key does not undo that alone: every secret the hub keeps to
// authenticate or to tag with was in the same directory, so each is
// generated again. The list is here so that it is one list: an area that
// adds a persistent secret of that kind registers it (its name and how to
// make a new one), and `anet-hub identity rotate --emergency` replaces each
// and says which. pow_key lives in process memory only and the first-contact
// session keys are made one by one at random, so neither is listed.

// EmergencySecret is one secret an emergency rotation replaces.
type EmergencySecret struct {
	// Name is how the operator knows the secret: a file of the hub data
	// directory, or the setting that holds it.
	Name string
	// Regenerate replaces the secret in the hub data directory dir with a
	// fresh one. Nil for a secret anet-hub does not keep (it lives outside
	// the data directory): the operator replaces it, and the rotation says
	// so by name.
	Regenerate func(dir string) error
}

var (
	secretsMu sync.Mutex
	secrets   []EmergencySecret
)

// RegisterEmergencySecret adds s to the list. A name is registered once; an
// empty or repeated one is a programming error.
func RegisterEmergencySecret(s EmergencySecret) {
	secretsMu.Lock()
	defer secretsMu.Unlock()
	if s.Name == "" {
		panic("hubid: an emergency secret needs a name")
	}
	for _, have := range secrets {
		if have.Name == s.Name {
			panic(fmt.Sprintf("hubid: emergency secret %q registered twice", s.Name))
		}
	}
	secrets = append(secrets, s)
}

// EmergencySecrets is the list, in the order of registration.
func EmergencySecrets() []EmergencySecret {
	secretsMu.Lock()
	defer secretsMu.Unlock()
	return slices.Clone(secrets)
}

// AdminTokenSecret names the hub admin token (core G18): the ADMIN_TOKEN
// of anet-hub-admin, which its service's environment holds, not the hub
// data directory, so anet-hub cannot replace it.
const AdminTokenSecret = "ADMIN_TOKEN (anet-hub-admin)"

func init() {
	RegisterEmergencySecret(EmergencySecret{Name: AdminTokenSecret})
}

// RegenerateEmergencySecrets replaces every registered secret anet-hub
// keeps in the hub data directory dir, and returns the names it replaced
// and those the operator has to replace. It goes on past a secret it
// cannot replace and returns the first error with the names done so far.
func RegenerateEmergencySecrets(dir string) (replaced, byOperator []string, err error) {
	for _, s := range EmergencySecrets() {
		if s.Regenerate == nil {
			byOperator = append(byOperator, s.Name)
			continue
		}
		if rerr := s.Regenerate(dir); rerr != nil {
			if err == nil {
				err = fmt.Errorf("hubid: replacing %s: %w", s.Name, rerr)
			}
			byOperator = append(byOperator, s.Name)
			continue
		}
		replaced = append(replaced, s.Name)
	}
	return replaced, byOperator, err
}
