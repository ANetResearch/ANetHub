package aghub

import (
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// The identities the tests of this package register with.
//
// A hub registers only the agents whose key history names it as their
// witness (KEL H-1), as a daemon's does once it has joined (KEL D-13): an
// agent identity (toad 1) whose first rot names the hub. The test hubs sign
// as the conformance hub identity (identity.SuiteController), whose AID is
// identitytest.Witness, so an agent of NewAgentForTest can register at any
// of them, and everything it signs (key sets, cards, receipts, requests) is
// signed under the key state it registers with. A test of two hubs gives the
// second one an identity of its own (hubid.LoadOrIncept) and its agents a
// rot naming that one (identitytest.SwitchWitness).

// HubIdentityForTest is the identity a test hub signs as.
func HubIdentityForTest(t testing.TB) *hubid.Identity {
	t.Helper()
	c := identity.SuiteController()
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return &hubid.Identity{Ctrl: c, AID: c.AID(), KEL: kel}
}

// NewAgentForTest is a new agent identity that has named the test hubs'
// identity as its witness, now.
func NewAgentForTest() (*identity.Controller, error) {
	return NewAgentWitnessedBy(identitytest.Witness, time.Now())
}

// NewAgentWitnessedBy is a new agent identity whose first rot, at at, names
// hubAID as its witness.
func NewAgentWitnessedBy(hubAID string, at time.Time) (*identity.Controller, error) {
	c, err := identitytest.Agent()
	if err != nil {
		return nil, err
	}
	if err := identitytest.SwitchWitness(c, hubAID, uint64(at.UnixMilli())); err != nil {
		return nil, err
	}
	return c, nil
}
