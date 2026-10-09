package aghub

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"

	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

func init() { wire3Setups["kel"] = wire3KELSetup }

// wire3KELSetup is the hub of wire3HubSetup for the fixtures of the hub as a
// witness (testdata/wire3/kel.json; KEL §2.7, H-1 to H-5, H-10 to H-13):
// POST /agents/kel:push, GET /agents/{aid}/kel, the notice members of
// /register and /relay/poll, key_retired. The hub's clock (the store's)
// stands at one millisecond for the whole file, so each notice it signs is
// fixed bytes: ${X_notice} is the notice of X's tip, observed then.
//
// Identities (each a ${name} variable, its AID):
//
//	alice      registered, names this hub; ${alice_kel}
//	rotor      registered, names this hub; ${rotor_kel}. ${rotor_kel2} adds
//	           a planned rot (its tip: seq 2, ${rotor_head2});
//	           ${rotor_fork_kel} forks from ${rotor_kel}; ${rotor_ahead_kel}
//	           extends ${rotor_kel2} with a rot 10 minutes ahead of the
//	           clock. rotor_old signs with rotor's key before the rot.
//	gone       registered and on the admission list; ${gone_dip_kel} ends
//	           in its dip (seq 2).
//	           gone_signer signs with its key before it.
//	moved      registered, its tip names another hub (as the store holds an
//	           agent whose move was pushed here)
//	newbie     on the admission list, names this hub; ${newbie_kel}
//	pending    on the list, its icp only: no witness yet; ${pending_kel}
//	elsewhere  on the list, names another hub; ${elsewhere_kel}
//	late       on the list, named this hub 10 minutes before the clock;
//	           ${late_kel}
//	stranger   known nowhere; ${stranger_kel}
//
// ${hub_kel} is the hub's own key history.
func wire3KELSetup(t *testing.T) *wire3test.Env {
	t.Helper()
	env, store, signers := wire3Hub(t)
	hubAID := env.Vars["hub"]
	clock := time.UnixMilli(time.Now().UnixMilli())
	store.clock = func() time.Time { return clock }
	b64 := base64.RawURLEncoding.EncodeToString
	kelOf := func(c *identity.Controller) string {
		b, err := identity.MarshalKEL(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		return b64(b)
	}
	put := func(c *identity.Controller, name string) {
		b, err := identity.MarshalKEL(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.PutAgent(c.AID(), name, nil, b); err != nil {
			t.Fatal(err)
		}
	}
	agent := func(name string, at time.Time) *identity.Controller {
		c, err := NewAgentWitnessedBy(hubAID, at)
		if err != nil {
			t.Fatal(err)
		}
		signers[name], env.Vars[name] = c, c.AID()
		return c
	}
	snapshot := func(c *identity.Controller) *identity.Controller {
		blob, err := c.Export()
		if err != nil {
			t.Fatal(err)
		}
		s, err := identity.Restore(blob)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	last := func(c *identity.Controller) identity.SignedEvent { kel := c.KEL(); return kel[len(kel)-1] }
	noticeOf := func(c *identity.Controller) string {
		tip := last(c)
		n, err := identity.SignNotice(identity.SuiteController(), identity.NoticeBody{
			AID: c.AID(), Seq: tip.Event.Seq, Head: tip.EventID, ObservedAt: uint64(clock.UnixMilli())})
		if err != nil {
			t.Fatal(err)
		}
		return b64(n)
	}
	other, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}

	alice := signers["alice"]
	env.Vars["alice_kel"], env.Vars["alice_notice"] = kelOf(alice), noticeOf(alice)

	rotor := agent("rotor", clock)
	put(rotor, "rotor")
	env.Vars["rotor_kel"] = kelOf(rotor)
	signers["rotor_old"] = snapshot(rotor)
	fork := snapshot(rotor)
	if err := identitytest.Rotate(rotor, last(rotor).Event.Timestamp+1); err != nil {
		t.Fatal(err)
	}
	env.Vars["rotor_kel2"], env.Vars["rotor_head2"] = kelOf(rotor), last(rotor).EventID
	if last(rotor).Event.Seq != 2 {
		t.Fatalf("setup: rotor's tip is seq %d, the file says 2", last(rotor).Event.Seq)
	}
	if err := identitytest.Rotate(fork, last(rotor).Event.Timestamp+7); err != nil {
		t.Fatal(err)
	}
	env.Vars["rotor_fork_kel"] = kelOf(fork)
	ahead := snapshot(rotor)
	if err := identitytest.Rotate(ahead, uint64(clock.Add(10*time.Minute).UnixMilli())); err != nil {
		t.Fatal(err)
	}
	env.Vars["rotor_ahead_kel"] = kelOf(ahead)

	gone := agent("gone", clock)
	put(gone, "gone")
	signers["gone_signer"] = snapshot(gone)
	// On the admission list, so that its registration after the dip gets
	// past the gate to the key history (PAY-A1 step 4 comes first).
	if _, err := store.Admit(gone.AID(), 0, "", false); err != nil {
		t.Fatal(err)
	}
	if err := identitytest.Deactivate(gone, last(gone).Event.Timestamp+1); err != nil {
		t.Fatal(err)
	}
	env.Vars["gone_dip_kel"] = kelOf(gone)
	if last(gone).Event.Seq != 2 {
		t.Fatalf("setup: gone's dip is seq %d, the file says 2", last(gone).Event.Seq)
	}

	moved, err := NewAgentWitnessedBy(other.AID(), clock)
	if err != nil {
		t.Fatal(err)
	}
	signers["moved"], env.Vars["moved"] = moved, moved.AID()
	put(moved, "moved")

	listed := func(c *identity.Controller, name string) {
		if _, err := store.Admit(c.AID(), 0, "", false); err != nil {
			t.Fatal(err)
		}
		signers[name], env.Vars[name], env.Vars[name+"_kel"] = c, c.AID(), kelOf(c)
	}
	newbie := agent("newbie", clock)
	listed(newbie, "newbie")
	env.Vars["newbie_notice"] = noticeOf(newbie)
	pending, err := identitytest.Agent()
	if err != nil {
		t.Fatal(err)
	}
	listed(pending, "pending")
	elsewhere, err := NewAgentWitnessedBy(other.AID(), clock)
	if err != nil {
		t.Fatal(err)
	}
	listed(elsewhere, "elsewhere")
	late := agent("late", clock.Add(-10*time.Minute))
	listed(late, "late")

	stranger, err := NewAgentForTest()
	if err != nil {
		t.Fatal(err)
	}
	env.Vars["stranger"], env.Vars["stranger_kel"] = stranger.AID(), kelOf(stranger)
	env.Vars["hub_kel"] = kelOf(identity.SuiteController())
	return env
}
