package aghub_test

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

// FuzzKELPush drives POST /agents/kel:push (KEL §2.7, H-4) against one hub
// whose state the inputs build up: an agent registered here (its history
// extended, forked, rolled back, moved to another hub, ended by a dip, or
// replaced by fuzzed bytes), an agent that left, an AID nobody registered,
// and fuzzed AIDs and bodies. Whatever the request:
//
//   - the answer is 200, or a wire-3 refusal of the route's (400, 404, 409,
//     413), never a server error;
//   - a 200 names the tip of the history the hub now holds for the AID;
//   - the history held for an AID (its registration, or the tombstone it
//     left) only ever grows: each one extends the one held before, and
//     replays to the AID;
//   - an AID nobody registered here gets no row;
//   - a notice kept for an AID states the tip of its registration's
//     history, and none is kept for one that is not registered.
func FuzzKELPush(f *testing.F) {
	h := newFZ(f)
	h.srv.SetKELPushRateForTest(1e9, 1<<30)
	a, _ := h.agent(f, "fuzz-push", []string{"fuzz.push"}, true)
	left, _ := h.agent(f, "fuzz-left", nil, false)
	if rec := h.signedDo(left, relayauth.ActionDeregister, http.MethodPost, "/agents/"+left.AID()+"/deregister", "", nil); rec.Code != http.StatusOK {
		f.Fatalf("deregister: %d %s", rec.Code, rec.Body.Bytes())
	}
	stranger, err := aghub.NewAgentForTest()
	if err != nil {
		f.Fatal(err)
	}
	other, err := identitytest.Hub()
	if err != nil {
		f.Fatal(err)
	}
	// The controller of each pushing identity as the hub holds it, and
	// copies of earlier states to roll back or fork from.
	held := map[string]*identity.Controller{a.AID(): a, left.AID(): left}
	earlier := map[string][]*identity.Controller{a.AID(): {fzSnapshot(f, a)}, left.AID(): {fzSnapshot(f, left)}}
	lastStored := map[string][]identity.SignedEvent{}

	for _, seed := range []struct {
		who, mode uint8
		off       int16
		raw       []byte
	}{
		{0, 0, 0, nil}, {0, 1, 0, nil}, {0, 1, 400, nil}, {0, 2, 0, nil}, {0, 3, 0, nil}, {0, 4, 0, []byte("kel")},
		{0, 5, 0, nil}, {0, 6, 0, nil}, {1, 1, 0, nil}, {1, 6, 0, nil}, {2, 0, 0, nil},
		{3, 0, 0, []byte("bafy")}, {0, 7, 0, []byte(`{"aid":"x","kel":"AAAA","zz":1}`)},
	} {
		f.Add(seed.who, seed.mode, seed.off, seed.raw)
	}
	f.Fuzz(func(t *testing.T, who, mode uint8, off int16, raw []byte) {
		if len(raw) > 96<<10 {
			raw = raw[:96<<10]
		}
		var aid string
		var c *identity.Controller
		switch who % 4 {
		case 0:
			aid, c = a.AID(), held[a.AID()]
		case 1:
			aid, c = left.AID(), held[left.AID()]
		case 2:
			aid, c = stranger.AID(), stranger
		case 3:
			aid = string(raw)
		}
		// A new event's time: around now, off seconds away (up to 9 hours
		// either way), after the last event of the history.
		at := func() uint64 {
			ts := uint64(time.Now().UnixMilli() + int64(off)*1000)
			if c != nil {
				if last := c.KEL()[len(c.KEL())-1].Event.Timestamp; ts <= last {
					ts = last + 1
				}
			}
			return ts
		}
		var next *identity.Controller // the state pushed, adopted when taken
		kel := ""
		body := []byte(nil)
		switch mode % 8 {
		case 0: // the history as held
			if c != nil {
				kel = fzKELURL(t, c)
			}
		case 1, 5, 6: // a planned rot, a move to another hub, a dip
			if c == nil || c.State() == identity.StateDeactivated {
				return
			}
			next = fzSnapshot(t, c)
			var err error
			switch mode % 8 {
			case 1:
				err = identitytest.Rotate(next, at())
			case 5:
				err = identitytest.SwitchWitness(next, other.AID(), at())
			case 6:
				err = identitytest.Deactivate(next, at())
			}
			if err != nil {
				return
			}
			kel = fzKELURL(t, next)
		case 2, 3: // an earlier state, or a fork of one
			if c == nil || len(earlier[aid]) == 0 {
				return
			}
			e := fzSnapshot(t, earlier[aid][int(off&0x7fff)%len(earlier[aid])])
			if mode%8 == 3 {
				if e.State() == identity.StateDeactivated || identitytest.Rotate(e, at()+7) != nil {
					return
				}
			}
			kel = fzKELURL(t, e)
		case 4: // bytes
			kel = base64.RawURLEncoding.EncodeToString(raw)
		case 7: // a body
			body = raw
		}
		if body == nil {
			body = fzJSON(t, map[string]any{"aid": aid, "kel": kel})
		}
		req := h.request(http.MethodPost, aghub.KELPushPath, "", body)
		rec := h.serve(req)
		if !allowed(rec.Code, 200, 400, 404, 409, 413) {
			t.Fatalf("push: unexpected %d %s", rec.Code, rec.Body.Bytes())
		}
		for _, p := range wire3test.Contract(rec.Code, rec.Header(), rec.Body.Bytes()) {
			t.Fatalf("push: %s", p)
		}
		stored, registered := fzStoredKEL(t, h, aid)
		if rec.Code == http.StatusOK {
			var out aghub.KELPushResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.AID != aid || stored == nil {
				t.Fatalf("push answered 200 with %s (holding %d events)", rec.Body.Bytes(), len(stored))
			}
			tip := stored[len(stored)-1]
			if out.Seq != tip.Event.Seq || out.Head != tip.EventID {
				t.Fatalf("push answered the tip %d %s, the hub holds %d %s", out.Seq, out.Head, tip.Event.Seq, tip.EventID)
			}
			if next != nil && !out.Unchanged {
				held[aid] = next
				earlier[aid] = append(earlier[aid], fzSnapshot(t, next))
			}
		}
		if aid == stranger.AID() || who%4 == 3 {
			if aid != a.AID() && aid != left.AID() && stored != nil {
				t.Fatalf("a push for an AID nobody registered left a history for it")
			}
		}
		if stored != nil {
			states, err := identity.Replay(stored)
			if err != nil || states[len(states)-1].AID != aid {
				t.Fatalf("the hub holds a history that does not replay to %s: %v", aid, err)
			}
			if prev := lastStored[aid]; prev != nil {
				if err := identity.ExtendsKEL(prev, stored); err != nil {
					t.Fatalf("the history held for %s went from %d to %d events without extending: %v", aid, len(prev), len(stored), err)
				}
			}
			lastStored[aid] = stored
		}
		seq, head, _, _, ok := h.store.NoticeRowForTest(aid)
		switch {
		case ok && !registered:
			t.Fatalf("a notice is kept for %s, which is not registered", aid)
		case ok && (seq != stored[len(stored)-1].Event.Seq || head != stored[len(stored)-1].EventID):
			t.Fatalf("the notice kept for %s states %d %s, its history ends at %d %s",
				aid, seq, head, stored[len(stored)-1].Event.Seq, stored[len(stored)-1].EventID)
		}
	})
}

// fzSnapshot is a second controller of c's identity as it is now.
func fzSnapshot(tb testing.TB, c *identity.Controller) *identity.Controller {
	tb.Helper()
	blob, err := c.Export()
	if err != nil {
		tb.Fatal(err)
	}
	s, err := identity.Restore(blob)
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

// fzKELURL is c's KEL in base64url.
func fzKELURL(tb testing.TB, c *identity.Controller) string {
	tb.Helper()
	b, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		tb.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// fzStoredKEL is the history the hub holds for aid, from the second
// connection: the agent row (registered) or the tombstone; nil for none.
func fzStoredKEL(tb testing.TB, h *fz, aid string) ([]identity.SignedEvent, bool) {
	tb.Helper()
	var raw []byte
	registered := true
	err := h.db.QueryRow(`SELECT kel FROM agent WHERE aid=?`, aid).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		registered = false
		err = h.db.QueryRow(`SELECT kel FROM departed_kel WHERE aid=?`, aid).Scan(&raw)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	if err != nil {
		tb.Fatal(err)
	}
	kel, err := identity.UnmarshalKEL(raw)
	if err != nil {
		tb.Fatalf("the hub holds a history for %s that does not decode: %v", aid, err)
	}
	return kel, registered
}
