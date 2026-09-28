//go:build taskboard

package taskboard_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/taskboard"
)

// FuzzTaskboardWrites runs a fuzzed sequence of task board writes (ANet
// docs/notes/0033-验证-模糊测试-hub.md). Each step picks an action, an
// actor among three registered agents, a card, a column, text fields and
// a time offset; the harness signs the challenge as the actor, and some
// steps tamper with it (another actor's AID, another action, a flipped
// signature bit) or replace the body with raw fuzz. After every step:
//
//   - the answer is 200, 400, 401, 403, 404, 409 or 413, never a 5xx;
//   - a tampered step, or one signed outside the ±5 min window, is
//     refused with 401 and changes nothing;
//   - the card a step names is in a consistent state: created cards sit in
//     draft/backlog/ready unassigned, claimed ones in in_progress or
//     blocked with an assignee, submitted ones in in_review, accepted ones
//     in done; and every accept in a card's trail was made by its creator.
func FuzzTaskboardWrites(f *testing.F) {
	dir := f.TempDir()
	hub, err := aghub.Open(dir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { hub.Close() })
	board, err := taskboard.Open(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { board.Close() })
	h := taskboard.NewServer(board, hub).Handler()
	var actors []*identity.Controller
	for i := 0; i < 3; i++ {
		c, err := identity.Incept()
		if err != nil {
			f.Fatal(err)
		}
		kel, _ := identity.MarshalKEL(c.KEL())
		if err := hub.PutAgent(c.AID(), "actor", nil, kel); err != nil {
			f.Fatal(err)
		}
		actors = append(actors, c)
	}
	actions := []string{"create", "move", "claim", "submit", "accept", "reject", "block", "unblock"}
	columns := []string{"draft", "backlog", "ready", "in_progress", "in_review", "done", "blocked", "", "nowhere"}
	var cards []string

	// A step is 6 bytes: action, actor, card, column, tamper, skew.
	f.Add([]byte{0, 0, 0, 2, 0, 0, 2, 1, 0, 0, 0, 0, 3, 1, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0}, "title", "note", []byte(nil))
	f.Add([]byte{0, 0, 0, 2, 0, 0, 2, 1, 0, 0, 0, 0, 6, 1, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0}, "t", "n", []byte(nil))
	f.Add([]byte{0, 0, 0, 2, 1, 0, 2, 1, 0, 0, 2, 0, 1, 0, 0, 0, 3, 0}, "t", "", []byte(nil))
	f.Add([]byte{0, 0, 0, 2, 0, 200, 0, 0, 0, 2, 0, 100}, "t", "n", []byte(nil))
	f.Add([]byte{3, 1, 0, 0, 4, 0}, "t", "n", []byte(`{"aid":"x","ts":1,"sig":"AAAA"}`))

	f.Fuzz(func(t *testing.T, steps []byte, title, note string, raw []byte) {
		if len(steps) > 6*24 {
			steps = steps[:6*24]
		}
		if len(title) > 256 {
			title = title[:256]
		}
		if len(note) > 256 {
			note = note[:256]
		}
		for ; len(steps) >= 6; steps = steps[6:] {
			action := actions[int(steps[0])%len(actions)]
			actor := actors[int(steps[1])%len(actors)]
			card := "card-none"
			if len(cards) > 0 {
				card = cards[len(cards)-1-int(steps[2])%len(cards)]
			}
			col := columns[int(steps[3])%len(columns)]
			tamper := steps[4]
			// skew: 0..127 is inside the window, above it is outside.
			skew := time.Duration(int8(steps[5])) * 5 * time.Second
			ts := uint64(time.Now().Add(skew).UnixMilli())
			signAction, signer := "task."+action, actor
			if tamper&1 != 0 {
				signAction = "task.other"
			}
			if tamper&2 != 0 {
				signer = actors[(int(steps[1])+1)%len(actors)]
			}
			sig, seq := signer.Sign(relayauth.Preimage(signAction, actor.AID(), ts))
			if tamper&4 != 0 {
				sig[int(steps[5])%len(sig)] ^= 1
			}
			body, _ := json.Marshal(map[string]any{
				"aid": actor.AID(), "ts": ts, "key_state_seq": seq, "sig": base64.StdEncoding.EncodeToString(sig),
				"card_id": card, "title": title, "taskdoc_cid": "bafy-" + title, "column": col, "note": note,
			})
			rawStep := tamper&8 != 0 && len(raw) > 0
			if rawStep {
				body = raw
			}
			tampered := tamper&7 != 0
			outWindow := skew < -5*time.Minute-5*time.Second || skew > 5*time.Minute+5*time.Second
			before := snapshotCard(t, board, card)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tasks/"+action, bytes.NewReader(body)))
			if !allowed(rec.Code, 200, 400, 401, 403, 404, 409, 413) {
				t.Fatalf("%s: unexpected %d %s", action, rec.Code, rec.Body.Bytes())
			}
			if !rawStep && (tampered || outWindow) {
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("%s tampered (%04b) or signed %s off: %d %s", action, tamper&7, skew, rec.Code, rec.Body.Bytes())
				}
				if after := snapshotCard(t, board, card); after != before {
					t.Fatalf("a refused %s changed the board", action)
				}
			}
			if rec.Code == http.StatusOK && action == "create" {
				var out struct {
					Card taskboard.Card `json:"card"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				if !rawStep && out.Card.CreatorAID != actor.AID() {
					t.Fatalf("a card created by %s names creator %s", actor.AID(), out.Card.CreatorAID)
				}
				cards = append(cards, out.Card.ID)
				if len(cards) > 64 {
					cards = cards[len(cards)-64:]
				}
				checkCard(t, board, out.Card.ID)
			}
			checkCard(t, board, card)
		}
	})
}

// FuzzTaskboardChallengeTime signs a task.create challenge at now plus a
// fuzzed offset across the whole uint64 range (wrapping), and checks the
// replay window: a challenge is accepted only when its time is within
// relayauth.MaxSkewMillis of the hub's clock.
func FuzzTaskboardChallengeTime(f *testing.F) {
	hub, err := aghub.Open(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { hub.Close() })
	board, err := taskboard.Open(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { board.Close() })
	h := taskboard.NewServer(board, hub).Handler()
	c, err := identity.Incept()
	if err != nil {
		f.Fatal(err)
	}
	kel, _ := identity.MarshalKEL(c.KEL())
	if err := hub.PutAgent(c.AID(), "actor", nil, kel); err != nil {
		f.Fatal(err)
	}
	// Go's fuzzer moves an integer by at most 100 per mutation, so the
	// boundaries it should cross are seeds: the window's edges on both
	// sides and the int64 sign boundary.
	for _, d := range []uint64{0, 1000, 299_000, 301_000, ^uint64(0) - 299_000, ^uint64(0) - 400_000, 1 << 40,
		1<<63 - 1} {
		f.Add(d)
	}
	f.Fuzz(func(t *testing.T, delta uint64) {
		now := uint64(time.Now().UnixMilli())
		ts := now + delta
		sig, seq := c.Sign(relayauth.Preimage("task.create", c.AID(), ts))
		body, _ := json.Marshal(map[string]any{"aid": c.AID(), "ts": ts, "key_state_seq": seq,
			"sig": base64.StdEncoding.EncodeToString(sig), "title": "t", "taskdoc_cid": "bafy-t"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tasks/create", bytes.NewReader(body)))
		// The distance from now either way, without int64 overflow.
		dist := ts - now
		if back := now - ts; back < dist {
			dist = back
		}
		if rec.Code == http.StatusOK && dist > relayauth.MaxSkewMillis+5_000 {
			t.Fatalf("a challenge signed for %d, %d ms from now (%d), was accepted", ts, dist, now)
		}
		if rec.Code != http.StatusOK && dist < relayauth.MaxSkewMillis-5_000 {
			t.Fatalf("a challenge signed %d ms from now was refused: %d %s", dist, rec.Code, rec.Body.Bytes())
		}
	})
}

// snapshotCard is one card and its trail as a comparable string ("" for
// no such card). A write names one card, so a refused write is checked
// against that card rather than the whole board, which keeps the cost of
// a step flat as the board grows across inputs.
func snapshotCard(t *testing.T, s *taskboard.Store, id string) string {
	t.Helper()
	c, ev, err := s.Get(id)
	if err != nil {
		return ""
	}
	out, _ := json.Marshal([]any{c, ev})
	return string(out)
}

// checkCard asserts a card's state is consistent (nothing for no card).
func checkCard(t *testing.T, s *taskboard.Store, id string) {
	t.Helper()
	c, events, err := s.Get(id)
	if err != nil {
		return
	}
	ok := false
	switch c.State {
	case taskboard.StateCreated:
		ok = (c.Column == "draft" || c.Column == "backlog" || c.Column == "ready") && c.Assignee == ""
	case taskboard.StateClaimed:
		ok = (c.Column == "in_progress" || c.Column == "blocked") && c.Assignee != ""
	case taskboard.StateSubmitted:
		ok = c.Column == "in_review" && c.Assignee != ""
	case taskboard.StateAccepted:
		ok = c.Column == "done" && c.Assignee != ""
	}
	if !ok {
		t.Fatalf("card %s is %s in column %s with assignee %q", c.ID, c.State, c.Column, c.Assignee)
	}
	for _, e := range events {
		if (e.Action == "accept" || e.Action == "reject" || e.Action == "move") && e.ActorAID != c.CreatorAID {
			t.Fatalf("card %s: %s by %s, not its creator", c.ID, e.Action, e.ActorAID)
		}
		if e.Action == "submit" && e.ActorAID != c.Assignee {
			t.Fatalf("card %s: submit by %s, not its assignee", c.ID, e.ActorAID)
		}
	}
}

func allowed(code int, set ...int) bool {
	for _, c := range set {
		if code == c {
			return true
		}
	}
	return false
}
