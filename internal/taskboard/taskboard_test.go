package taskboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestHappyPath(t *testing.T) {
	s := openTest(t)
	c, err := s.Create("aid:alice", "translate poem", "bafyT1", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Column != "ready" || c.State != StateCreated {
		t.Fatalf("default placement wrong: %+v", c)
	}
	if c, err = s.Claim("aid:bob", c.ID); err != nil || c.Assignee != "aid:bob" || c.Column != "in_progress" {
		t.Fatalf("claim: %+v %v", c, err)
	}
	if c, err = s.Submit("aid:bob", c.ID, "done, see evidence"); err != nil || c.Column != "in_review" {
		t.Fatalf("submit: %+v %v", c, err)
	}
	if c, err = s.Accept("aid:alice", c.ID); err != nil || c.State != StateAccepted || c.Column != "done" {
		t.Fatalf("accept: %+v %v", c, err)
	}
	_, evs, err := s.Get(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range evs {
		actions = append(actions, e.Action)
	}
	want := "create,claim,submit,accept"
	if strings.Join(actions, ",") != want {
		t.Fatalf("audit trail %v, want %s", actions, want)
	}
}

func TestRejectLoop(t *testing.T) {
	s := openTest(t)
	c, _ := s.Create("aid:alice", "t", "bafyT2", "ready")
	c, _ = s.Claim("aid:bob", c.ID)
	c, _ = s.Submit("aid:bob", c.ID, "v1")
	if _, err := s.Reject("aid:alice", c.ID, ""); !errors.Is(err, ErrValidation) {
		t.Fatal("empty rejection note must be rejected")
	}
	c, err := s.Reject("aid:alice", c.ID, "missing tests")
	if err != nil || c.State != StateClaimed || c.Column != "in_progress" {
		t.Fatalf("reject: %+v %v", c, err)
	}
	if _, err := s.Submit("aid:bob", c.ID, "v2"); err != nil {
		t.Fatal("resubmit after reject must work:", err)
	}
}

func TestGuards(t *testing.T) {
	s := openTest(t)
	c, _ := s.Create("aid:alice", "t", "bafyT3", "backlog")
	if _, err := s.Claim("aid:bob", c.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("backlog card must not be claimable")
	}
	if _, err := s.Move("aid:mallory", c.ID, "ready"); !errors.Is(err, ErrForbidden) {
		t.Fatal("non-creator move must be forbidden")
	}
	c, _ = s.Move("aid:alice", c.ID, "ready")
	c, _ = s.Claim("aid:bob", c.ID)
	if _, err := s.Submit("aid:carol", c.ID, "x"); !errors.Is(err, ErrForbidden) {
		t.Fatal("non-assignee submit must be forbidden")
	}
	c2, _ := s.Submit("aid:bob", c.ID, "x")
	if _, err := s.Accept("aid:bob", c2.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("assignee self-accept must be forbidden")
	}
}

func TestWIPLimit(t *testing.T) {
	s := openTest(t)
	for i := 0; i < WIPLimit; i++ {
		c, _ := s.Create("aid:alice", fmt.Sprintf("t%d", i), "bafyT", "ready")
		if _, err := s.Claim("aid:bob", c.ID); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := s.Create("aid:alice", "one too many", "bafyT", "ready")
	if _, err := s.Claim("aid:bob", c.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("claim beyond WIP=%d must conflict", WIPLimit)
	}
	if _, err := s.Claim("aid:carol", c.ID); err != nil {
		t.Fatal("other agents unaffected by bob's WIP:", err)
	}
}

func TestBlockFlow(t *testing.T) {
	s := openTest(t)
	c, _ := s.Create("aid:alice", "t", "bafyT4", "ready")
	c, _ = s.Claim("aid:bob", c.ID)
	if _, err := s.Block("aid:bob", c.ID, ""); !errors.Is(err, ErrValidation) {
		t.Fatal("block requires a note")
	}
	c, err := s.Block("aid:bob", c.ID, "waiting on API key")
	if err != nil || c.Column != "blocked" || c.State != StateClaimed {
		t.Fatalf("block: %+v %v", c, err)
	}
	if _, err := s.Submit("aid:bob", c.ID, "x"); !errors.Is(err, ErrConflict) {
		t.Fatal("blocked card must not submit")
	}
	if _, err := s.Unblock("aid:mallory", c.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("stranger unblock must be forbidden")
	}
	if c, err = s.Unblock("aid:alice", c.ID); err != nil || c.Column != "in_progress" {
		t.Fatalf("unblock: %+v %v", c, err)
	}
}

// stubAuth records the actions it was asked to verify.
type stubAuth struct{ actions []string }

func (a *stubAuth) VerifyAgentChallenge(action, aid string, _, _ uint64, sig string) error {
	a.actions = append(a.actions, action)
	if sig == "bad" {
		return errors.New("bad signature")
	}
	return nil
}

func TestHTTPFlow(t *testing.T) {
	s := openTest(t)
	auth := &stubAuth{}
	srv := httptest.NewServer(NewServer(s, auth).Handler())
	defer srv.Close()

	post := func(path string, body map[string]any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		resp, err := srv.Client().Post(srv.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	code, out := post("/tasks/create", map[string]any{"aid": "aid:alice", "sig": "ok", "title": "T", "taskdoc_cid": "bafyX"})
	if code != 200 {
		t.Fatalf("create: %d %v", code, out)
	}
	cardID := out["card"].(map[string]any)["id"].(string)

	if code, _ := post("/tasks/claim", map[string]any{"aid": "aid:bob", "sig": "bad", "card_id": cardID}); code != 401 {
		t.Fatalf("bad sig must 401, got %d", code)
	}
	if code, _ := post("/tasks/claim", map[string]any{"aid": "aid:bob", "sig": "ok", "card_id": cardID}); code != 200 {
		t.Fatalf("claim: %d", code)
	}
	if code, _ := post("/tasks/accept", map[string]any{"aid": "aid:bob", "sig": "ok", "card_id": cardID}); code != 403 {
		t.Fatalf("non-creator accept must 403, got %d", code)
	}
	if code, _ := post("/tasks/accept", map[string]any{"aid": "aid:alice", "sig": "ok", "card_id": cardID}); code != 409 {
		t.Fatalf("accepting a merely-claimed card must 409, got %d", code)
	}

	resp, _ := srv.Client().Get(srv.URL + "/tasks/board")
	var board struct {
		Columns []struct {
			Key   string `json:"key"`
			Cards []Card `json:"cards"`
		} `json:"columns"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&board)
	resp.Body.Close()
	if len(board.Columns) != 7 {
		t.Fatalf("board must show 7 columns, got %d", len(board.Columns))
	}
	found := false
	for _, col := range board.Columns {
		if col.Key == "in_progress" && len(col.Cards) == 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("claimed card missing from in_progress")
	}
	for _, a := range auth.actions {
		if !strings.HasPrefix(a, "task.") {
			t.Fatalf("action %q escapes the task.* namespace", a)
		}
	}
}
