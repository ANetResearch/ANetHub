// Package taskboard is the hub-side task board (K207 A4): the 7-column
// kanban FSM from AgentNetwork v3, re-homed on the hub with one decisive
// change (D3): a card is a VIEW — the truth about a task is the TaskDoc the
// card's taskdoc_cid points to. The board never stores task semantics, only
// workflow position and an append-only event trail.
//
// Columns (v3 DefaultColumnsJSON, faithfully carried):
//
//	draft · backlog · ready(claimable) · in_progress(WIP≤3/assignee) ·
//	in_review · done · blocked(claimed cards, blocker note required)
//
// States: created → claimed → submitted → accepted (reject: submitted →
// claimed). Column is a projection of state plus explicit placement.
package taskboard

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver (K207 A3)
)

const (
	StateCreated   = "created"
	StateClaimed   = "claimed"
	StateSubmitted = "submitted"
	StateAccepted  = "accepted"
)

// Columns in board order.
var Columns = []struct{ Key, Name string }{
	{"draft", "Draft"}, {"backlog", "Backlog"}, {"ready", "Ready"},
	{"in_progress", "In Progress"}, {"in_review", "In Review"},
	{"done", "Done"}, {"blocked", "Blocked"},
}

// WIPLimit bounds simultaneously in-progress cards per assignee (v3 default).
const WIPLimit = 3

var (
	ErrNotFound   = errors.New("taskboard: card not found")
	ErrForbidden  = errors.New("taskboard: actor not allowed")
	ErrConflict   = errors.New("taskboard: transition not allowed")
	ErrValidation = errors.New("taskboard: invalid input")
)

// Card is one board card. TaskDocCID is the task's truth; Title is display
// convenience only.
type Card struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	TaskDocCID string `json:"taskdoc_cid"`
	State      string `json:"state"`
	Column     string `json:"column"`
	CreatorAID string `json:"creator_aid"`
	Assignee   string `json:"assignee_aid,omitempty"`
	Note       string `json:"note,omitempty"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

// Event is one audit-trail entry.
type Event struct {
	Seq      int64  `json:"seq"`
	CardID   string `json:"card_id"`
	TS       int64  `json:"ts"`
	ActorAID string `json:"actor_aid"`
	Action   string `json:"action"`
	Detail   string `json:"detail,omitempty"`
}

// Store is the taskboard database (its own file, so the module stays
// removable without touching hub.db).
type Store struct{ db *sql.DB }

func Open(dir string) (*Store, error) {
	db, err := sql.Open("sqlite", filepath.Join(dir, "taskboard.db")+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(15000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("taskboard: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS cards (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  taskdoc_cid TEXT NOT NULL,
  state TEXT NOT NULL,
  col TEXT NOT NULL,
  creator_aid TEXT NOT NULL,
  assignee_aid TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cards_col ON cards(col);
CREATE INDEX IF NOT EXISTS idx_cards_assignee ON cards(assignee_aid, col);
CREATE TABLE IF NOT EXISTS card_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  card_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  actor_aid TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_card ON card_events(card_id, seq);
`

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "card-" + hex.EncodeToString(b)
}

func nowMillis() int64 { return time.Now().UnixMilli() }

func (s *Store) log(cardID, actor, action, detail string) {
	_, _ = s.db.Exec(`INSERT INTO card_events (card_id, ts, actor_aid, action, detail) VALUES (?,?,?,?,?)`,
		cardID, nowMillis(), actor, action, detail)
}

// Create adds a card in draft/backlog/ready (default ready).
func (s *Store) Create(creator, title, taskdocCID, col string) (*Card, error) {
	if creator == "" || title == "" || taskdocCID == "" {
		return nil, fmt.Errorf("%w: creator, title and taskdoc_cid required", ErrValidation)
	}
	if col == "" {
		col = "ready"
	}
	if col != "draft" && col != "backlog" && col != "ready" {
		return nil, fmt.Errorf("%w: new cards start in draft|backlog|ready", ErrValidation)
	}
	now := nowMillis()
	c := &Card{ID: newID(), Title: title, TaskDocCID: taskdocCID, State: StateCreated,
		Column: col, CreatorAID: creator, CreatedAt: now, UpdatedAt: now}
	_, err := s.db.Exec(`INSERT INTO cards (id,title,taskdoc_cid,state,col,creator_aid,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?)`, c.ID, c.Title, c.TaskDocCID, c.State, c.Column, c.CreatorAID, now, now)
	if err != nil {
		return nil, err
	}
	s.log(c.ID, creator, "create", col)
	return c, nil
}

// Move repositions a created card among draft/backlog/ready (creator only).
func (s *Store) Move(actor, id, col string) (*Card, error) {
	if col != "draft" && col != "backlog" && col != "ready" {
		return nil, fmt.Errorf("%w: move targets draft|backlog|ready", ErrValidation)
	}
	return s.mutate(actor, id, "move", col, func(c *Card) error {
		if c.CreatorAID != actor {
			return fmt.Errorf("%w: only the creator moves a card", ErrForbidden)
		}
		if c.State != StateCreated {
			return fmt.Errorf("%w: only unclaimed cards move", ErrConflict)
		}
		c.Column = col
		return nil
	})
}

// Claim takes a ready card (any registered agent within WIP limit).
func (s *Store) Claim(actor, id string) (*Card, error) {
	var wip int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM cards WHERE assignee_aid=? AND col='in_progress'`, actor).Scan(&wip); err != nil {
		return nil, err
	}
	if wip >= WIPLimit {
		return nil, fmt.Errorf("%w: WIP limit %d reached for %s", ErrConflict, WIPLimit, actor)
	}
	return s.mutate(actor, id, "claim", "", func(c *Card) error {
		if c.State != StateCreated || c.Column != "ready" {
			return fmt.Errorf("%w: only ready cards are claimable", ErrConflict)
		}
		c.State, c.Column, c.Assignee = StateClaimed, "in_progress", actor
		return nil
	})
}

// Submit hands claimed work in for review (assignee only, not while blocked).
func (s *Store) Submit(actor, id, note string) (*Card, error) {
	return s.mutate(actor, id, "submit", note, func(c *Card) error {
		if c.Assignee != actor {
			return fmt.Errorf("%w: only the assignee submits", ErrForbidden)
		}
		if c.State != StateClaimed || c.Column != "in_progress" {
			return fmt.Errorf("%w: submit requires in-progress claimed card", ErrConflict)
		}
		c.State, c.Column, c.Note = StateSubmitted, "in_review", note
		return nil
	})
}

// Accept closes a submitted card (creator only).
func (s *Store) Accept(actor, id string) (*Card, error) {
	return s.mutate(actor, id, "accept", "", func(c *Card) error {
		if c.CreatorAID != actor {
			return fmt.Errorf("%w: only the creator accepts", ErrForbidden)
		}
		if c.State != StateSubmitted {
			return fmt.Errorf("%w: only submitted cards are accepted", ErrConflict)
		}
		c.State, c.Column = StateAccepted, "done"
		return nil
	})
}

// Reject returns a submitted card to its assignee (creator only, note required).
func (s *Store) Reject(actor, id, note string) (*Card, error) {
	if note == "" {
		return nil, fmt.Errorf("%w: rejection requires a note", ErrValidation)
	}
	return s.mutate(actor, id, "reject", note, func(c *Card) error {
		if c.CreatorAID != actor {
			return fmt.Errorf("%w: only the creator rejects", ErrForbidden)
		}
		if c.State != StateSubmitted {
			return fmt.Errorf("%w: only submitted cards are rejected", ErrConflict)
		}
		c.State, c.Column, c.Note = StateClaimed, "in_progress", note
		return nil
	})
}

// Block parks an in-progress card (assignee or creator, blocker note required).
func (s *Store) Block(actor, id, note string) (*Card, error) {
	if note == "" {
		return nil, fmt.Errorf("%w: blocking requires a blocker note", ErrValidation)
	}
	return s.mutate(actor, id, "block", note, func(c *Card) error {
		if actor != c.Assignee && actor != c.CreatorAID {
			return fmt.Errorf("%w: only assignee or creator blocks", ErrForbidden)
		}
		if c.Column != "in_progress" {
			return fmt.Errorf("%w: only in-progress cards block", ErrConflict)
		}
		c.Column, c.Note = "blocked", note
		return nil
	})
}

// Unblock returns a blocked card to in_progress (assignee or creator).
func (s *Store) Unblock(actor, id string) (*Card, error) {
	return s.mutate(actor, id, "unblock", "", func(c *Card) error {
		if actor != c.Assignee && actor != c.CreatorAID {
			return fmt.Errorf("%w: only assignee or creator unblocks", ErrForbidden)
		}
		if c.Column != "blocked" {
			return fmt.Errorf("%w: card is not blocked", ErrConflict)
		}
		c.Column = "in_progress"
		return nil
	})
}

// mutate loads, applies, persists and logs one transition atomically.
func (s *Store) mutate(actor, id, action, detail string, apply func(*Card) error) (*Card, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c, err := scanCard(tx.QueryRow(`SELECT id,title,taskdoc_cid,state,col,creator_aid,assignee_aid,note,created_at,updated_at FROM cards WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	if err := apply(c); err != nil {
		return nil, err
	}
	c.UpdatedAt = nowMillis()
	if _, err := tx.Exec(`UPDATE cards SET title=?,state=?,col=?,assignee_aid=?,note=?,updated_at=? WHERE id=?`,
		c.Title, c.State, c.Column, c.Assignee, c.Note, c.UpdatedAt, c.ID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO card_events (card_id, ts, actor_aid, action, detail) VALUES (?,?,?,?,?)`,
		c.ID, c.UpdatedAt, actor, action, detail); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return c, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanCard(r rowScanner) (*Card, error) {
	var c Card
	err := r.Scan(&c.ID, &c.Title, &c.TaskDocCID, &c.State, &c.Column, &c.CreatorAID, &c.Assignee, &c.Note, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Get returns one card and its event trail.
func (s *Store) Get(id string) (*Card, []Event, error) {
	c, err := scanCard(s.db.QueryRow(`SELECT id,title,taskdoc_cid,state,col,creator_aid,assignee_aid,note,created_at,updated_at FROM cards WHERE id=?`, id))
	if err != nil {
		return nil, nil, err
	}
	rows, err := s.db.Query(`SELECT seq,card_id,ts,actor_aid,action,detail FROM card_events WHERE card_id=? ORDER BY seq`, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var evs []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Seq, &e.CardID, &e.TS, &e.ActorAID, &e.Action, &e.Detail); err != nil {
			return nil, nil, err
		}
		evs = append(evs, e)
	}
	return c, evs, rows.Err()
}

// Board lists every column with its cards (most recently updated first).
func (s *Store) Board() (map[string][]Card, error) {
	rows, err := s.db.Query(`SELECT id,title,taskdoc_cid,state,col,creator_aid,assignee_aid,note,created_at,updated_at FROM cards ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Card{}
	for rows.Next() {
		c, err := scanCard(rows)
		if err != nil {
			return nil, err
		}
		out[c.Column] = append(out[c.Column], *c)
	}
	return out, rows.Err()
}
