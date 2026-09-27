package admin

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite" // pure-Go driver (K207 A3: no cgo in distributed runtime)
)

// HubDB is the admin plane's handle on the PUBLIC hub store (the same hub.db the anet-hub binary
// serves). Writes are limited to the registry delete and restore operator actions — every other
// mutation belongs to the public hub's own signed API. Cross-process safety: both processes open the
// file in WAL mode with a 15s busy timeout.
//
// Nothing here reads relay_message payloads. Since hub wire 2 they are sealed envelopes the admin
// plane cannot open, and reading them at all would copy relay data out of the relay's own retention
// (A2A-DESIGN §9, SI-1). The only relay figure read is a row count.
type HubDB struct {
	db *sql.DB
	mu sync.Mutex

	path string // hub.db file path (for size stat)
}

// OpenHubDB opens the public hub store at dir (dir/hub.db must exist — the admin plane never creates
// or migrates the public store).
func OpenHubDB(dir string) (*HubDB, error) {
	p := filepath.Join(dir, "hub.db")
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("admin: hub db: %w", err)
	}
	db, err := sql.Open("sqlite", p+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(15000)")
	if err != nil {
		return nil, err
	}
	return &HubDB{db: db, path: p}, nil
}

// Close closes the handle.
func (h *HubDB) Close() error { return h.db.Close() }

// SizeBytes returns hub.db's current file size (WAL not included).
func (h *HubDB) SizeBytes() int64 {
	fi, err := os.Stat(h.path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// AdminAgentView is the operator's registry row: the public AgentView fields PLUS what the public API
// hides (unlisted agents, mailbox backlog, reviews written).
//
// The per-agent task counters (tasks_as_provider, tasks_as_requester, last_completed_at) are gone
// with the completed_task table they were read from (A2A-DESIGN §9, [C38]). What the hub can still
// state is reviews: ReviewCount is the reviews this agent received as provider, ReviewsWritten the
// reviews it published as requester — each one anchored on a provider-signed receipt.
type AdminAgentView struct {
	AID            string   `json:"aid"`
	Name           string   `json:"name"`
	Caps           []string `json:"caps"`
	Summary        string   `json:"summary,omitempty"`
	Readme         string   `json:"readme,omitempty"`
	Pricing        string   `json:"pricing,omitempty"`
	Listed         bool     `json:"listed"`
	AvgRating      float64  `json:"avg_rating"`
	ReviewCount    int      `json:"review_count"`
	ReviewsWritten int      `json:"reviews_written"`
	RegisteredAt   string   `json:"registered_at"`
	MailboxBacklog int      `json:"mailbox_backlog"` // envelopes queued for this agent (a relay row exists only until ack)
}

// AllAgents returns EVERY registered agent (listed or not) with activity aggregates, most recently
// registered first. q filters like the public search.
func (h *HubDB) AllAgents(q string) ([]AdminAgentView, error) {
	query := `
	SELECT a.aid, a.name, a.caps, a.summary, a.readme, a.pricing, a.registered_at,
	       COALESCE((SELECT AVG(rating) FROM review r WHERE r.subject_aid=a.aid), 0),
	       COALESCE((SELECT COUNT(*) FROM review r WHERE r.subject_aid=a.aid), 0),
	       COALESCE((SELECT COUNT(*) FROM review r WHERE r.reviewer_aid=a.aid), 0),
	       COALESCE((SELECT COUNT(*) FROM relay_message m WHERE m.to_aid=a.aid), 0)
	FROM agent a`
	var args []any
	if q != "" {
		like := "%" + q + "%"
		query += ` WHERE a.aid LIKE ? OR a.name LIKE ? OR a.caps LIKE ? OR a.summary LIKE ? OR a.readme LIKE ?`
		args = append(args, like, like, like, like, like)
	}
	query += ` ORDER BY a.registered_at DESC`
	rows, err := h.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminAgentView{}
	for rows.Next() {
		var v AdminAgentView
		var capsJSON string
		if err := rows.Scan(&v.AID, &v.Name, &capsJSON, &v.Summary, &v.Readme, &v.Pricing,
			&v.RegisteredAt, &v.AvgRating, &v.ReviewCount, &v.ReviewsWritten,
			&v.MailboxBacklog); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(capsJSON), &v.Caps)
		v.Listed = len(v.Caps) > 0 || v.Summary != "" || v.Readme != "" || v.Pricing != ""
		out = append(out, v)
	}
	return out, rows.Err()
}

// Agent returns one agent's admin view, or an error if not registered.
func (h *HubDB) Agent(aid string) (*AdminAgentView, error) {
	all, err := h.AllAgents("")
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].AID == aid {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("admin: agent %s not registered", aid)
}

// HubReview mirrors the public review row (admin reads it straight from the store). No content:
// the hub store has none (A2A-DESIGN §9 row 评价).
type HubReview struct {
	InteractionID string `json:"interaction_id"`
	SubjectAID    string `json:"subject_aid"`
	ReviewerAID   string `json:"reviewer_aid"`
	Rating        int    `json:"rating"`
	Comment       string `json:"comment,omitempty"`
	ReceiptCID    string `json:"receipt_cid"`
	CreatedAt     int64  `json:"created_at"`
}

// RecentReviews returns the newest limit reviews.
func (h *HubDB) RecentReviews(limit int) ([]HubReview, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := h.db.Query(
		`SELECT interaction_id,subject_aid,reviewer_aid,rating,comment,receipt_cid,created_at
		 FROM review ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HubReview{}
	for rows.Next() {
		var r HubReview
		if err := rows.Scan(&r.InteractionID, &r.SubjectAID, &r.ReviewerAID, &r.Rating, &r.Comment,
			&r.ReceiptCID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// HubTotals are the whole-store aggregates the snapshot ticker records.
//
// TasksCompleted has the meaning /stats gives it since A2A-DESIGN §9: distinct valid receipts
// published to this hub through reviews. Snapshots taken before that change counted wire-1 relay
// results instead, so the series has a step at the upgrade.
type HubTotals struct {
	Agents         int     `json:"agents"`
	Listed         int     `json:"listed"`
	TasksCompleted int     `json:"tasks_completed"`
	Reviews        int     `json:"reviews"`
	AvgRating      float64 `json:"avg_rating"`
	RelayBacklog   int     `json:"relay_backlog"`
}

// Totals computes the aggregates.
func (h *HubDB) Totals() (HubTotals, error) {
	var t HubTotals
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM agent`).Scan(&t.Agents); err != nil {
		return t, err
	}
	rows, err := h.db.Query(`SELECT caps, summary, readme, pricing FROM agent`)
	if err != nil {
		return t, err
	}
	for rows.Next() {
		var capsJSON, sum, rd, pr string
		if err := rows.Scan(&capsJSON, &sum, &rd, &pr); err != nil {
			rows.Close()
			return t, err
		}
		// Same "listed" rule as the public hub's scanAgent: parsed caps (nil-caps registrations store
		// JSON "null", which a raw string compare would miscount) or any profile text.
		var caps []string
		_ = json.Unmarshal([]byte(capsJSON), &caps)
		if len(caps) > 0 || sum != "" || rd != "" || pr != "" {
			t.Listed++
		}
	}
	rows.Close()
	if err := h.db.QueryRow(
		`SELECT COUNT(DISTINCT receipt_cid) FROM review WHERE receipt_cid != ''`).Scan(&t.TasksCompleted); err != nil {
		return t, err
	}
	var avg sql.NullFloat64
	if err := h.db.QueryRow(`SELECT COUNT(*), AVG(rating) FROM review`).Scan(&t.Reviews, &avg); err != nil {
		return t, err
	}
	if avg.Valid {
		t.AvgRating = avg.Float64
	}
	// Since hub wire 2 a relay row exists only while undelivered (ack
	// deletes it), so every row is backlog.
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM relay_message`).Scan(&t.RelayBacklog); err != nil {
		return t, err
	}
	return t, nil
}

// DeleteAgent removes an agent from the public registry (reviews are kept — they are counterparty
// evidence, not the agent's property). The agent can re-register; recording the
// delist intent in moderation is the caller's job.
//
// The agent's A2A card and its skill and tag index rows go with it: they
// exist only for an agent on the registry, and the card is re-admitted
// when the agent registers again. The hub's registry queries join the
// agent table as well, so a row left behind would not be listed, but it
// would sit in the database describing an agent the operator removed.
func (h *HubDB) DeleteAgent(aid string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM agent WHERE aid=?`, aid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("admin: agent %s not registered", aid)
	}
	for _, q := range []string{
		`DELETE FROM agent_a2a_card WHERE aid=?`,
		`DELETE FROM agent_skill WHERE aid=?`,
		`DELETE FROM agent_tag WHERE aid=?`,
	} {
		// A hub.db written by a hub that predates these tables does not
		// have them, and there is nothing to remove from it.
		if _, err := tx.Exec(q, aid); err != nil && !strings.Contains(err.Error(), "no such table") {
			return err
		}
	}
	return tx.Commit()
}
