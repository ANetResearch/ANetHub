package admin

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite" // pure-Go driver (K207 A3: no cgo in distributed runtime)
)

// HubDB is the admin plane's handle on the PUBLIC hub store (the same hub.db the anet-hub binary
// serves). Reads are unrestricted; writes are deliberately limited to two operator actions
// (guest-quota update, registry delete) — every other mutation belongs to the public hub's own
// signed-challenge API. Cross-process safety: both processes open the file in WAL mode with a
// 15s busy timeout.
//
// Query discipline: relay_message is multi-GB (payload BLOBs). Everything the UI polls must stay on
// covering indexes (idx_relay_mailbox) or small tables; only the harvester pages through payloads,
// by rowid, in bounded batches.
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
// hides (unlisted agents, mailbox backlog, work volume).
type AdminAgentView struct {
	AID              string   `json:"aid"`
	Name             string   `json:"name"`
	Caps             []string `json:"caps"`
	Summary          string   `json:"summary,omitempty"`
	Readme           string   `json:"readme,omitempty"`
	Pricing          string   `json:"pricing,omitempty"`
	GuestQuota       int      `json:"guest_quota"`
	Listed           bool     `json:"listed"`
	AvgRating        float64  `json:"avg_rating"`
	ReviewCount      int      `json:"review_count"`
	RegisteredAt     string   `json:"registered_at"`
	TasksAsProvider  int      `json:"tasks_as_provider"`
	TasksAsRequester int      `json:"tasks_as_requester"`
	MailboxBacklog   int      `json:"mailbox_backlog"` // undelivered relay messages waiting for this agent
	LastCompletedAt  string   `json:"last_completed_at,omitempty"`
}

// AllAgents returns EVERY registered agent (listed or not) with activity aggregates, most recently
// registered first. q filters like the public search.
func (h *HubDB) AllAgents(q string) ([]AdminAgentView, error) {
	query := `
	SELECT a.aid, a.name, a.caps, a.summary, a.readme, a.pricing, a.guest_quota, a.registered_at,
	       COALESCE((SELECT AVG(rating) FROM review r WHERE r.subject_aid=a.aid), 0),
	       COALESCE((SELECT COUNT(*) FROM review r WHERE r.subject_aid=a.aid), 0),
	       COALESCE((SELECT COUNT(*) FROM completed_task c WHERE c.provider_aid=a.aid), 0),
	       COALESCE((SELECT COUNT(*) FROM completed_task c WHERE c.requester_aid=a.aid), 0),
	       COALESCE((SELECT COUNT(*) FROM relay_message m WHERE m.to_aid=a.aid AND m.delivered_at IS NULL), 0),
	       COALESCE((SELECT MAX(completed_at) FROM completed_task c WHERE c.provider_aid=a.aid OR c.requester_aid=a.aid), '')
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
		if err := rows.Scan(&v.AID, &v.Name, &capsJSON, &v.Summary, &v.Readme, &v.Pricing, &v.GuestQuota,
			&v.RegisteredAt, &v.AvgRating, &v.ReviewCount, &v.TasksAsProvider, &v.TasksAsRequester,
			&v.MailboxBacklog, &v.LastCompletedAt); err != nil {
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

// HubReview mirrors the public review row (admin reads it straight from the store).
type HubReview struct {
	InteractionID string `json:"interaction_id"`
	SubjectAID    string `json:"subject_aid"`
	ReviewerAID   string `json:"reviewer_aid"`
	Rating        int    `json:"rating"`
	Comment       string `json:"comment,omitempty"`
	Goal          string `json:"goal,omitempty"`
	Deliverable   string `json:"deliverable,omitempty"`
	CreatedAt     int64  `json:"created_at"`
}

// RecentReviews returns the newest limit reviews.
func (h *HubDB) RecentReviews(limit int) ([]HubReview, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := h.db.Query(
		`SELECT interaction_id,subject_aid,reviewer_aid,rating,comment,goal,deliverable,created_at
		 FROM review ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HubReview{}
	for rows.Next() {
		var r HubReview
		if err := rows.Scan(&r.InteractionID, &r.SubjectAID, &r.ReviewerAID, &r.Rating, &r.Comment,
			&r.Goal, &r.Deliverable, &r.CreatedAt); err != nil {
			return nil, err
		}
		// Deliverables can be huge (verified full content) — the admin list only needs a preview.
		if len(r.Deliverable) > 2048 {
			r.Deliverable = r.Deliverable[:2048] + "…"
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CompletedTask is one delivered-result marker.
type CompletedTask struct {
	InteractionID string `json:"interaction_id"`
	ProviderAID   string `json:"provider_aid"`
	RequesterAID  string `json:"requester_aid"`
	CompletedAt   string `json:"completed_at"`
}

// RecentTasks returns the newest limit completed tasks.
func (h *HubDB) RecentTasks(limit int) ([]CompletedTask, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := h.db.Query(
		`SELECT interaction_id,provider_aid,requester_aid,completed_at
		 FROM completed_task ORDER BY completed_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CompletedTask{}
	for rows.Next() {
		var t CompletedTask
		if err := rows.Scan(&t.InteractionID, &t.ProviderAID, &t.RequesterAID, &t.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// HubTotals are the whole-store aggregates the snapshot ticker records.
type HubTotals struct {
	Agents         int     `json:"agents"`
	Listed         int     `json:"listed"`
	TasksCompleted int     `json:"tasks_completed"`
	Reviews        int     `json:"reviews"`
	AvgRating      float64 `json:"avg_rating"`
	RelayBacklog   int     `json:"relay_backlog"`
}

// Totals computes the aggregates. The backlog count runs on the covering mailbox index, so it stays
// cheap even with a multi-GB relay table.
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
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM completed_task`).Scan(&t.TasksCompleted); err != nil {
		return t, err
	}
	var avg sql.NullFloat64
	if err := h.db.QueryRow(`SELECT COUNT(*), AVG(rating) FROM review`).Scan(&t.Reviews, &avg); err != nil {
		return t, err
	}
	if avg.Valid {
		t.AvgRating = avg.Float64
	}
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM relay_message WHERE delivered_at IS NULL`).Scan(&t.RelayBacklog); err != nil {
		return t, err
	}
	return t, nil
}

// SetGuestQuota is an operator override of an agent's guest trial quota (regulation lever: 0 shuts an
// agent out of guest traffic). Note a subsequent `anet hub-register` by the agent overwrites it.
func (h *HubDB) SetGuestQuota(aid string, quota int) error {
	if quota < 0 || quota > 1000 {
		return fmt.Errorf("admin: quota out of range")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	res, err := h.db.Exec(`UPDATE agent SET guest_quota=? WHERE aid=?`, quota, aid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("admin: agent %s not registered", aid)
	}
	return nil
}

// DeleteAgent removes an agent from the public registry (reviews and completed_task history are kept —
// they are counterparty evidence, not the agent's property). The agent can re-register; recording the
// delist intent in moderation is the caller's job.
func (h *HubDB) DeleteAgent(aid string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	res, err := h.db.Exec(`DELETE FROM agent WHERE aid=?`, aid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("admin: agent %s not registered", aid)
	}
	return nil
}

// RelayRow is one raw relay_message row (harvester input).
type RelayRow struct {
	ID            int64
	ToAID         string
	FromAID       string
	Kind          string
	InteractionID string
	Payload       []byte
	CreatedAt     string
	Delivered     bool
}

// RelayRowsSince pages through relay_message by rowid: rows with id > afterID, oldest first, at most
// limit rows AND at most byteBudget cumulative payload (whichever cuts first; always at least one row
// when any exists). This is the ONLY payload-reading query in the admin plane.
func (h *HubDB) RelayRowsSince(afterID int64, limit int, byteBudget int64) ([]RelayRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := h.db.Query(
		`SELECT id,to_aid,from_aid,kind,interaction_id,payload,created_at,delivered_at IS NOT NULL
		 FROM relay_message WHERE id > ? ORDER BY id LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RelayRow
	var acc int64
	for rows.Next() {
		var r RelayRow
		if err := rows.Scan(&r.ID, &r.ToAID, &r.FromAID, &r.Kind, &r.InteractionID, &r.Payload, &r.CreatedAt, &r.Delivered); err != nil {
			return nil, err
		}
		if len(out) > 0 && acc+int64(len(r.Payload)) > byteBudget {
			break
		}
		acc += int64(len(r.Payload))
		out = append(out, r)
	}
	return out, rows.Err()
}

// AgentNames returns aid → display name for labeling (small table, full read).
func (h *HubDB) AgentNames() (map[string]string, error) {
	rows, err := h.db.Query(`SELECT aid, name FROM agent`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var aid, name string
		if err := rows.Scan(&aid, &name); err != nil {
			return nil, err
		}
		out[aid] = name
	}
	return out, rows.Err()
}
