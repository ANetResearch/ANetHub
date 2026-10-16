package admin

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver (K207 A3: no cgo in distributed runtime)

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// HubDB is the admin plane's handle on the PUBLIC hub store (the same hub.db the anet-hub binary
// serves). Its one write is the operator's delete, and that is aghub.DeregisterTx, the one function
// that removes an agent from a hub (hub-payment-privacy PAY-O1, PAY-O3): the admin plane writes no
// agent row, no tombstone and no admission list of its own. Every other mutation belongs to the
// public hub's own signed API or to anet-hub's subcommands. Cross-process safety: both processes open
// the file in WAL mode with a 15s busy timeout, and a delete takes the write lock when it begins.
//
// Nothing here reads relay_message payloads. They are sealed envelopes the admin plane cannot open,
// and reading them at all would copy relay data out of the relay's own retention (A2A-DESIGN §9,
// SI-1). The only relay figure read is the whole hub's row count (sealed-sender SSR-H19: no
// per-agent mailbox figure).
//
// Nor does it read the ledger (credit_*, settle_guard), the balance proofs (liab_*) or the reviews a
// peer hub sent (fed_review) (PAY-O5). The operator reads redemptions with anet-hub redemptions.
type HubDB struct {
	db *sql.DB
	mu sync.Mutex

	path string // hub.db file path (for size stat)
}

// hubDSN opens hub.db as the hub does: WAL, a busy timeout, secure_delete (a delete overwrites what
// it removes, so the envelopes a deregistration drops do not stay readable in the file's free
// space), and transactions that take the write lock when they begin (BEGIN IMMEDIATE).
const hubDSN = "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(15000)" +
	"&_pragma=secure_delete(ON)&_txlock=immediate"

// ErrNoHubData is OpenHubDB's answer for a hub.db the hub has not created its schema in yet.
var ErrNoHubData = errors.New("admin: hub.db holds no hub data yet")

// OpenHubDB opens the public hub store at dir. dir/hub.db must exist: the admin plane never creates
// or converts the public store.
//
// A hub.db this release does not open is refused before anything opens it for writing, and the
// directory is left exactly as it was (aghub.CheckData reads it immutable, core CORE-V4): one of 0.2
// or earlier wraps aghub.ErrHubDataV02, one a newer anet-hub wrote aghub.ErrHubDataTooNew.
// anet-hub-admin answers them with anet-hub's own sentences (hub_identity_v02, hub_data_too_new).
func OpenHubDB(dir string) (*HubDB, error) {
	p := filepath.Join(dir, "hub.db")
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("admin: hub db: %w", err)
	}
	if err := aghub.CheckData(dir); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", p+hubDSN)
	if err != nil {
		return nil, err
	}
	// CheckData read the file without its write-ahead log; read through it, the database can still
	// turn out to be another release's, or one the hub never finished creating.
	if err := checkSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &HubDB{db: db, path: p}, nil
}

// checkSchema is OpenHubDB's second look, through the open handle.
func checkSchema(db *sql.DB) error {
	var version, objects int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("admin: hub db: %w", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&objects); err != nil {
		return fmt.Errorf("admin: hub db: %w", err)
	}
	switch {
	case version == aghub.SchemaVersion:
		return nil
	case version == 0 && objects == 0:
		return ErrNoHubData
	case version > aghub.SchemaVersion:
		return fmt.Errorf("%w (user_version %d)", aghub.ErrHubDataTooNew, version)
	}
	return fmt.Errorf("%w (user_version %d)", aghub.ErrHubDataV02, version)
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

// AdminAgentView is the operator's registry row: what the public listing says about an agent, for
// every registered agent, listed or not (PAY-O5).
//
// What it does not say: a price (prices are not public; they travel in the extended card the provider
// signs), how many reviews the agent wrote (a review names no reviewer, SI-48), and how much mail is
// queued for it (no per-agent mailbox figure, SSR-H19; the overview has the whole hub's backlog).
// RegisteredAt is the UTC day of the registration, as the public listing states it.
type AdminAgentView struct {
	AID          string   `json:"aid"`
	Name         string   `json:"name"`
	Caps         []string `json:"caps"`
	Summary      string   `json:"summary,omitempty"`
	Readme       string   `json:"readme,omitempty"`
	Listed       bool     `json:"listed"`
	AvgRating    float64  `json:"avg_rating"`
	ReviewCount  int      `json:"review_count"`
	RegisteredAt string   `json:"registered_at"`
}

// agentColumns are what scanAdminAgent reads, over agent a.
const agentColumns = `a.aid, a.name, a.caps, a.summary, a.readme, a.registered_at,
	EXISTS(SELECT 1 FROM agent_keys k WHERE k.aid = a.aid),
	COALESCE((SELECT AVG(r.rating) FROM review r WHERE r.subject_aid = a.aid), 0),
	(SELECT COUNT(*) FROM review r WHERE r.subject_aid = a.aid)`

// listed is the registry's rule (sealed-sender SSR-H18): an agent is listed once it advertises a
// service (a capability or profile text) and has published a key set, since nobody could write to
// it before.
func listed(capsJSON, summary, readme string, hasKeys bool) bool {
	// Parsed, not compared: a registration with no capabilities stores JSON "null".
	var caps []string
	_ = json.Unmarshal([]byte(capsJSON), &caps)
	return hasKeys && (len(caps) > 0 || summary != "" || readme != "")
}

func scanAdminAgent(sc interface{ Scan(...any) error }) (AdminAgentView, error) {
	var v AdminAgentView
	var capsJSON string
	var hasKeys bool
	if err := sc.Scan(&v.AID, &v.Name, &capsJSON, &v.Summary, &v.Readme, &v.RegisteredAt,
		&hasKeys, &v.AvgRating, &v.ReviewCount); err != nil {
		return v, err
	}
	_ = json.Unmarshal([]byte(capsJSON), &v.Caps)
	v.Listed = listed(capsJSON, v.Summary, v.Readme, hasKeys)
	v.RegisteredAt = toTheDay(v.RegisteredAt)
	return v, nil
}

// toTheDay is a stored registration time as its UTC day (midnight), as the public listing states it
// (SSR-H18); "" for one that does not parse.
func toTheDay(stamp string) string {
	t, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return ""
	}
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
}

// AllAgents returns EVERY registered agent (listed or not), most recently registered first. q
// filters like the public search.
func (h *HubDB) AllAgents(q string) ([]AdminAgentView, error) {
	query := `SELECT ` + agentColumns + ` FROM agent a`
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
		v, err := scanAdminAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ErrAgentNotFound is Agent's answer for an AID that is not registered.
var ErrAgentNotFound = errors.New("admin: that agent is not registered")

// Agent returns one agent's admin view, or ErrAgentNotFound.
func (h *HubDB) Agent(aid string) (*AdminAgentView, error) {
	v, err := scanAdminAgent(h.db.QueryRow(`SELECT `+agentColumns+` FROM agent a WHERE a.aid = ?`, aid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrAgentNotFound, aid)
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// HubReview is one review stored here, as the operator sees it (PAY-O5): the interaction's
// commitment (base64url), whom it reviews, the rating and comment, the receipt it rests on and the
// UTC day it was written. A review stored here names no reviewer and holds no time finer than a day
// (SI-48), and this view adds neither; it has no content either, since the hub store has none.
type HubReview struct {
	IXCommit   string `json:"ix_commit"`
	SubjectAID string `json:"subject_aid"`
	Rating     int    `json:"rating"`
	Comment    string `json:"comment"`
	ReceiptCID string `json:"receipt_cid"`
	CreatedDay uint64 `json:"created_day"`
}

// reviewLimit bounds a page of reviews.
func reviewLimit(limit int) int {
	if limit <= 0 || limit > 500 {
		return 50
	}
	return limit
}

// RecentReviews returns the newest limit reviews stored here, newest day first.
func (h *HubDB) RecentReviews(limit int) ([]HubReview, error) {
	return h.reviews(``, reviewLimit(limit))
}

// ReviewsOf returns the newest limit reviews of the subject aid: the reviews an agent received. There
// is no "reviews an agent wrote": a review names no reviewer (SI-48).
func (h *HubDB) ReviewsOf(aid string, limit int) ([]HubReview, error) {
	return h.reviews(aid, reviewLimit(limit))
}

func (h *HubDB) reviews(subject string, limit int) ([]HubReview, error) {
	query := `SELECT ix_commit, subject_aid, rating, comment, receipt_cid, created_day FROM review`
	var args []any
	if subject != "" {
		query += ` WHERE subject_aid = ?`
		args = append(args, subject)
	}
	query += ` ORDER BY created_day DESC, ix_commit LIMIT ?`
	rows, err := h.db.Query(query, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HubReview{}
	for rows.Next() {
		var r HubReview
		var ix []byte
		if err := rows.Scan(&ix, &r.SubjectAID, &r.Rating, &r.Comment, &r.ReceiptCID, &r.CreatedDay); err != nil {
			return nil, err
		}
		r.IXCommit = wire3.EncodeB64URL(ix)
		out = append(out, r)
	}
	return out, rows.Err()
}

// HubTotals are the whole-store aggregates the snapshot ticker records.
//
// TasksCompleted has the meaning /stats gives it: distinct valid receipts published to this hub
// through reviews. RelayBacklog is the whole hub's queued mail; there is no per-agent figure
// (SSR-H19).
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
	rows, err := h.db.Query(`SELECT caps, summary, readme,
	    EXISTS(SELECT 1 FROM agent_keys k WHERE k.aid = a.aid) FROM agent a`)
	if err != nil {
		return t, err
	}
	for rows.Next() {
		var capsJSON, sum, rd string
		var hasKeys bool
		if err := rows.Scan(&capsJSON, &sum, &rd, &hasKeys); err != nil {
			rows.Close()
			return t, err
		}
		t.Agents++
		if listed(capsJSON, sum, rd, hasKeys) {
			t.Listed++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return t, err
	}
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
	// A relay row exists only while undelivered (ack deletes it), so every
	// row is backlog.
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM relay_message`).Scan(&t.RelayBacklog); err != nil {
		return t, err
	}
	return t, nil
}

// Deletion is what an operator's delete did (PAY-O3).
type Deletion struct {
	// Balance is the agent's balance, which stays on the ledger: it is
	// still this hub's debt.
	Balance int64
	// Undelivered is how much mail was queued for it and is now dropped.
	Undelivered int
	// Open is whether this hub takes open sign-ups, in which case the AID
	// can register again through the gates (with a key history that
	// extends the one it left with).
	Open bool
}

// DeleteAgent revokes aid's admission and deregisters it, in one BEGIN IMMEDIATE transaction, through
// aghub.DeregisterTx (PAY-O1, PAY-O3): the same as anet-hub admissions revoke, so an operator has one
// kind of delete to know. The agent's key history becomes its tombstone, so it can only come back
// with a history that extends it, and only once it is admitted again (anet-hub admit) or, on an open
// hub, through the gates. Its balance, its ledger window and the reviews it is the subject of stay.
// The hub process drops what it holds in memory for the AID (its sessions) within two seconds, from
// the dereg_event row the transaction leaves (PAY-O2).
//
// An AID that is not registered is aghub.ErrNotRegistered, and nothing is written.
func (h *HubDB) DeleteAgent(aid string) (Deletion, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	tx, err := h.db.Begin()
	if err != nil {
		return Deletion{}, err
	}
	defer tx.Rollback()
	res, err := aghub.DeregisterTx(tx, aid, aghub.DeregOperator)
	if err != nil {
		return Deletion{}, err
	}
	open, err := admissionOpen(tx)
	if err != nil {
		return Deletion{}, err
	}
	if err := tx.Commit(); err != nil {
		return Deletion{}, err
	}
	return Deletion{Balance: res.Balance, Undelivered: res.Undelivered, Open: open}, nil
}

// admissionOpen reports whether the hub's admission mode is open; a hub that never set one is
// closed (aghub.Store.AdmissionMode).
func admissionOpen(tx *sql.Tx) (bool, error) {
	var mode string
	err := tx.QueryRow(`SELECT value FROM hub_meta WHERE key = 'admission_mode'`).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return mode == aghub.AdmissionOpen, err
}
