package aghub

import (
	"fmt"
	"strings"
)

// Content removal from the hub store (A2A-DESIGN §9).
//
// Before this change the hub stored interaction content in two places:
// review.goal and review.deliverable (the request goal and the full
// deliverable of every reviewed interaction, served to anyone on
// GET /agents/{aid}), and review_blob.request_doc_raw and
// review_blob.deliverable_raw (the raw bytes, streamed to peer hubs on
// GET /fed/v1/reviews). It also kept completed_task, a table derived from
// wire-1 relay traffic, and agent.guest_quota for the guest broker.
//
// migrateContentV2 rebuilds the review tables without the content columns,
// drops completed_task, drops agent.guest_quota, and then runs VACUUM and a
// truncating WAL checkpoint so that the removed bytes are not left in free
// pages of hub.db or in hub.db-wal. It runs once: on a store already in the
// new shape every step is skipped.
//
// It does not reach copies outside hub.db. Weekly backups written before
// this change (hub-backup-*.db) still hold the content; removing them is
// part of the production cleanup (deploy/cleanup-content-v0.2.sh), which
// runs only with the product owner's approval. Content that peer hubs
// already received through /fed/v1/reviews cannot be recalled.
//
// Cost: VACUUM rewrites the whole database once, through the WAL, so the
// first start after the upgrade needs free disk of about the database size
// and holds an exclusive lock for the duration.

// reviewTableV2 is the review table without content columns. request_cid
// and result_cid are the receipt's commitments, copied from the signed
// receipt; they are not content.
const reviewTableV2 = `CREATE TABLE IF NOT EXISTS review (
   interaction_id TEXT PRIMARY KEY,
   subject_aid TEXT NOT NULL,
   reviewer_aid TEXT NOT NULL,
   rating INTEGER NOT NULL,
   comment TEXT NOT NULL DEFAULT '',
   receipt_cid TEXT NOT NULL,
   request_cid TEXT NOT NULL DEFAULT '',
   result_cid TEXT NOT NULL DEFAULT '',
   completed_at INTEGER NOT NULL DEFAULT 0,
   created_at INTEGER NOT NULL,
   stored_at TEXT NOT NULL
 )`

// reviewBlobTableV2 keeps the two signed objects a review was verified
// from, so that a peer hub can re-verify them, and nothing else.
const reviewBlobTableV2 = `CREATE TABLE IF NOT EXISTS review_blob (
   interaction_id TEXT PRIMARY KEY,
   receipt_raw    BLOB NOT NULL,
   review_raw     BLOB NOT NULL
 )`

// reviewColumnsV2 and reviewBlobColumnsV2 are the columns copied by the
// rebuild, each with the value used when an old table lacks it.
var (
	reviewColumnsV2 = []migrateColumn{
		{"interaction_id", ""}, {"subject_aid", ""}, {"reviewer_aid", ""},
		{"rating", "0"}, {"comment", "''"}, {"receipt_cid", "''"},
		{"request_cid", "''"}, {"result_cid", "''"}, {"completed_at", "0"},
		{"created_at", "0"}, {"stored_at", "''"},
	}
	reviewBlobColumnsV2 = []migrateColumn{
		{"interaction_id", ""}, {"receipt_raw", ""}, {"review_raw", ""},
	}
)

// migrateColumn is one column of a rebuilt table: its name, and the SQL
// expression used when the old table does not have it ("" means the old
// table must have it).
type migrateColumn struct {
	name     string
	fallback string
}

// migrateContentV2 removes the content columns and tables described above.
// See the file comment.
func (s *Store) migrateContentV2() error {
	reviewCols, err := tableColumns(s.db, "review")
	if err != nil {
		return err
	}
	blobCols, err := tableColumns(s.db, "review_blob")
	if err != nil {
		return err
	}
	agentCols, err := tableColumns(s.db, "agent")
	if err != nil {
		return err
	}
	completed, err := tableColumns(s.db, "completed_task")
	if err != nil {
		return err
	}
	rebuildReview := reviewCols["goal"] || reviewCols["deliverable"]
	rebuildBlob := blobCols["request_doc_raw"] || blobCols["deliverable_raw"]
	dropGuest := agentCols["guest_quota"]
	dropCompleted := len(completed) > 0
	if !rebuildReview && !rebuildBlob && !dropGuest && !dropCompleted {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var stmts []string
	if rebuildReview {
		sel, err := selectList(reviewColumnsV2, reviewCols)
		if err != nil {
			return fmt.Errorf("hub: migrate review: %w", err)
		}
		stmts = append(stmts,
			strings.Replace(reviewTableV2, "EXISTS review (", "EXISTS review_v2 (", 1),
			`INSERT INTO review_v2(`+columnNames(reviewColumnsV2)+`) SELECT `+sel+` FROM review`,
			`DROP TABLE review`,
			`ALTER TABLE review_v2 RENAME TO review`,
			`CREATE INDEX IF NOT EXISTS idx_review_subject ON review(subject_aid)`,
		)
	}
	if rebuildBlob {
		sel, err := selectList(reviewBlobColumnsV2, blobCols)
		if err != nil {
			return fmt.Errorf("hub: migrate review_blob: %w", err)
		}
		stmts = append(stmts,
			strings.Replace(reviewBlobTableV2, "EXISTS review_blob (", "EXISTS review_blob_v2 (", 1),
			`INSERT INTO review_blob_v2(`+columnNames(reviewBlobColumnsV2)+`) SELECT `+sel+` FROM review_blob`,
			`DROP TABLE review_blob`,
			`ALTER TABLE review_blob_v2 RENAME TO review_blob`,
		)
	}
	if dropCompleted {
		stmts = append(stmts, `DROP TABLE completed_task`)
	}
	if dropGuest {
		// Not content, so a column drop is enough; SQLite rewrites the
		// rows of agent without it.
		stmts = append(stmts, `ALTER TABLE agent DROP COLUMN guest_quota`)
	}
	for _, q := range stmts {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("hub: migrate content: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("hub: migrate content: %w", err)
	}
	// VACUUM rewrites the file from the live pages only; the checkpoint
	// then moves the rewritten pages into hub.db and truncates the WAL,
	// which held the page images written by the rebuild above.
	if _, err := s.db.Exec(`VACUUM`); err != nil {
		return fmt.Errorf("hub: migrate content: vacuum: %w", err)
	}
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("hub: migrate content: checkpoint: %w", err)
	}
	return nil
}

// selectList builds the SELECT list that copies cols out of a table that
// has the columns in have.
func selectList(cols []migrateColumn, have map[string]bool) (string, error) {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		switch {
		case have[c.name]:
			out = append(out, c.name)
		case c.fallback != "":
			out = append(out, c.fallback)
		default:
			return "", fmt.Errorf("the existing table has no column %s", c.name)
		}
	}
	return strings.Join(out, ", "), nil
}

func columnNames(cols []migrateColumn) string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.name
	}
	return strings.Join(out, ", ")
}
