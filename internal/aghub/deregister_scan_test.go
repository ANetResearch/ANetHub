package aghub_test

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// deregAllowed are the tables an AID may still appear in after it is
// deregistered (hub-payment-privacy PAY-O1): its tombstone; its balance and
// the ledger and the settlements (the debt is still this hub's); its leaf in
// the balance tree of an epoch already closed, kept the 14 days the epoch's
// proofs are (the published root covers every leaf, so one cannot go); the
// reviews and receipts it is the subject of; the withdrawals on
// the card federation streams; dereg_event for the hub process; and the
// admission list and the quota the operator raised for it unless the
// admission was revoked.
//
// A review names no reviewer (evidence v2, SI-48), so an AID is in review,
// review_blob and fed_review only as the subject.
var deregAllowed = map[string]bool{
	"departed_kel":        true,
	"credit_balance":      true,
	"credit_entry":        true,
	"liab_leaf":           true,
	"credit_settled":      true,
	"credit_cleared":      true,
	"credit_redemption":   true,
	"review":              true,
	"review_blob":         true,
	"fed_review":          true,
	"a2a_card_withdrawal": true,
	"dereg_event":         true,
}

// tablesNaming is every table holding a row with aid in any of its columns.
func tablesNaming(t *testing.T, db *sql.DB, aid string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	var out []string
	for _, tb := range tables {
		r, err := db.Query(`SELECT * FROM "` + tb + `"`)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := r.Columns()
		found := false
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for _, v := range vals {
				var b []byte
				switch x := v.(type) {
				case string:
					b = []byte(x)
				case []byte:
					b = x
				}
				if bytes.Contains(b, []byte(aid)) {
					found = true
				}
			}
		}
		r.Close()
		if found {
			out = append(out, tb)
		}
	}
	sort.Strings(out)
	return out
}

// TestDeregRemovesEveryAIDKeyedRow (PAY-O1): an agent with everything a hub
// keeps for it — capabilities, both cards on federating streams, a key set,
// a directory entry, mail waiting, credit, reviews as subject and as reviewer,
// an admission, revoked delivery credentials, a raised quota — is
// deregistered for each reason; afterwards its AID is
// only in the tables of deregAllowed (read row by row), and the raw bytes
// of hub.db hold it nowhere else (the allowed rows removed from a copy,
// then VACUUM, then the file scanned).
func TestDeregRemovesEveryAIDKeyedRow(t *testing.T) {
	for _, why := range []string{aghub.DeregSelf, aghub.DeregDip, aghub.DeregRevoked, aghub.DeregInactive, aghub.DeregOperator} {
		t.Run(why, func(t *testing.T) {
			dir := t.TempDir()
			srv, store, _ := newHubAt(t, dir)
			x, y := twoAgents(t)
			register(t, srv, x, "X", []string{"work.do", "work.more"})
			register(t, srv, y, "Y", nil)
			setVisibility(t, srv, x, aghub.VisibilityFederated)
			registerA2A(t, srv, x, "X", []string{"work.do"}, signA2A(t, x, a2aCardFor(x, 1)))
			raw, _ := mintKeySet(t, x, uint64(time.Now().UnixMilli()))
			if code, b := publishKeys(t, srv, x, raw); code != http.StatusOK {
				t.Fatalf("keys: %d %s", code, b)
			}
			if lookUpInBucket(t, srv, x.AID(), "") == nil {
				t.Fatal("setup: the agent has no directory entry")
			}
			if code, b, _ := relaySend(t, srv, y, x.AID(), testEnvelope(t, x.AID(), nil)); code != http.StatusOK {
				t.Fatalf("send: %d %s", code, b)
			}
			uploadInterlockedReview(t, srv, x, y, 5, "as subject")
			uploadInterlockedReview(t, srv, y, x, 4, "as reviewer")
			revoked(t, srv, x, b64ids(capIDFor(1, 1), capIDFor(1, 2)), 2, 2)
			if _, err := store.SetQuota(x.AID(), aghub.QuotaChange{NonContactMsgs: i64(900)}); err != nil {
				t.Fatal(err)
			}
			publishEpoch(t, store) // a leaf in a closed epoch

			if got := tablesNaming(t, store.DBForTest(), x.AID()); len(got) < 13 {
				t.Fatalf("setup: the agent is in only %v", got)
			}
			tx, err := store.DBForTest().Begin()
			if err != nil {
				t.Fatal(err)
			}
			res, err := aghub.DeregisterTx(tx, x.AID(), why)
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if res.Undelivered != 1 || res.Balance != testRegistrationFunds {
				t.Errorf("result %+v, want 1 undelivered and the balance %d", res, testRegistrationFunds)
			}

			allowed := map[string]bool{}
			for k := range deregAllowed {
				allowed[k] = true
			}
			if why != aghub.DeregRevoked && why != aghub.DeregOperator {
				allowed["admitted"] = true
				allowed["quota_override"] = true
			}
			for _, tb := range tablesNaming(t, store.DBForTest(), x.AID()) {
				if !allowed[tb] {
					t.Errorf("after %s the AID is still in %s", why, tb)
				}
			}
			if leftover := rawScanWithout(t, store.DBForTest(), dir, allowed, x.AID()); leftover != 0 {
				t.Errorf("after %s the raw bytes of hub.db hold the AID %d time(s) outside the allowed tables", why, leftover)
			}
			// What is gone is what made it reachable.
			if store.KnowsAgent(x.AID()) {
				t.Error("still registered")
			}
			if lookUpInBucket(t, srv, x.AID(), "") != nil {
				t.Error("its directory entry is still served")
			}
			if n := revocationCount(t, store, x.AID()); n != 0 {
				t.Errorf("after %s it still has %d revocations", why, n)
			}
			q, err := store.QuotaOf(x.AID())
			if raised := q != aghub.DefaultQuota(); err != nil || raised != allowed["quota_override"] {
				t.Errorf("after %s its quota is %+v (%v): the operator's raise should stay only when the operator did not remove it", why, q, err)
			}
		})
	}
}

// rawScanWithout copies hub.db after a checkpoint, deletes from the copy
// every row of the allowed tables, VACUUMs it, and counts aid in its raw
// bytes: what is left is in a table, an index or free space the allowed
// tables do not explain.
func rawScanWithout(t *testing.T, db *sql.DB, dir string, allowed map[string]bool, aid string) int {
	t.Helper()
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "copy.db")
	in, err := os.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	in.Close()
	out.Close()
	c, err := sql.Open("sqlite", copyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var names []string
	for tb := range allowed {
		names = append(names, tb)
	}
	sort.Strings(names)
	for _, tb := range names {
		if _, err := c.Exec(fmt.Sprintf(`DELETE FROM "%s"`, tb)); err != nil && !strings.Contains(err.Error(), "no such table") {
			t.Fatal(err)
		}
	}
	if _, err := c.Exec(`VACUUM`); err != nil {
		t.Fatal(err)
	}
	c.Close()
	b, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(b, []byte(aid))
}

// A new account on probation does not upload reviews yet (PAY-A4;
// M-PAY-24): 403 probation, nothing stored; after the probation, or once
// the operator admits it, it does.
func TestReviewsWaitForProbation(t *testing.T) {
	srv, store := newHubWithStore(t)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"bakery"})
	register(t, srv, req, "Requester", nil)
	until := time.Now().Add(time.Hour).UnixMilli()
	if _, err := store.DBForTest().Exec(`UPDATE agent SET admitted_via='open', probation_until=?, trial='pending' WHERE aid=?`,
		until, req.AID()); err != nil {
		t.Fatal(err)
	}
	k := makeEvidence(t, prov, req, "ix_probation", 5, "")
	code, b := uploadReview(t, srv, k)
	if code != http.StatusForbidden || !strings.Contains(string(b), `"probation"`) {
		t.Fatalf("a review from an account on probation: %d %s", code, b)
	}
	if reviewStored(t, store, k) {
		t.Fatal("the refused review was stored")
	}
	// The operator admits it: probation over, the review goes in.
	if _, err := store.Admit(req.AID(), 0, "", false); err != nil {
		t.Fatal(err)
	}
	if code, b := uploadReview(t, srv, k); code != http.StatusOK {
		t.Fatalf("the same review after admission: %d %s", code, b)
	}
}
