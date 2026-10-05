package aghub_test

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ANetResearch/ANetCore/identity/identitytest"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// hub.db is 0.3.0 data or it is refused (core CORE-V4): a new database is
// created with its whole schema and PRAGMA user_version = 3 in one
// transaction; one at version 3 opens as it is; one an earlier anet-hub
// wrote (a lower version, or tables without one) is ErrHubDataV02 and one a
// newer anet-hub wrote is ErrHubDataTooNew. A refused directory is left
// byte for byte as it was.

// dirSnapshot is every file in dir with its size and hash, for "nothing
// was written here".
func dirSnapshot(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, fmt.Sprintf("%s %d %x", e.Name(), len(b), sha256.Sum256(b)))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// writeDB makes dir/hub.db with stmts and the given user_version.
func writeDB(t *testing.T, dir string, version int, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`PRAGMA user_version = ` + strconv.Itoa(version)); err != nil {
		t.Fatal(err)
	}
}

func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// An agent table as anet-hub 0.2 wrote it.
const v02AgentTable = `CREATE TABLE agent (aid TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '',
	caps TEXT NOT NULL DEFAULT '[]', pricing TEXT NOT NULL DEFAULT '', kel BLOB NOT NULL, registered_at TEXT NOT NULL)`

func TestANewHubDBIsVersion3WithItsWholeSchema(t *testing.T) {
	dir := t.TempDir()
	s, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db := s.DBForTest()
	if v := userVersion(t, db); v != aghub.SchemaVersion || aghub.SchemaVersion != 3 {
		t.Errorf("a new hub.db has user_version %d, want 3", v)
	}
	for _, table := range []string{"agent", "agent_cap", "credit_balance", "credit_entry", "credit_settled",
		"credit_cleared", "credit_redemption", "hub_due", "hub_owed", "hub_cleared", "hub_meta", "departed_kel",
		"agent_keys", "agent_a2a_card", "agent_skill", "agent_tag", "a2a_card_withdrawal", "fed_a2a_card",
		"a2a_fed_seq", "admitted", "admission_window", "dereg_event", "relay_message", "relay_redelivery",
		"cap_revocation", "quota_override", "review", "review_blob", "fed_review", "head_attestation",
		"supply_totals", "supply_chain", "liab_leaf", "liab_meta"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil || n != 1 {
			t.Errorf("table %s: %d (%v)", table, n, err)
		}
	}
	for _, gone := range []string{"credit_issuance", "invite", "invite_use", "gateway_voucher", "fed_card", "completed_task"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name=?`, gone).Scan(&n); err != nil || n != 0 {
			t.Errorf("a new hub.db has %s", gone)
		}
	}
	// The one-row tables start with their row.
	var totals, seq int
	if err := db.QueryRow(`SELECT COUNT(*) FROM supply_totals WHERE id = 1 AND issued = 0 AND redeemed = 0
	    AND events_since_publish = 0 AND last_to_day IS NULL`).Scan(&totals); err != nil || totals != 1 {
		t.Errorf("supply_totals: %d (%v)", totals, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM a2a_fed_seq WHERE id = 1 AND last = 0`).Scan(&seq); err != nil || seq != 1 {
		t.Errorf("a2a_fed_seq: %d (%v)", seq, err)
	}
	// It reopens as it is, with what was written.
	c, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Credit(c.AID(), 3, "kept"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := aghub.CheckData(dir); err != nil {
		t.Fatalf("CheckData on a 0.3.0 hub.db: %v", err)
	}
	s2, err := aghub.Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if b, _ := s2.Balance(c.AID()); b != 3 {
		t.Errorf("after reopening the balance is %d", b)
	}
}

// An empty hub.db file (a creation that never committed) is created into.
func TestAnEmptyHubDBFileIsCreatedInto(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hub.db"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v := userVersion(t, s.DBForTest()); v != 3 {
		t.Errorf("user_version %d", v)
	}
}

func TestHubDataOfAnotherReleaseIsRefusedUntouched(t *testing.T) {
	for _, c := range []struct {
		name    string
		version int
		stmts   []string
		want    error
	}{
		{"0.2 tables, no version", 0, []string{v02AgentTable}, aghub.ErrHubDataV02},
		// As a 0.2 hub left it: in WAL mode, stopped cleanly. Read without
		// the immutable flag, SQLite would make its -wal and -shm files.
		{"0.2 tables in WAL mode", 0, []string{`PRAGMA journal_mode=WAL`, v02AgentTable}, aghub.ErrHubDataV02},
		{"version 1", 1, []string{v02AgentTable}, aghub.ErrHubDataV02},
		{"version 2", 2, []string{v02AgentTable}, aghub.ErrHubDataV02},
		{"version 2, no tables", 2, nil, aghub.ErrHubDataV02},
		{"version 4", 4, []string{`CREATE TABLE agent (aid TEXT PRIMARY KEY, future BLOB)`}, aghub.ErrHubDataTooNew},
		{"version 4, no tables", 4, nil, aghub.ErrHubDataTooNew},
		{"version 1000", 1000, []string{v02AgentTable}, aghub.ErrHubDataTooNew},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDB(t, dir, c.version, c.stmts...)
			before := dirSnapshot(t, dir)
			if err := aghub.CheckData(dir); !errors.Is(err, c.want) {
				t.Errorf("CheckData: %v, want %v", err, c.want)
			}
			s, err := aghub.Open(dir)
			if !errors.Is(err, c.want) {
				if s != nil {
					s.Close()
				}
				t.Fatalf("Open: %v, want %v", err, c.want)
			}
			if after := dirSnapshot(t, dir); after != before {
				t.Errorf("the refused directory changed:\n%s\n%s", before, after)
			}
		})
	}
	// The two are told apart: one says move it away, the other upgrade.
	if errors.Is(aghub.ErrHubDataTooNew, aghub.ErrHubDataV02) || errors.Is(aghub.ErrHubDataV02, aghub.ErrHubDataTooNew) {
		t.Error("the two refusals are one")
	}
}

// The pool keeps idle connections in step with the hub's concurrency: a
// burst of concurrent reads leaves its connections idle for the next burst
// instead of closing all but two of them, each of which would parse the
// whole schema again when reopened.
func TestThePoolKeepsItsConnections(t *testing.T) {
	s, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := s.DBForTest()
	const n = 24
	for round := 0; round < 3; round++ {
		var ready, done sync.WaitGroup
		release := make(chan struct{})
		for i := 0; i < n; i++ {
			ready.Add(1)
			done.Add(1)
			go func() {
				defer done.Done()
				// An open result holds its connection until it is closed, so
				// n of them at once are n connections.
				rows, err := db.Query(`SELECT aid FROM agent`)
				ready.Done()
				if err != nil {
					t.Error(err)
					return
				}
				<-release
				rows.Close()
			}()
		}
		ready.Wait()
		close(release)
		done.Wait()
	}
	if st := db.Stats(); st.MaxIdleClosed > 0 {
		t.Errorf("the pool closed %d idle connections over three bursts of %d (stats %+v)", st.MaxIdleClosed, n, st)
	}
}

// No migration is left in the hub (core CORE-V4): no ALTER TABLE in the
// non-test code, except the review tables' rebuild in content_v2.go, which
// goes when the reviews are rewritten; and no function of hub.db's code
// that converts another release's data by name.
func TestNoHubMigrationStatements(t *testing.T) {
	root := hubModuleRoot(t)
	allowed := map[string]bool{filepath.Join("internal", "aghub", "content_v2.go"): true}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BasicLit:
				if v.Kind == token.STRING && strings.Contains(strings.ToUpper(v.Value), "ALTER TABLE") && !allowed[rel] {
					t.Errorf("%s: an ALTER TABLE statement: %s", rel, v.Value)
				}
			case *ast.FuncDecl:
				// hub.db's code; admin.db (internal/admin) is its own store.
				name := strings.ToLower(v.Name.Name)
				if (strings.Contains(name, "migrate") || strings.Contains(name, "backfill") ||
					strings.Contains(name, "readmitlegacy") || name == "openbalance") && !allowed[rel] &&
					strings.HasPrefix(rel, filepath.Join("internal", "aghub")) {
					t.Errorf("%s: %s converts data of another release", rel, v.Name.Name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// hubModuleRoot is the ANetHub module directory.
func hubModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		up := filepath.Dir(dir)
		if up == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = up
	}
}
