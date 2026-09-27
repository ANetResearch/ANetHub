//go:build linux

// Package deploy_test runs the operator scripts in this directory against
// fixture data directories.
//
// cleanup-content-v0.2.sh deletes production data once, irreversibly, and
// hub-db-roll.sh decides what the weekly backup keeps. Neither had ever run
// anywhere before these tests (05-hub H6): no host of the authors had the
// sqlite3 CLI, and nothing in CI ran them. Both scripts need it, so these
// tests are skipped where it is missing — unless ANET_HUB_SCRIPT_TESTS is
// "require", which CI sets after installing it, so that a skip there is a
// failure rather than a silent pass.
//
// The scripts are bash with GNU coreutils (stat -c, date -d, sed -i), as on
// the hub hosts; hence linux only.
package deploy_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

func needSQLite3(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sqlite3"); err != nil {
		if os.Getenv("ANET_HUB_SCRIPT_TESTS") == "require" {
			t.Fatal("the sqlite3 CLI is not installed and ANET_HUB_SCRIPT_TESTS=require")
		}
		t.Skip("the sqlite3 CLI is not installed; the deploy scripts need it " +
			"(run these tests on a host that has it; CI installs it)")
	}
}

// runScript runs a script in this directory with extra environment. It has
// no controlling terminal (setsid), so a confirmation prompt fails instead
// of waiting for a person.
func runScript(t *testing.T, env []string, script string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	}
	t.Fatalf("running %s: %v", script, err)
	return "", 0
}

func canary(t *testing.T, what string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return what + "-CANARY-" + hex.EncodeToString(b)
}

func execAll(t *testing.T, path string, stmts []string, args ...[]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i, q := range stmts {
		var a []any
		if i < len(args) {
			a = args[i]
		}
		if _, err := db.Exec(q, a...); err != nil {
			t.Fatalf("%s: %v\n%s", filepath.Base(path), err, q)
		}
	}
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// snapshot hashes every file under the roots, so a dry run can be shown to
// have changed nothing.
func snapshot(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			out[p] = hex.EncodeToString(sum[:])
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// filesHolding lists the files under the roots whose bytes contain s.
func filesHolding(t *testing.T, s string, roots ...string) []string {
	t.Helper()
	var hits []string
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte(s)) {
				hits = append(hits, p)
			}
			return nil
		})
	}
	return hits
}

func queryInt(t *testing.T, path, q string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		t.Fatalf("%s: %s: %v", filepath.Base(path), q, err)
	}
	return n
}

// cleanupFixture is a hub host as a v0.1 hub and admin left it: every
// place §9 lists, each holding a canary, plus the old admin's ops
// credentials (05-hub H7).
type cleanupFixture struct {
	hub, admin, ssh, systemd string
	content                  string // task content, in every copy §9 lists
	secret                   string // the monitor token's value
	opsKey, otherKey         string
	envFile, dropIn, unit    string
}

func newCleanupFixture(t *testing.T) cleanupFixture {
	root := t.TempDir()
	f := cleanupFixture{
		hub: filepath.Join(root, "data"), admin: filepath.Join(root, "admin"),
		ssh: filepath.Join(root, "ssh"), systemd: filepath.Join(root, "systemd"),
		content: canary(t, "CONTENT"), secret: canary(t, "MONITOR"),
	}
	c := f.content
	execAll(t, filepath.Join(f.hub, "hub.db"), []string{
		`CREATE TABLE relay_message (id INTEGER PRIMARY KEY AUTOINCREMENT, to_aid TEXT NOT NULL,
		   from_aid TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, interaction_id TEXT NOT NULL DEFAULT '',
		   payload BLOB NOT NULL, created_at TEXT NOT NULL, delivered_at TEXT)`,
		`INSERT INTO relay_message(to_aid,from_aid,kind,payload,created_at,delivered_at)
		   VALUES('bafyto','bafyfrom','delegate',?,'2026-09-01T10:00:00Z','2026-09-01T10:01:00Z'),
		         ('bafyto','bafyfrom','message',?,'2026-09-20T10:00:00Z',NULL)`,
		`CREATE TABLE review (interaction_id TEXT PRIMARY KEY, subject_aid TEXT NOT NULL,
		   reviewer_aid TEXT NOT NULL, rating INTEGER NOT NULL, comment TEXT NOT NULL DEFAULT '',
		   receipt_cid TEXT NOT NULL, goal TEXT NOT NULL DEFAULT '', deliverable TEXT NOT NULL DEFAULT '',
		   created_at INTEGER NOT NULL, stored_at TEXT NOT NULL)`,
		`INSERT INTO review VALUES('ix1','bafyp','bafyr',5,'fine','bafyrc',?,?,1,'2026-09-01')`,
		`CREATE TABLE review_blob (interaction_id TEXT PRIMARY KEY, receipt_raw BLOB NOT NULL,
		   review_raw BLOB NOT NULL, request_doc_raw BLOB NOT NULL, deliverable_raw BLOB NOT NULL)`,
		`INSERT INTO review_blob VALUES('ix1',x'01',x'02',?,?)`,
	}, nil, []any{[]byte("goal " + c), []byte("chat " + c)}, nil,
		[]any{"goal " + c, "deliverable " + c}, nil,
		[]any{[]byte("doc " + c), []byte("result " + c)})
	writeFile(t, filepath.Join(f.hub, "hub-backup-20260906.db"), "SQLite backup "+c, 0o600)
	for _, s := range []string{"", "-wal", "-shm"} {
		writeFile(t, filepath.Join(f.hub, "taskboard.db"+s), "card "+c, 0o600)
	}
	writeFile(t, filepath.Join(f.hub, "guest_identity.kel"), "seed "+c, 0o600)
	// A file that looks like a copy: listed for the operator, not deleted.
	writeFile(t, filepath.Join(f.hub, "notes.old"), "operator notes", 0o600)

	oldManifest := `{"schema":"anet.agent/1","id":"%s","name":"A","tier":"official","aid":"bafya",
	  "runtime":{"host":"%s","ssh_user":"%s","workdir":"/srv/` + c + `","units":["a.service"]},
	  "monitor":{"url":"http://127.0.0.1:9101/","auth":"token"},"ops":{"allowed":["restart"]},
	  "datasets":{"harvest":true}}`
	man := func(id, host, user string) string {
		s := strings.Replace(oldManifest, "%s", id, 1)
		s = strings.Replace(s, "%s", host, 1)
		return strings.Replace(s, "%s", user, 1)
	}
	execAll(t, filepath.Join(f.admin, "admin.db"), []string{
		`CREATE TABLE session (source TEXT NOT NULL, session_id TEXT NOT NULL, goal TEXT NOT NULL DEFAULT '',
		   PRIMARY KEY(source, session_id))`,
		`INSERT INTO session VALUES('hub-relay','s1',?)`,
		`CREATE TABLE harvest_state (source TEXT PRIMARY KEY, cursor TEXT NOT NULL DEFAULT '')`,
		`INSERT INTO harvest_state VALUES('hub-relay','42')`,
		`CREATE TABLE official_agent (id TEXT PRIMARY KEY, manifest TEXT NOT NULL,
		   enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`INSERT INTO official_agent VALUES('echo-e',?,1,'t','t'),
		   ('plain','{"schema":"anet.agent/1","id":"plain","name":"P","tier":"official"}',1,'t','t')`,
	}, nil, []any{"goal " + c}, nil, nil, nil,
		[]any{man("echo-e", "emax.example", "")})
	writeFile(t, filepath.Join(f.admin, "officials.json"),
		"["+man("tools", "dmax.example", "anet")+"]\n", 0o640)
	writeFile(t, filepath.Join(f.admin, "datasets", "hub-relay", "2026-09.jsonl"), `{"goal":"`+c+`"}`, 0o600)
	writeFile(t, filepath.Join(f.admin, "datasets", "ai-studio", "cards", "j1.json"), `{"prompt":"`+c+`"}`, 0o600)

	// The ops plane's ssh key, named with --ops-ssh-key, and another
	// default key that the script must leave alone.
	f.opsKey = filepath.Join(f.ssh, "id_ed25519")
	f.otherKey = filepath.Join(f.ssh, "id_rsa")
	writeFile(t, f.opsKey, "-----BEGIN OPENSSH PRIVATE KEY-----\nops\n", 0o600)
	writeFile(t, f.opsKey+".pub", "ssh-ed25519 AAAA ops\n", 0o644)
	writeFile(t, f.otherKey, "-----BEGIN OPENSSH PRIVATE KEY-----\nother\n", 0o600)

	// The monitor token in each place systemd takes environment from.
	f.unit = filepath.Join(f.systemd, "anet-hub-admin.service")
	f.dropIn = filepath.Join(f.systemd, "anet-hub-admin.service.d", "override.conf")
	f.envFile = filepath.Join(root, "admin.env")
	writeFile(t, f.unit, "[Service]\nEnvironment=ADMIN_TOKEN=keep-this-admin-token\n"+
		"Environment=ADMIN_MONITOR_TOKEN="+f.secret+"\nExecStart=/bin/true\n", 0o644)
	writeFile(t, f.dropIn, "[Service]\nEnvironment=\"ADMIN_MONITOR_TOKEN="+f.secret+"\"\n"+
		"EnvironmentFile=-"+f.envFile+"\n"+
		"Environment=LOG_LEVEL=info ADMIN_MONITOR_TOKEN="+f.secret+"\n", 0o644)
	writeFile(t, f.envFile, "export ADMIN_MONITOR_TOKEN="+f.secret+"\nOTHER=1\n", 0o600)
	return f
}

func (f cleanupFixture) args(extra ...string) []string {
	return append([]string{"--hub-data", f.hub, "--admin-data", f.admin, "--ssh-dir", f.ssh,
		"--systemd-dir", f.systemd, "--ops-ssh-key", f.opsKey}, extra...)
}

// The cleanup script on a v0.1 hub host. A dry run reports every item of
// the §9 list and the ops credentials, prints neither content nor the
// token, and changes no byte; --apply without a terminal or --yes refuses
// and changes nothing; --apply --yes leaves no copy of the content in
// either data directory (WAL included), strips the manifests, removes the
// monitor token where it stands alone and the named ssh key, and leaves
// everything it was not asked to touch.
func TestTheCleanupScriptReportsThenDeletesEveryListedCopy(t *testing.T) {
	needSQLite3(t)
	f := newCleanupFixture(t)
	roots := []string{f.hub, f.admin, f.ssh, f.systemd, f.envFile}
	before := snapshot(t, roots...)

	out, code := runScript(t, nil, "cleanup-content-v0.2.sh", f.args()...)
	if code != 0 {
		t.Fatalf("dry run: exit %d\n%s", code, out)
	}
	for _, want := range []string{
		"mode: dry run",
		"[1] relay_message: not migrated; all 2 rows are wire-1 plaintext",
		"[3] review: goal/deliverable columns present (hub.db not yet migrated): 1 rows with content",
		"[3] review_blob: request_doc_raw/deliverable_raw present: 1 rows",
		"hub-backup-20260906.db", "[4] " + filepath.Join(f.hub, "taskboard.db-wal"),
		"hub-relay: 1 files", "ai-studio: 1 files",
		"[6] admin.db session: 1 rows", "[6] admin.db harvest_state: 1 rows",
		"[7] admin.db official_agent: 1 manifests carry", "officials.json: 1 manifests carry",
		"[8] " + filepath.Join(f.hub, "guest_identity.kel"),
		// The ssh user defaults to root, as the old ops plane did.
		"root@emax.example", "anet@dmax.example",
		"private key " + f.opsKey, "private key " + f.otherKey,
		f.unit + ": 1 line(s) name ADMIN_MONITOR_TOKEN", f.dropIn + ": 2 line(s)", f.envFile + ": 1 line(s)",
		"authorized_keys", "rotate ADMIN_TOKEN",
		filepath.Join(f.hub, "notes.old"),
		"nothing was deleted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run output lacks %q", want)
		}
	}
	if strings.Contains(out, f.content) || strings.Contains(out, f.secret) {
		t.Errorf("the report printed content or the monitor token:\n%s", out)
	}
	assertUnchanged(t, "dry run", before, snapshot(t, roots...))

	out, code = runScript(t, nil, "cleanup-content-v0.2.sh", f.args("--apply")...)
	if code != 2 || !strings.Contains(out, "refusing to apply: no terminal") {
		t.Errorf("--apply without a terminal or --yes: exit %d, want 2 and a refusal\n%s", code, out)
	}
	assertUnchanged(t, "refused --apply", before, snapshot(t, roots...))

	out, code = runScript(t, nil, "cleanup-content-v0.2.sh", f.args("--apply", "--yes")...)
	if code != 0 {
		t.Fatalf("--apply --yes: exit %d\n%s", code, out)
	}
	if hits := filesHolding(t, f.content, f.hub, f.admin); len(hits) > 0 {
		t.Errorf("content survives the cleanup in %v\n%s", hits, out)
	}
	if strings.Contains(out, f.content) || strings.Contains(out, f.secret) {
		t.Errorf("the apply run printed content or the monitor token")
	}
	for _, gone := range []string{
		filepath.Join(f.hub, "hub-backup-20260906.db"), filepath.Join(f.hub, "taskboard.db"),
		filepath.Join(f.hub, "taskboard.db-wal"), filepath.Join(f.hub, "taskboard.db-shm"),
		filepath.Join(f.hub, "guest_identity.kel"), filepath.Join(f.admin, "datasets", "hub-relay"),
		f.opsKey, f.opsKey + ".pub",
	} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Errorf("%s still exists after --apply (%v)", gone, err)
		}
	}
	for _, kept := range []string{filepath.Join(f.hub, "notes.old"), f.otherKey, filepath.Join(f.admin, "datasets")} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s was not the script's to delete: %v", kept, err)
		}
	}
	for _, wal := range []string{filepath.Join(f.hub, "hub.db-wal"), filepath.Join(f.admin, "admin.db-wal")} {
		if st, err := os.Stat(wal); err == nil && st.Size() != 0 {
			t.Errorf("%s holds %d bytes after the final checkpoint", wal, st.Size())
		}
	}
	hubdb, admindb := filepath.Join(f.hub, "hub.db"), filepath.Join(f.admin, "admin.db")
	for q, want := range map[string]int{
		`SELECT COUNT(*) FROM relay_message`: 0,
		`SELECT COUNT(*) FROM review`:        1, // the review stays, without its content
	} {
		if n := queryInt(t, hubdb, q); n != want {
			t.Errorf("hub.db %s = %d, want %d", q, n, want)
		}
	}
	for q, want := range map[string]int{
		`SELECT COUNT(*) FROM session`:        0,
		`SELECT COUNT(*) FROM harvest_state`:  0,
		`SELECT COUNT(*) FROM official_agent`: 2,
		`SELECT COUNT(*) FROM official_agent WHERE json_type(manifest,'$.runtime') IS NOT NULL`: 0,
		`SELECT COUNT(*) FROM official_agent WHERE json_type(manifest,'$.monitor') IS NOT NULL`: 0,
	} {
		if n := queryInt(t, admindb, q); n != want {
			t.Errorf("admin.db %s = %d, want %d", q, n, want)
		}
	}
	var officials []map[string]any
	b, _ := os.ReadFile(filepath.Join(f.admin, "officials.json"))
	if err := json.Unmarshal(b, &officials); err != nil || len(officials) != 1 {
		t.Fatalf("officials.json after --apply: %v %q", err, b)
	}
	for _, k := range []string{"runtime", "monitor", "ops", "datasets"} {
		if _, ok := officials[0][k]; ok {
			t.Errorf("officials.json still has %q", k)
		}
	}
	if officials[0]["id"] != "tools" {
		t.Errorf("officials.json lost the registration itself: %v", officials[0])
	}
	if st, err := os.Stat(filepath.Join(f.admin, "officials.json")); err != nil || st.Mode().Perm() != 0o640 {
		t.Errorf("officials.json mode after the rewrite: %v %v, want 0640", st.Mode(), err)
	}

	// The monitor token: gone where a line only assigned it; the line that
	// also sets another variable is left and reported; ADMIN_TOKEN stays.
	unit, _ := os.ReadFile(f.unit)
	dropIn, _ := os.ReadFile(f.dropIn)
	env, _ := os.ReadFile(f.envFile)
	if strings.Contains(string(unit), "ADMIN_MONITOR_TOKEN") || strings.Contains(string(env), "ADMIN_MONITOR_TOKEN") {
		t.Errorf("a line that only set ADMIN_MONITOR_TOKEN survived:\n%s\n%s", unit, env)
	}
	if !strings.Contains(string(unit), "Environment=ADMIN_TOKEN=keep-this-admin-token") ||
		!strings.Contains(string(env), "OTHER=1") || !strings.Contains(string(dropIn), "EnvironmentFile=-") {
		t.Errorf("the edit removed lines that do not set the monitor token:\n%s\n%s\n%s", unit, dropIn, env)
	}
	if n := strings.Count(string(dropIn), "ADMIN_MONITOR_TOKEN"); n != 1 ||
		!strings.Contains(out, "remove ADMIN_MONITOR_TOKEN from them by hand") {
		t.Errorf("the shared line: %d left in the drop-in (want 1), and it must be reported\n%s", n, out)
	}
	if !strings.Contains(out, "systemctl daemon-reload") {
		t.Error("the apply run edited units without saying to reload systemd")
	}
}

func assertUnchanged(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	for p, h := range before {
		if after[p] != h {
			t.Errorf("%s changed %s", what, p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s created %s", what, p)
		}
	}
}

// On a hub.db the wire-2 hub has migrated, the script reports the record
// the migration left in hub_meta, and --relay-before cannot be used to
// delete wire-2 envelopes (05-hub H5).
func TestTheCleanupScriptReportsWhatTheMigrationDropped(t *testing.T) {
	needSQLite3(t)
	dir := t.TempDir()
	execAll(t, filepath.Join(dir, "hub.db"), []string{
		`CREATE TABLE relay_message (id INTEGER PRIMARY KEY AUTOINCREMENT, to_aid TEXT NOT NULL,
		   from_aid TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, interaction_id TEXT NOT NULL DEFAULT '',
		   payload BLOB NOT NULL, created_at TEXT NOT NULL, delivered_at TEXT)`,
		`INSERT INTO relay_message(to_aid,kind,payload,created_at,delivered_at)
		   VALUES('a','delegate',x'01','2026-09-01T10:00:00Z','2026-09-01T10:01:00Z'),
		         ('a','message',x'02','2026-09-20T10:00:00Z',NULL),
		         ('b','message',x'03','2026-09-21T10:00:00Z',NULL)`,
	})
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	out, code := runScript(t, nil, "cleanup-content-v0.2.sh", "--hub-data", dir, "--admin-data", t.TempDir(),
		"--ssh-dir", t.TempDir(), "--systemd-dir", t.TempDir(),
		"--relay-before", "9999999999999")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{"migrated to wire 2 at", "dropped 2 undelivered and 1 delivered wire-1 rows",
		"nothing to delete", "--relay-before ignored"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q\n%s", want, out)
		}
	}
}

// hub-db-roll.sh on the weekly path: the backup has no relay row and no
// relay payload, keeps the rest, the WAL is truncated, the two newest
// backups are kept, and no temporary copy is left behind. The hub holds
// the database open while the script runs, as it does in production.
func TestTheWeeklyBackupHoldsNoRelayRows(t *testing.T) {
	needSQLite3(t)
	dir := t.TempDir()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	payload := canary(t, "ENVELOPE")
	// The hub's own connection: rows written through it sit in hub.db-wal
	// until somebody checkpoints.
	hub, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	if _, err := hub.Exec(`INSERT INTO agent(aid, kel, registered_at) VALUES('bafyagent', x'00', '2026-09-01')`); err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Exec(`INSERT INTO relay_message(to_aid, size, created_at, payload) VALUES('bafyagent', ?, 1, ?)`,
		len(payload), []byte(payload)); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dir, "hub.db-wal")); err != nil || st.Size() == 0 {
		t.Fatalf("precondition: the rows should be in hub.db-wal (%v); the checkpoint assertion "+
			"would pass for the wrong reason", err)
	}
	// Two old backups; with today's the oldest must go.
	for i, name := range []string{"hub-backup-20200105.db", "hub-backup-20200112.db"} {
		p := filepath.Join(dir, name)
		writeFile(t, p, "old backup", 0o600)
		old := time.Now().Add(-time.Duration(30-i) * 24 * time.Hour)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	out, code := runScript(t, []string{"HUB_DATA_DIR=" + dir, "FORCE_WEEKLY=1"}, "hub-db-roll.sh")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	backup := filepath.Join(dir, "hub-backup-"+time.Now().Format("20060102")+".db")
	if n := queryInt(t, backup, `SELECT COUNT(*) FROM relay_message`); n != 0 {
		t.Errorf("the backup holds %d relay rows", n)
	}
	if n := queryInt(t, backup, `SELECT COUNT(*) FROM agent`); n != 1 {
		t.Errorf("the backup holds %d agent rows, want the 1 the hub has", n)
	}
	if hits := filesHolding(t, payload, dir); len(hits) != 1 || !strings.HasSuffix(hits[0], "hub.db") {
		t.Errorf("the relay payload is in %v; want it only in hub.db, where the hub keeps it until ack", hits)
	}
	if st, err := os.Stat(filepath.Join(dir, "hub.db-wal")); err == nil && st.Size() != 0 {
		t.Errorf("hub.db-wal holds %d bytes after the run's checkpoint", st.Size())
	}
	left, _ := filepath.Glob(filepath.Join(dir, "hub-backup-*.db"))
	if len(left) != 2 || !containsPath(left, backup) || !containsPath(left, filepath.Join(dir, "hub-backup-20200112.db")) {
		t.Errorf("backups after the run: %v, want today's and the newest old one", left)
	}
	if tmp, _ := filepath.Glob(filepath.Join(dir, ".hub-backup-*")); len(tmp) != 0 {
		t.Errorf("temporary copies left behind: %v", tmp)
	}
	logb, _ := os.ReadFile(filepath.Join(dir, "roll.log"))
	for _, want := range []string{"START", "relay_backlog=1", "weekly backup", "pruned old backup", "END"} {
		if !bytes.Contains(logb, []byte(want)) {
			t.Errorf("roll.log lacks %q:\n%s", want, logb)
		}
	}
}

func containsPath(list []string, p string) bool {
	for _, s := range list {
		if s == p {
			return true
		}
	}
	return false
}
