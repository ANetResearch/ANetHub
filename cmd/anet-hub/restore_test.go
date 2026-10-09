package main

// anet-hub restore (core G12; KEL H-20, H-23): the backup becomes the hub's
// database, in quarantine; a directory is taken for its newest backup; every
// refusal says why and changes nothing.

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// backupInto writes a copy of the database in dir to path, as
// deploy/hub-db-roll.sh makes a backup (VACUUM INTO).
func backupInto(t *testing.T, dir, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`VACUUM INTO ?`, path); err != nil {
		t.Fatal(err)
	}
}

// agentCount is how many agents the hub in dir registers, and whether it is
// in a restore quarantine.
func agentCount(t *testing.T, dir string) (int, bool) {
	t.Helper()
	s, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q, err := s.Quarantine()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM agent`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n, q.Active
}

func TestRestoreTheSubcommand(t *testing.T) {
	for _, lang := range []string{"en", "zh"} {
		t.Run(lang, func(t *testing.T) {
			dir := hubDir(t)
			backups := t.TempDir()
			a, _ := newAID(t)
			registerIn(t, dir, a)
			older := filepath.Join(backups, "hub-backup-20261001.db")
			backupInto(t, dir, older)
			b, _ := newAID(t)
			registerIn(t, dir, b)
			newer := filepath.Join(backups, "hub-backup-20261004.db")
			backupInto(t, dir, newer)
			// Neither a backup by name nor the newest.
			if err := os.WriteFile(filepath.Join(backups, "hub-backup-manual.db"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			c, _ := newAID(t)
			registerIn(t, dir, c)

			// The directory: its newest backup.
			r := cli(t, lang, "-data", dir, "restore", backups)
			expectOut(t, r, sentenceOf(lang, "restore.ok", map[string]string{"path": newer, "n": "2"}))
			if n, quarantined := agentCount(t, dir); n != 2 || !quarantined {
				t.Errorf("after restoring the newest backup: %d agents, quarantine %v; want 2, in quarantine", n, quarantined)
			}
			// A file, with --data after the subcommand.
			r = cli(t, lang, "restore", "--data", dir, older)
			expectOut(t, r, sentenceOf(lang, "restore.ok", map[string]string{"path": older, "n": "1"}))
			if n, _ := agentCount(t, dir); n != 1 {
				t.Errorf("after restoring the older backup: %d agents, want 1", n)
			}
		})
	}
}

func TestRestoreRefusals(t *testing.T) {
	for _, lang := range []string{"en", "zh"} {
		t.Run(lang, func(t *testing.T) {
			dir := hubDir(t)
			a, _ := newAID(t)
			registerIn(t, dir, a)
			backups := t.TempDir()
			good := filepath.Join(backups, "hub-backup-20261004.db")
			backupInto(t, dir, good)
			bad := filepath.Join(t.TempDir(), "hub-backup-20261005.db")
			if err := os.WriteFile(bad, []byte("not a database"), 0o600); err != nil {
				t.Fatal(err)
			}
			empty := t.TempDir()
			missing := filepath.Join(empty, "nothing.db")
			noHub := t.TempDir()
			before := dirFiles(t, dir)

			expectErr(t, cli(t, lang, "-data", dir, "restore", empty), 1,
				sentenceOf(lang, "restore.no_backup", map[string]string{"path": empty}))
			expectErr(t, cli(t, lang, "-data", dir, "restore", missing), 1,
				sentenceOf(lang, "restore.no_backup", map[string]string{"path": missing}))
			expectErr(t, cli(t, lang, "-data", dir, "restore", bad), 1,
				sentenceOf(lang, "restore.bad_backup", map[string]string{"path": bad}))
			expectErr(t, cli(t, lang, "-data", noHub, "restore", good), 1,
				sentenceOf(lang, "restore.no_identity", map[string]string{"path": noHub}))
			if r := cli(t, lang, "-data", dir, "restore"); r.code != 2 || r.stdout != "" {
				t.Errorf("restore without a backup: exit %d, stdout %q; want a usage error", r.code, r.stdout)
			}
			if r := cli(t, lang, "-data", dir, "restore", good, good); r.code != 2 {
				t.Errorf("restore of two backups: exit %d; want a usage error", r.code)
			}
			if after := dirFiles(t, dir); !sameFiles(before, after) {
				t.Error("a refused restore changed the data directory")
			}
			if entries, _ := os.ReadDir(noHub); len(entries) != 0 {
				t.Errorf("a refused restore wrote into a directory with no hub: %v", entries)
			}
		})
	}
}

// dirFiles is every file directly in dir with its contents.
func dirFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			out[e.Name()+"/"] = ""
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

func sameFiles(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
