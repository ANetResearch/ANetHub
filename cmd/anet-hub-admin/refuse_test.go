package main

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/ANetResearch/ANetHub/internal/admin"
	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// What anet-hub-admin refuses to start with, each answered with its one sentence (internal/admin
// text.go): the flags of the removed restore and prune paths (exit 2, nothing opened), an admin.db
// of an earlier release (admin.db_too_old) and a hub data directory of 0.2 or of a newer anet-hub
// (anet-hub's own hub_identity_v02 and hub_data_too_new), left as they were.

const realToken = "k7Qw2mZr9TfLpX4vN3sB"

// runAdminLang runs main() in a child process in language lang ("en" or "zh") and returns its exit
// code, stdout and stderr.
func runAdminLang(t *testing.T, lang string, args ...string) (int, string, string) {
	t.Helper()
	l := "C"
	if lang == "zh" {
		l = "zh_CN.UTF-8"
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1", "ADMIN_TOKEN="+realToken, "LC_ALL=", "LC_MESSAGES=", "LANG=", "ANET_LANG="+l)
	var out, errw strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errw
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errw.String()
}

// sentenceIn is the sentence of key in lang, as the child prints it.
func sentenceIn(t *testing.T, lang, key string) string {
	t.Helper()
	l := "C"
	if lang == "zh" {
		l = "zh_CN.UTF-8"
	}
	t.Setenv("ANET_LANG", l)
	return admin.Sentence(key, nil) + "\n"
}

// snapshot is every file under dir with its size and hash ("" for no directory).
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		rel, _ := filepath.Rel(dir, p)
		lines = append(lines, fmt.Sprintf("%s %d %x", rel, len(b), sha256.Sum256(b)))
		return nil
	})
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// TestRemovedAdminFlagsAreAnswered (PAY-O4, J-PAY-14's last step): --restore-agents-from and
// --keep-only-agents, in any spelling the flag parser takes, are answered with their sentence on
// stderr, exit 2, before any database is opened: the admin data directory stays empty and the hub's
// is not touched.
func TestRemovedAdminFlagsAreAnswered(t *testing.T) {
	for _, c := range []struct {
		args []string
		key  string
	}{
		{[]string{"--restore-agents-from", "x"}, "admin.flag_removed.restore"},
		{[]string{"-restore-agents-from=/var/backups/hub.db"}, "admin.flag_removed.restore"},
		{[]string{"--restore-agents-from"}, "admin.flag_removed.restore"},
		{[]string{"--keep-only-agents", "bafya,bafyb"}, "admin.flag_removed.prune"},
		{[]string{"--keep-only-agents=bafya"}, "admin.flag_removed.prune"},
	} {
		for _, lang := range []string{"en", "zh"} {
			data, hubData := t.TempDir(), t.TempDir()
			hubBefore := snapshot(t, hubData)
			args := append([]string{"-addr", "127.0.0.1:0", "-data", data, "-hub-data", hubData}, c.args...)
			code, out, errw := runAdminLang(t, lang, args...)
			if want := sentenceIn(t, lang, c.key); code != 2 || errw != want || out != "" {
				t.Errorf("%v (%s): exit %d, stdout %q, stderr %q; want exit 2 and %q", c.args, lang, code, out, errw, want)
			}
			if s := snapshot(t, data); s != "" {
				t.Errorf("%v: the admin data directory was written: %s", c.args, s)
			}
			if s := snapshot(t, hubData); s != hubBefore {
				t.Errorf("%v: the hub data directory changed", c.args)
			}
		}
	}
}

// TestTheAdminRefusesOldHubData (core CORE-V4): a hub data directory of 0.2 or of a newer anet-hub
// is answered with anet-hub's own sentence for it, exit 1, and its files are left as they were.
func TestTheAdminRefusesOldHubData(t *testing.T) {
	for _, c := range []struct {
		version int
		key     string
	}{{0, "hub_identity_v02"}, {2, "hub_identity_v02"}, {aghub.SchemaVersion + 1, "hub_data_too_new"}} {
		for _, lang := range []string{"en", "zh"} {
			hubData := t.TempDir()
			db, err := sql.Open("sqlite", filepath.Join(hubData, "hub.db"))
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{`CREATE TABLE agent (aid TEXT PRIMARY KEY, kel BLOB NOT NULL)`,
				`PRAGMA user_version = ` + strconv.Itoa(c.version)} {
				if _, err := db.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			db.Close()
			before := snapshot(t, hubData)
			code, _, errw := runAdminLang(t, lang, "-addr", "127.0.0.1:0", "-data", t.TempDir(), "-hub-data", hubData)
			if want := sentenceIn(t, lang, c.key); code != 1 || errw != want {
				t.Errorf("user_version %d (%s): exit %d, stderr %q; want exit 1 and %q", c.version, lang, code, errw, want)
			}
			if after := snapshot(t, hubData); after != before {
				t.Errorf("user_version %d: the refused hub data directory changed:\n%s\n%s", c.version, before, after)
			}
		}
	}
}

// TestTheAdminRefusesAnOldAdminDB (§3.4a): an admin.db whose deleted_agent still has the row column
// of the removed restore path is admin.db_too_old, exit 1, and the file is left as it was.
func TestTheAdminRefusesAnOldAdminDB(t *testing.T) {
	data := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(data, "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE deleted_agent (aid TEXT NOT NULL, row TEXT NOT NULL,
	    deleted_at TEXT NOT NULL, actor TEXT NOT NULL DEFAULT 'admin')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before := snapshot(t, data)
	for _, lang := range []string{"en", "zh"} {
		code, _, errw := runAdminLang(t, lang, "-addr", "127.0.0.1:0", "-data", data, "-hub-data", t.TempDir())
		if want := sentenceIn(t, lang, "admin.db_too_old"); code != 1 || errw != want {
			t.Errorf("%s: exit %d, stderr %q; want exit 1 and %q", lang, code, errw, want)
		}
	}
	if after := snapshot(t, data); after != before {
		t.Errorf("the refused admin.db changed:\n%s\n%s", before, after)
	}
}
