package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// A hub data directory this release does not open (core CORE-V4) is refused
// with one sentence that says why and what to do, exit 1, by the hub and by
// every subcommand, and nothing in the directory is written: data of 0.2 or
// earlier is hub_identity_v02 (move it away; a new identity is created);
// data a newer anet-hub wrote is hub_data_too_new (upgrade; do not delete
// it).

// snapshotDir is every file in dir with its size and hash.
func snapshotDir(t *testing.T, dir string) string {
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

// writeHubDB makes dir/hub.db with stmts at the given user_version.
func writeHubDB(t *testing.T, dir string, version int, stmts ...string) {
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

// refusedEverywhere opens dir as the hub would to serve and as two
// subcommands would, in both languages, and checks each says key on stderr
// with exit 1 and leaves dir as it was.
func refusedEverywhere(t *testing.T, dir, key string) {
	t.Helper()
	before := snapshotDir(t, dir)
	for _, lang := range []string{"en", "zh"} {
		// Serving (main: openStore).
		l := "C"
		if lang == "zh" {
			l = "zh_CN.UTF-8"
		}
		t.Setenv("ANET_LANG", l)
		var out, errw bytes.Buffer
		store, code := openStore(newConsole(&out, &errw), dir)
		if store != nil {
			store.Close()
			t.Fatalf("%s: the hub opened the directory", lang)
		}
		if want := sentenceOf(lang, key, nil); code != 1 || errw.String() != want || out.Len() != 0 {
			t.Errorf("%s: serving: exit %d, stdout %q, stderr %q; want exit 1, stderr %q", lang, code, out.String(), errw.String(), want)
		}
		// Subcommands.
		_, aid := newAID(t)
		expectErr(t, cli(t, lang, "-data", dir, "admissions"), 1, sentenceOf(lang, key, nil))
		expectErr(t, cli(t, lang, "-data", dir, "grant", aid, "--amount", "5"), 1, sentenceOf(lang, key, nil))
		expectErr(t, cli(t, lang, "-data", dir, "supply"), 1, sentenceOf(lang, key, nil))
	}
	if after := snapshotDir(t, dir); after != before {
		t.Errorf("the refused directory changed:\n%s\n%s", before, after)
	}
}

// TestHubRefusesOldDB: a hub.db of 0.2 — tables without a version, or a
// version below 3 — is hub_identity_v02.
func TestHubRefusesOldDB(t *testing.T) {
	const v02Agent = `CREATE TABLE agent (aid TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '',
	   caps TEXT NOT NULL DEFAULT '[]', pricing TEXT NOT NULL DEFAULT '', kel BLOB NOT NULL, registered_at TEXT NOT NULL)`
	for _, c := range []struct {
		name    string
		version int
	}{{"no version", 0}, {"version 1", 1}, {"version 2", 2}} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeHubDB(t, dir, c.version, v02Agent,
				`CREATE TABLE credit_issuance (seq INTEGER PRIMARY KEY, amount INTEGER)`)
			refusedEverywhere(t, dir, "hub_identity_v02")
		})
	}
	// The sentence covers the database as well as the identity file, and
	// says to move the directory away.
	if got := render("hub_identity_v02", langEN, nil); !strings.Contains(got, "database") ||
		!strings.Contains(got, "move the hub data directory away") {
		t.Errorf("hub_identity_v02: %q", got)
	}
}

// TestHubRefusesNewerDB: a hub.db a newer anet-hub wrote is
// hub_data_too_new, whose next step is to upgrade and not to move the data.
func TestHubRefusesNewerDB(t *testing.T) {
	for _, version := range []int{aghub.SchemaVersion + 1, 99} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			dir := t.TempDir()
			writeHubDB(t, dir, version, `CREATE TABLE agent (aid TEXT PRIMARY KEY, kel BLOB NOT NULL)`)
			refusedEverywhere(t, dir, "hub_data_too_new")
		})
	}
	for _, lang := range []textLang{langEN, langZH} {
		got := render("hub_data_too_new", lang, nil)
		if strings.Contains(got, "move") || strings.Contains(got, "移走") {
			t.Errorf("hub_data_too_new tells the operator to move valid data away: %q", got)
		}
		if !strings.Contains(got, "anet-hub") {
			t.Errorf("hub_data_too_new does not name what to upgrade: %q", got)
		}
	}
}

// A 0.3.0 directory opens for serving with no sentence.
func TestHubOpensItsOwnDB(t *testing.T) {
	dir := hubDir(t)
	var out, errw bytes.Buffer
	store, code := openStore(newConsole(&out, &errw), dir)
	if store == nil || code != 0 || errw.Len() != 0 || out.Len() != 0 {
		t.Fatalf("a 0.3.0 directory: exit %d, %q %q", code, out.String(), errw.String())
	}
	store.Close()
}
