package aghub

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
)

// kel_hwm holds a count and a newline, and nothing else is read as one
// (KEL H-21): what is not is a file this hub did not write, and the start
// takes the database for an older copy.
func TestParseKELHWM(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"0\n", 0, true},
		{"7\n", 7, true},
		{"9223372036854775807\n", 1<<63 - 1, true},
		{"9223372036854775808\n", 0, false}, // more than a database counts
		{"18446744073709551615\n", 0, false},
		{"7", 0, false},
		{"07\n", 0, false},
		{"\n", 0, false},
		{"", 0, false},
		{"+7\n", 0, false},
		{"-1\n", 0, false},
		{" 7\n", 0, false},
		{"7\n\n", 0, false},
		{"7\r\n", 0, false},
		{"0x7\n", 0, false},
		{"lots\n", 0, false},
	} {
		got, err := parseKELHWM([]byte(c.in))
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("parseKELHWM(%q) = %d, %v; want %d, ok %v", c.in, got, err, c.want, c.ok)
		}
	}
}

// FuzzKELHighWaterFile: parseKELHWM never panics, accepts exactly what
// writeKELHWM writes (a count up to what a database counts, in decimal
// without leading zeros, then a newline), and a count read back is the count
// written.
func FuzzKELHighWaterFile(f *testing.F) {
	for _, s := range []string{"0\n", "1\n", "42\n", "9223372036854775807\n", "9223372036854775808\n", "007\n", "1", "", "\n", "x\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		n, err := parseKELHWM(b)
		canonical := err == nil && bytes.Equal(b, []byte(strconv.FormatUint(n, 10)+"\n"))
		if err == nil && !canonical {
			t.Fatalf("parseKELHWM(%q) = %d, but that is not how %d is written", b, n, n)
		}
		if err != nil && n != 0 {
			t.Fatalf("parseKELHWM(%q) refused with %d", b, n)
		}
		if err == nil && n > maxKELChanges {
			t.Fatalf("parseKELHWM(%q) = %d, above what a database counts", b, n)
		}
		// What writeKELHWM writes, it reads back.
		if err == nil {
			dir := t.TempDir()
			if err := writeKELHWM(dir, n); err != nil {
				t.Fatal(err)
			}
			back, err := readKELHWM(dir)
			if err != nil || back != n {
				t.Fatalf("wrote %d, read back %d (%v)", n, back, err)
			}
		}
	})
}

// A file of more than a count and a newline is not read past them.
func TestReadKELHWMReadsABoundedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, kelHWMFile), bytes.Repeat([]byte("9"), 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readKELHWM(dir); err == nil {
		t.Error("a megabyte of nines read as a count")
	}
}

// Restore empties what no backup holds: exactly the tables
// deploy/hub-db-roll.sh leaves out of a backup (core §2.16), so a restored
// hub holds what a backup holds whatever copy it came from.
func TestRestoreClearsWhatTheBackupScriptExcludes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "hub-db-roll.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^EXCLUDED_TABLES="([^"]*)"$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("hub-db-roll.sh has no EXCLUDED_TABLES line")
	}
	script := strings.Fields(string(m[1]))
	ours := slices.Clone(restoreCleared)
	slices.Sort(script)
	slices.Sort(ours)
	if !slices.Equal(script, ours) {
		t.Errorf("Restore empties %v; the backup script leaves out %v", ours, script)
	}
	// And the quarantine's own tables are in every backup.
	for _, table := range []string{"restore_state", "restore_released", "kel_hwm", "x402_first_verify"} {
		if slices.Contains(script, table) {
			t.Errorf("the backup script leaves out %s, which a restored hub needs", table)
		}
	}
}

// listedNoticeByDecoding is what a listing carried for an agent before it
// read the stored tip: the cached notice when, decoded, it states the tip of
// the decoded key history. The listings must answer the same.
func listedNoticeByDecoding(kel, notice []byte) []byte {
	if len(notice) == 0 {
		return nil
	}
	body, _, err := identity.DecodeNotice(notice)
	if err != nil {
		return nil
	}
	if seq, head, ok := kelTip(kel); !ok || body.Seq != seq || body.Head != head {
		return nil
	}
	return notice
}

// The anonymous listings (/agents and /a2a/v1/agents of this hub's agents,
// the federation card stream) take the cached notice by the tip the agent
// row keeps with its key history, and decode no key history to do it: their
// answers are the ones decoding gives (a notice for the tip listed, a stale
// one not), and they stay so with the key history's bytes replaced by ones
// that do not decode at all.
func TestListingsReadTheStoredTip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	hub := identity.SuiteController()
	s.SetHubKey(hub)
	agents := map[string]*identity.Controller{}
	for i := 0; i < 3; i++ {
		c, err := NewAgentForTest()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := identity.MarshalKEL(c.KEL())
		if err := s.RegisterAgent(c.AID(), "agent", []string{"work.do"}, raw, c.KEL()); err != nil {
			t.Fatal(err)
		}
		if _, why, err := s.NoticeFor(c.AID()); err != nil || why != "" {
			t.Fatalf("notice: %q %v", why, err)
		}
		agents[c.AID()] = c
	}
	// One agent rotates; its cached notice is put back as it was, about the
	// old tip, as a KEL change that failed to drop it would leave it.
	var rotated *identity.Controller
	for _, c := range agents {
		rotated = c
		break
	}
	_, _, _, stale, _ := noticeRow(t, s, rotated.AID())
	if err := identitytest.Rotate(rotated, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	raw, _ := identity.MarshalKEL(rotated.KEL())
	if err := s.RegisterAgent(rotated.AID(), "agent", []string{"work.do"}, raw, rotated.KEL()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO notice_cache(aid, seq, head, observed_at, blob) VALUES(?, 1, ?, ?, ?)`,
		rotated.AID(), rotated.KEL()[1].EventID, time.Now().UnixMilli(), stale); err != nil {
		t.Fatal(err)
	}

	type got struct{ agents, cached map[string][]byte }
	read := func() got {
		t.Helper()
		g := got{map[string][]byte{}, map[string][]byte{}}
		views, err := s.ListAgents("")
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range views {
			g.agents[v.AID] = decodeB64(t, v.KeyStateNotice)
		}
		for aid := range agents {
			n, err := cachedNoticeOf(s.db, aid)
			if err != nil {
				t.Fatal(err)
			}
			g.cached[aid] = n
		}
		return g
	}
	// ListAgents lists only agents with a key set: give each one (the
	// listing's own rule; it serves the bytes and does not decode them),
	// without touching the cache.
	for aid := range agents {
		if _, err := s.db.Exec(`INSERT INTO agent_keys(aid, seq, keyset, stored_at) VALUES(?, 1, x'01', '')
		    ON CONFLICT(aid) DO UPDATE SET keyset = excluded.keyset`, aid); err != nil {
			t.Fatal(err)
		}
	}
	before := read()
	for aid := range agents {
		var kel, notice []byte
		if err := s.db.QueryRow(`SELECT a.kel, n.blob FROM agent a LEFT JOIN notice_cache n ON n.aid = a.aid WHERE a.aid = ?`,
			aid).Scan(&kel, &notice); err != nil {
			t.Fatal(err)
		}
		want := listedNoticeByDecoding(kel, notice)
		if !bytes.Equal(before.agents[aid], want) || !bytes.Equal(before.cached[aid], want) {
			t.Errorf("%s: listed %x, cached %x; decoding gives %x", aid, before.agents[aid], before.cached[aid], want)
		}
		if aid == rotated.AID() && want != nil {
			t.Errorf("the stale notice of the rotated agent is one decoding lists")
		}
		if aid != rotated.AID() && want == nil {
			t.Errorf("%s has no notice for its tip", aid)
		}
	}
	// Nothing decodes the key histories.
	if _, err := s.db.Exec(`UPDATE agent SET kel = x'ff00ff'`); err != nil {
		t.Fatal(err)
	}
	after := read()
	for aid := range agents {
		if !bytes.Equal(after.agents[aid], before.agents[aid]) || !bytes.Equal(after.cached[aid], before.cached[aid]) {
			t.Errorf("%s: with a key history that does not decode the listing changed", aid)
		}
	}
}

func noticeRow(t *testing.T, s *Store, aid string) (uint64, string, int64, []byte, bool) {
	t.Helper()
	return s.NoticeRowForTest(aid)
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// FuzzRestoreBackupFile: whatever bytes are given as a backup (a damaged or
// truncated copy, or something else), Restore does not panic; when it
// refuses, the data directory is as it was, with nothing left beside it;
// when it accepts, the hub opens on what it restored, in quarantine.
func FuzzRestoreBackupFile(f *testing.F) {
	src := f.TempDir()
	s, err := Open(src)
	if err != nil {
		f.Fatal(err)
	}
	s.SetHubKey(identity.SuiteController())
	c, err := NewAgentForTest()
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := identity.MarshalKEL(c.KEL())
	if err := s.RegisterAgent(c.AID(), "agent", nil, raw, c.KEL()); err != nil {
		f.Fatal(err)
	}
	good := filepath.Join(f.TempDir(), "b.db")
	if _, err := s.db.Exec(`VACUUM INTO ?`, good); err != nil {
		f.Fatal(err)
	}
	s.Close()
	valid, err := os.ReadFile(good)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{})
	f.Add([]byte("SQLite format 3\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		backup := filepath.Join(t.TempDir(), "backup.db")
		if err := os.WriteFile(backup, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Restore(dir, backup, time.Now())
		entries, rerr := os.ReadDir(dir)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if err != nil {
			if len(entries) != 0 {
				t.Fatalf("a refused restore (%v) left %v", err, entries)
			}
			return
		}
		st, err := Open(dir)
		if err != nil {
			t.Fatalf("restored, and the hub does not open: %v", err)
		}
		defer st.Close()
		if q, err := st.Quarantine(); err != nil || !q.Active {
			t.Fatalf("restored without a quarantine: %+v %v", q, err)
		}
	})
}
