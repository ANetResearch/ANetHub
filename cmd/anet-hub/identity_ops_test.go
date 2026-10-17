package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// The hub identity subcommands and the hub's start (KEL H-30 to H-36,
// D-31a, C-34; identity_ops.go).

// The passphrases of these tests: two good ones, and the refused kinds.
var (
	passA     = []byte("correct horse battery staple")
	passB     = []byte("a different and longer passphrase")
	passShort = []byte("too short")
	passBadU8 = []byte("not utf-8 \xff\xfe at all!!")
)

// fakeTerm is a terminal whose typing a test scripts: each ReadSecret takes
// the next answer. It records the prompts and lines it was given.
type fakeTerm struct {
	mu      sync.Mutex
	answers [][]byte
	prompts []string
	said    []string
}

func typing(answers ...[]byte) *fakeTerm { return &fakeTerm{answers: answers} }

func (f *fakeTerm) ReadSecret(prompt string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prompts = append(f.prompts, prompt)
	if len(f.answers) == 0 {
		return nil, io.EOF
	}
	a := append([]byte(nil), f.answers[0]...)
	f.answers = f.answers[1:]
	return a, nil
}

func (f *fakeTerm) Say(line string) {
	f.mu.Lock()
	f.said = append(f.said, line)
	f.mu.Unlock()
}

func (f *fakeTerm) Close() error { return nil }

// idCLI runs anet-hub with args as main would, in lang, with term as the
// controlling terminal (nil: the process has none).
func idCLI(t *testing.T, lang string, term terminal, args ...string) cliResult {
	t.Helper()
	l := "C"
	if lang == "zh" {
		l = "zh_CN.UTF-8"
	}
	t.Setenv("ANET_LANG", l)
	fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := defineFlags(fs)
	if err := fs.Parse(args); err != nil {
		return cliResult{code: 2, stderr: err.Error()}
	}
	var out, errw bytes.Buffer
	c := newConsole(&out, &errw)
	c.openTerminal = func() (terminal, error) {
		if term == nil {
			return nil, errNoTerminal
		}
		return term, nil
	}
	code, done := beforeServing(f, fs, c)
	return cliResult{code: code, served: !done, stdout: out.String(), stderr: errw.String()}
}

// recDir is a directory for recovery files; HOME points at another, so that
// no test writes the default place of the person running it.
func recDir(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return t.TempDir()
}

// setUp runs setup-recovery on the hub of dir with pass, its recovery file
// at path, and checks it succeeded.
func setUp(t *testing.T, dir, path string, pass []byte) {
	t.Helper()
	r := idCLI(t, "en", typing(pass, pass), "-data", dir, "identity", "setup-recovery", "--recovery-file", path)
	if r.code != 0 {
		t.Fatalf("setup-recovery: exit %d %q %q", r.code, r.stdout, r.stderr)
	}
}

// loadHub is the hub identity of dir as its file holds it.
func loadHub(t *testing.T, dir string) *hubid.Identity {
	t.Helper()
	id, err := hubid.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// openRec opens the recovery file at path with pass.
func openRec(t *testing.T, path string, pass []byte) ([32]byte, identity.Commit, error) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rs, _, _, commit, err := identity.OpenRecoveryFile(b, pass)
	return rs, commit, err
}

// fileOf is a file's bytes, or nil.
func fileOf(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

// v02IdentityFile is a hub identity file of 0.2: a CBOR map without the type
// tag of an identity file v2.
func v02IdentityFile(t *testing.T) []byte {
	t.Helper()
	b, err := cbor.Marshal(map[uint64]any{1: []byte("kel of 0.2"), 2: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// KEL S-2, H-30: a hub identity file of 0.2 is refused, by the hub and by
// every subcommand, with hub_identity_v02 and exit 1; nothing in the data
// directory is written, and the file stays where it is.
func TestHubRefusesToStartWithV1IdentityFile(t *testing.T) {
	for _, withDB := range []bool{false, true} {
		t.Run(fmt.Sprint("hub.db ", withDB), func(t *testing.T) {
			dir := t.TempDir()
			if withDB {
				s, err := aghub.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				s.Close()
			}
			if err := os.WriteFile(filepath.Join(dir, hubid.FileName), v02IdentityFile(t), 0o600); err != nil {
				t.Fatal(err)
			}
			before := snapshotDir(t, dir)
			for _, lang := range []string{"en", "zh"} {
				want := sentenceOf(lang, "hub_identity_v02", nil)
				t.Setenv("ANET_LANG", map[string]string{"en": "C", "zh": "zh_CN.UTF-8"}[lang])
				var out, errw bytes.Buffer
				store, code := openStore(newConsole(&out, &errw), dir)
				if store != nil {
					store.Close()
					t.Fatalf("%s: the hub opened a 0.2 identity", lang)
				}
				if code != 1 || errw.String() != want || out.Len() != 0 {
					t.Errorf("%s: serving: exit %d %q %q, want %q", lang, code, out.String(), errw.String(), want)
				}
				term := typing(passA, passA)
				for _, args := range [][]string{
					{"identity", "status"},
					{"identity", "setup-recovery", "--recovery-file", filepath.Join(t.TempDir(), "r")},
					{"identity", "rotate", "--recovery-file", filepath.Join(t.TempDir(), "r")},
				} {
					expectErr(t, idCLI(t, lang, term, append([]string{"-data", dir}, args...)...), 1, want)
				}
				if withDB {
					expectErr(t, cli(t, lang, "-data", dir, "admissions"), 1, want)
					expectErr(t, cli(t, lang, "-data", dir, "supply"), 1, want)
				}
				if len(term.prompts) != 0 {
					t.Errorf("%s: a passphrase was asked for a 0.2 identity", lang)
				}
			}
			if after := snapshotDir(t, dir); after != before {
				t.Errorf("the refused directory changed:\n%s\n%s", before, after)
			}
		})
	}
}

// KEL H-31, H-32: setup-recovery and rotate run only while the hub is
// stopped, and only with a terminal for the passphrase; otherwise they
// refuse (hub_running, hub_identity.tty_required), exit 1, and change
// nothing. The serving hub holds the lock they test for.
func TestSetupRecoveryRequiresStoppedHubAndTTY(t *testing.T) {
	rd := recDir(t)
	for _, lang := range []string{"en", "zh"} {
		dir := hubDir(t)
		path := filepath.Join(rd, lang+".anetrec")
		// The hub is serving: its start took the lock.
		store, err := aghub.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		var out, errw bytes.Buffer
		id, lock, code := startIdentity(newConsole(&out, &errw), dir, store, func(string, ...any) {})
		if id == nil {
			t.Fatalf("start: exit %d %q", code, errw.String())
		}
		for _, action := range []string{"setup-recovery", "rotate"} {
			term := typing(passA, passA)
			expectErr(t, idCLI(t, lang, term, "-data", dir, "identity", action, "--recovery-file", path), 1,
				sentenceOf(lang, "hub_running", map[string]string{"action": action}))
			if len(term.prompts) != 0 {
				t.Errorf("%s %s: a passphrase was asked while the hub runs", lang, action)
			}
		}
		// A second hub on the same directory is refused too.
		var out2, errw2 bytes.Buffer
		if id2, _, code := startIdentity(newConsole(&out2, &errw2), dir, store, func(string, ...any) {}); id2 != nil || code != 1 ||
			errw2.String() != sentenceOf(lang, "data.in_use", map[string]string{"path": dir}) {
			t.Errorf("a second hub on the directory: exit %d %q", code, errw2.String())
		}
		lock.Release()
		store.Close()
		// Stopped, but no terminal.
		snap := snapshotDir(t, dir)
		expectErr(t, idCLI(t, lang, nil, "-data", dir, "identity", "setup-recovery", "--recovery-file", path), 1,
			sentenceOf(lang, "hub_identity.tty_required", map[string]string{"action": "setup-recovery"}))
		if after := snapshotDir(t, dir); after != snap {
			t.Errorf("%s: setup-recovery without a terminal changed the directory", lang)
		}
		if fileOf(path) != nil {
			t.Errorf("%s: setup-recovery without a terminal wrote a recovery file", lang)
		}
		if loadHub(t, dir).RecoverySet() {
			t.Fatalf("%s: the recovery was set", lang)
		}
		// Set up, then rotate without a terminal.
		setUp(t, dir, path, passA)
		snap = snapshotDir(t, dir)
		rec := fileOf(path)
		expectErr(t, idCLI(t, lang, nil, "-data", dir, "identity", "rotate", "--recovery-file", path), 1,
			sentenceOf(lang, "hub_identity.tty_required", map[string]string{"action": "rotate"}))
		if after := snapshotDir(t, dir); after != snap || !bytes.Equal(fileOf(path), rec) {
			t.Errorf("%s: rotate without a terminal changed something", lang)
		}
	}
}

// KEL H-31, C-31, C-32: setup-recovery writes the recovery file (0600, the
// note in both languages) and makes the first rotation, which reveals the
// icp's hot key and commits the seed's key for seq 2; the hub then holds no
// next key. A second run has nothing to do.
func TestHubSetupRecovery(t *testing.T) {
	rd := recDir(t)
	dir := hubDir(t)
	path := filepath.Join(rd, "hub.anetrec")
	if !strings.Contains(idCLI(t, "en", nil, "-data", dir, "identity", "status").stdout, "recovery\tunset\n"+
		render("hub_recovery_setup_required", langEN, nil)) {
		t.Error("status before setup-recovery does not say it is needed")
	}
	icp := loadHub(t, dir).Ctrl.Accepted()[0]
	r := idCLI(t, "zh", typing(passA, passA), "-data", dir, "identity", "setup-recovery", "--recovery-file", path)
	want := sentenceOf("zh", "hub_identity.recovery_written", map[string]string{"path": path}) +
		sentenceOf("zh", "hub_identity.rotated", map[string]string{"from": "0", "to": "1"})
	expectOut(t, r, want)
	id := loadHub(t, dir)
	kel := id.Ctrl.Accepted()
	if len(kel) != 2 || !id.RecoverySet() || kel[1].Event.Type != identity.Rotation || kel[1].Event.Emergency {
		t.Fatalf("after setup-recovery the KEL is %d events", len(kel))
	}
	// The rot revealed the hot key the icp committed.
	if d := sha256Of(kel[1].Event.Keys[0]); !bytes.Equal(d, icp.Event.NextDigest) {
		t.Error("the first rotation did not reveal the icp's hot key")
	}
	rs, commit, err := openRec(t, path, passA)
	if err != nil {
		t.Fatal(err)
	}
	if commit.Seq != 2 || !bytes.Equal(commit.Digest[:], id.Commitment()) {
		t.Errorf("the recovery file commits %d %x, the KEL %x", commit.Seq, commit.Digest, id.Commitment())
	}
	if d, _ := identity.NextDigest(rs, id.AID, 2); !bytes.Equal(d[:], kel[1].Event.NextDigest) {
		t.Error("the rotation does not commit the seed's key for seq 2")
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("recovery file mode: %v %v", st.Mode(), err)
	}
	text := string(fileOf(path))
	for _, lang := range []textLang{langZH, langEN} {
		if !strings.Contains(text, render("hub_identity.recovery_file_note", lang, nil)) {
			t.Errorf("the recovery file has no note in language %d", lang)
		}
	}
	// The identity file holds no next key.
	f, err := identity.ParseIdentityFile(fileOf(filepath.Join(dir, hubid.FileName)))
	if err != nil || f.HotNext != nil || f.Pending != nil {
		t.Errorf("the identity file after setup-recovery: %+v %v", f, err)
	}
	expectOut(t, idCLI(t, "en", typing(passA, passA), "-data", dir, "identity", "setup-recovery", "--recovery-file", path),
		sentenceOf("en", "hub_identity.recovery_already", nil))
	st2 := idCLI(t, "en", nil, "-data", dir, "identity", "status", "--recovery-file", path)
	if want := "aid\t" + id.AID + "\nkey_seq\t1\nrecovery\tset\nrecovery_file\t" + path + "\tpresent\n"; st2.stdout != want || st2.code != 0 {
		t.Errorf("status: %q, want %q", st2.stdout, want)
	}
	// A new hub sets it up before its first start: the identity is made
	// then. A recovery file already where it would go is never overwritten.
	fresh := filepath.Join(t.TempDir(), "new-hub")
	setUp(t, fresh, filepath.Join(rd, "fresh.anetrec"), passB)
	if !loadHub(t, fresh).RecoverySet() {
		t.Error("setup-recovery of a new data directory")
	}
	other := hubDir(t)
	expectErr(t, idCLI(t, "en", typing(passA, passA), "-data", other, "identity", "setup-recovery", "--recovery-file", path), 1,
		sentenceOf("en", "hub_identity.recovery_file_exists", map[string]string{"path": path}))
}

func sha256Of(b []byte) []byte {
	d := sha256.Sum256(b)
	return d[:]
}

// KEL C-34: a new passphrase that is too short or not UTF-8 is refused at
// once with its sentence, exit 1, and nothing is written; a passphrase
// that is not UTF-8 is refused before a recovery file is opened with it.
// Two entries that differ are asked again.
func TestHubPassphraseRefusals(t *testing.T) {
	rd := recDir(t)
	// A new hub's data directory: its identity is made by setup-recovery,
	// and a refused passphrase leaves none behind.
	fresh := filepath.Join(t.TempDir(), "new-hub")
	expectErr(t, idCLI(t, "en", typing(passShort), "-data", fresh, "identity", "setup-recovery", "--recovery-file",
		filepath.Join(rd, "fresh.anetrec")), 1, sentenceOf("en", "hub_passphrase_too_short", nil))
	if hubid.Exists(fresh) || fileOf(filepath.Join(rd, "fresh.anetrec")) != nil {
		t.Error("a refused passphrase left a new hub's identity or recovery file behind")
	}
	for _, lang := range []string{"en", "zh"} {
		dir := hubDir(t)
		path := filepath.Join(rd, lang+".anetrec")
		snap := snapshotDir(t, dir)
		expectErr(t, idCLI(t, lang, typing(passShort), "-data", dir, "identity", "setup-recovery", "--recovery-file", path), 1,
			sentenceOf(lang, "hub_passphrase_too_short", nil))
		expectErr(t, idCLI(t, lang, typing(passBadU8), "-data", dir, "identity", "setup-recovery", "--recovery-file", path), 1,
			sentenceOf(lang, "hub_passphrase_not_utf8", nil))
		if snapshotDir(t, dir) != snap || fileOf(path) != nil {
			t.Fatalf("%s: a refused passphrase wrote something", lang)
		}
		// Asked again until the two entries agree.
		term := typing(passA, passB, passA, passA)
		if r := idCLI(t, lang, term, "-data", dir, "identity", "setup-recovery", "--recovery-file", path); r.code != 0 {
			t.Fatalf("%s: setup-recovery after a mismatch: %d %q", lang, r.code, r.stderr)
		}
		l := map[string]textLang{"en": langEN, "zh": langZH}[lang]
		if len(term.said) != 1 || term.said[0] != render("hub_identity.prompt.mismatch", l, nil) ||
			len(term.prompts) != 4 || term.prompts[0] != render("hub_identity.prompt.new_passphrase", l, nil) ||
			term.prompts[1] != render("hub_identity.prompt.again", l, nil) {
			t.Errorf("%s: prompts %q, said %q", lang, term.prompts, term.said)
		}
		if _, _, err := openRec(t, path, passA); err != nil {
			t.Fatalf("%s: the passphrase set is not the one typed twice: %v", lang, err)
		}
		snap = snapshotDir(t, dir)
		rec := fileOf(path)
		expectErr(t, idCLI(t, lang, typing(passBadU8), "-data", dir, "identity", "rotate", "--recovery-file", path), 1,
			sentenceOf(lang, "hub_passphrase_not_utf8", nil))
		expectErr(t, idCLI(t, lang, typing(passB), "-data", dir, "identity", "rotate", "--recovery-file", path), 1,
			sentenceOf(lang, "hub_identity.passphrase_wrong", nil))
		expectErr(t, idCLI(t, lang, typing(passA, passShort), "-data", dir, "identity", "rotate", "--new-recovery", "--recovery-file", path), 1,
			sentenceOf(lang, "hub_passphrase_too_short", nil))
		expectErr(t, idCLI(t, lang, typing(passA, passBadU8), "-data", dir, "identity", "rotate", "--emergency", "--recovery-file", path), 1,
			sentenceOf(lang, "hub_passphrase_not_utf8", nil))
		if snapshotDir(t, dir) != snap || !bytes.Equal(fileOf(path), rec) || fileOf(path+".new") != nil {
			t.Errorf("%s: a refused rotation changed something", lang)
		}
	}
}

// KEL D-31a, H-32: changing the recovery seed rotates twice, so that the
// current key is the new seed's alone: the first rotation reveals the old
// seed's key and commits the new seed's, the second reveals the new seed's.
// The old recovery file no longer works. A planned rotation is one, from
// the same seed. --emergency is the same pair, both urgent (key 12).
func TestHubNewRecoveryRotatesTwice(t *testing.T) {
	rd := recDir(t)
	for _, emergency := range []bool{false, true} {
		t.Run(fmt.Sprint("emergency ", emergency), func(t *testing.T) {
			dir := hubDir(t)
			path := filepath.Join(rd, fmt.Sprint(emergency)+".anetrec")
			setUp(t, dir, path, passA)
			// A planned rotation: one event, the same seed.
			rs1, _, err := openRec(t, path, passA)
			if err != nil {
				t.Fatal(err)
			}
			old := fileOf(path)
			expectOut(t, idCLI(t, "en", typing(passA), "-data", dir, "identity", "rotate", "--recovery-file", path),
				sentenceOf("en", "hub_identity.rotated", map[string]string{"from": "1", "to": "2"}))
			id := loadHub(t, dir)
			k2, _ := identity.RecoverySeed(rs1, id.AID, 2)
			if kel := id.Ctrl.Accepted(); len(kel) != 3 || !bytes.Equal(kel[2].Event.Keys[0], k2.Public().(ed25519.PublicKey)) {
				t.Fatalf("a planned rotation: %d events", len(kel))
			}
			if !bytes.Equal(fileOf(path), old) {
				t.Error("a planned rotation rewrote the recovery file")
			}
			flag := "--new-recovery"
			if emergency {
				flag = "--emergency"
			}
			r := idCLI(t, "en", typing(passA, passB, passB), "-data", dir, "identity", "rotate", flag, "--recovery-file", path)
			if r.code != 0 || !strings.HasPrefix(r.stdout, sentenceOf("en", "hub_identity.rotated", map[string]string{"from": "2", "to": "4"})+
				sentenceOf("en", "hub_identity.recovery_written", map[string]string{"path": path})) {
				t.Fatalf("rotate %s: %d %q %q", flag, r.code, r.stdout, r.stderr)
			}
			id = loadHub(t, dir)
			kel := id.Ctrl.Accepted()
			if len(kel) != 5 {
				t.Fatalf("rotate %s added %d events, want 2", flag, len(kel)-3)
			}
			rs2, commit, err := openRec(t, path, passB)
			if err != nil {
				t.Fatalf("the new recovery file does not open with the new passphrase: %v", err)
			}
			if rs2 == rs1 {
				t.Fatal("the seed did not change")
			}
			if _, _, err := openRec(t, path, passA); !errors.Is(err, identity.ErrRecoveryPassphrase) {
				t.Errorf("the new recovery file opens with the old passphrase: %v", err)
			}
			pub := func(rs [32]byte, seq uint64) []byte {
				k, err := identity.RecoverySeed(rs, id.AID, seq)
				if err != nil {
					t.Fatal(err)
				}
				return k.Public().(ed25519.PublicKey)
			}
			nd := func(rs [32]byte, seq uint64) []byte {
				d, _ := identity.NextDigest(rs, id.AID, seq)
				return d[:]
			}
			// The first reveals the old seed's key and commits the new seed's.
			if !bytes.Equal(kel[3].Event.Keys[0], pub(rs1, 3)) || !bytes.Equal(kel[3].Event.NextDigest, nd(rs2, 4)) {
				t.Error("the first rotation of the pair")
			}
			// The second, the current key, is the new seed's only.
			if !bytes.Equal(kel[4].Event.Keys[0], pub(rs2, 4)) || bytes.Equal(kel[4].Event.Keys[0], pub(rs1, 4)) ||
				!bytes.Equal(kel[4].Event.NextDigest, nd(rs2, 5)) {
				t.Error("the current key is not the new seed's alone")
			}
			if commit.Seq != 5 || !bytes.Equal(commit.Digest[:], id.Commitment()) {
				t.Errorf("the recovery file commits seq %d", commit.Seq)
			}
			for _, e := range kel[3:] {
				if e.Event.Emergency != emergency {
					t.Errorf("rot %d: emergency %v", e.Event.Seq, e.Event.Emergency)
				}
			}
			// The recovery file of before no longer rotates the hub.
			stale := filepath.Join(rd, fmt.Sprint(emergency)+"-old.anetrec")
			if err := os.WriteFile(stale, old, 0o600); err != nil {
				t.Fatal(err)
			}
			expectErr(t, idCLI(t, "en", typing(passA), "-data", dir, "identity", "rotate", "--recovery-file", stale), 1,
				sentenceOf("en", "hub_identity.recovery_stale", map[string]string{"path": stale}))
			if fileOf(path+".new") != nil {
				t.Error("a .new recovery file was left")
			}
		})
	}
}

// testSecret is a secret of this test package's hubs: a file of the data
// directory, registered once with the emergency rotation.
const testSecret = "test-secret"

var registerTestSecret = sync.OnceFunc(func() {
	hubid.RegisterEmergencySecret(hubid.EmergencySecret{Name: testSecret, Regenerate: func(dir string) error {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, testSecret), b, 0o600)
	}})
})

// KEL H-33, core G18: an emergency rotation replaces every secret
// hubid.EmergencySecrets lists that the hub keeps, says which, and names
// those the operator replaces (the admin token, not in the data
// directory). A planned rotation or a new recovery seed replaces none.
func TestHubEmergencyRegeneratesListedSecrets(t *testing.T) {
	registerTestSecret()
	rd := recDir(t)
	dir := hubDir(t)
	path := filepath.Join(rd, "hub.anetrec")
	setUp(t, dir, path, passA)
	secret := filepath.Join(dir, testSecret)
	if err := os.WriteFile(secret, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := idCLI(t, "en", typing(passA), "-data", dir, "identity", "rotate", "--recovery-file", path); r.code != 0 {
		t.Fatal(r.stderr)
	}
	if r := idCLI(t, "en", typing(passA, passB, passB), "-data", dir, "identity", "rotate", "--new-recovery", "--recovery-file", path); r.code != 0 ||
		strings.Contains(r.stdout, testSecret) {
		t.Fatalf("--new-recovery: %d %q %q", r.code, r.stdout, r.stderr)
	}
	if string(fileOf(secret)) != "before" {
		t.Fatal("a rotation that is not an emergency replaced a secret")
	}
	for _, lang := range []string{"zh", "en"} {
		pass, next := passB, passA
		if lang == "en" {
			pass, next = passA, passB
		}
		before := fileOf(secret)
		r := idCLI(t, lang, typing(pass, next, next), "-data", dir, "identity", "rotate", "--emergency", "--recovery-file", path)
		var replaced []string
		for _, s := range hubid.EmergencySecrets() {
			if s.Regenerate != nil {
				replaced = append(replaced, s.Name)
			}
		}
		if !strings.HasSuffix(r.stdout, sentenceOf(lang, "hub_identity.secrets_regenerated", map[string]string{"list": strings.Join(replaced, ", ")})+
			sentenceOf(lang, "hub_identity.secrets_by_operator", map[string]string{"list": hubid.AdminTokenSecret})) || r.code != 0 {
			t.Fatalf("%s: emergency: %d %q %q", lang, r.code, r.stdout, r.stderr)
		}
		if after := fileOf(secret); len(after) != 32 || bytes.Equal(after, before) {
			t.Errorf("%s: the listed secret was not replaced", lang)
		}
	}
}

// KEL H-35: the first start after the hub identity rotated drops, before it
// serves, every witness notice cached under the key it rotated away from,
// so none is served again; the next is signed with the new key. A start
// without a rotation keeps them.
func TestHubRotationClearsNoticeCache(t *testing.T) {
	rd := recDir(t)
	dir := hubDir(t)
	path := filepath.Join(rd, "hub.anetrec")
	setUp(t, dir, path, passA)
	hubAID := loadHub(t, dir).AID
	agent, err := identitytest.Agent()
	if err != nil {
		t.Fatal(err)
	}
	if err := identitytest.SwitchWitness(agent, hubAID, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	registerIn(t, dir, agent)
	serve := func() (*aghub.Store, *hubid.DirLock, string) {
		t.Helper()
		store, err := aghub.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		var logged strings.Builder
		var out, errw bytes.Buffer
		id, lock, code := startIdentity(newConsole(&out, &errw), dir, store, func(f string, a ...any) { fmt.Fprintf(&logged, f+"\n", a...) })
		if id == nil {
			t.Fatalf("start: %d %q", code, errw.String())
		}
		return store, lock, logged.String()
	}
	noticeSeq := func(store *aghub.Store) uint64 {
		t.Helper()
		n, why, err := store.NoticeFor(agent.AID())
		if err != nil || why != "" {
			t.Fatalf("notice: %q %v", why, err)
		}
		_, env, err := identity.DecodeNotice(n)
		if err != nil {
			t.Fatal(err)
		}
		return env.KeyStateSeq
	}
	cached := func() int {
		t.Helper()
		db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM notice_cache`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	store, lock, _ := serve()
	if seq := noticeSeq(store); seq != 1 {
		t.Fatalf("the notice is signed at %d", seq)
	}
	store.Close()
	lock.Release()
	// A restart without a rotation keeps the notice.
	store, lock, _ = serve()
	if cached() != 1 {
		t.Fatal("a start without a rotation dropped the notice")
	}
	store.Close()
	lock.Release()
	// The hub stops, rotates, starts.
	if r := idCLI(t, "en", typing(passA), "-data", dir, "identity", "rotate", "--recovery-file", path); r.code != 0 {
		t.Fatal(r.stderr)
	}
	if cached() != 1 {
		t.Fatal("the rotation itself is not what drops the cache")
	}
	store, lock, logged := serve()
	defer store.Close()
	defer lock.Release()
	if n := cached(); n != 0 {
		t.Fatalf("after the rotation, %d notices signed with the old key are still cached", n)
	}
	if !strings.Contains(logged, "dropped 1 ") {
		t.Errorf("the start did not say what it dropped: %q", logged)
	}
	if seq := noticeSeq(store); seq != 2 {
		t.Errorf("after the rotation the notice is signed at %d, want 2", seq)
	}
}

// KEL H-31: until its recovery passphrase is set, the hub says so in its log
// at every start (and anet-hub identity status says the same sentence).
func TestHubStartSaysRecoverySetupRequired(t *testing.T) {
	rd := recDir(t)
	dir := hubDir(t)
	start := func() string {
		store, err := aghub.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		var logged strings.Builder
		var out, errw bytes.Buffer
		_, lock, _ := startIdentity(newConsole(&out, &errw), dir, store, func(f string, a ...any) { fmt.Fprintf(&logged, f+"\n", a...) })
		lock.Release()
		return logged.String()
	}
	t.Setenv("ANET_LANG", "C")
	if got := start(); !strings.Contains(got, render("hub_recovery_setup_required", langEN, nil)) {
		t.Errorf("start before setup-recovery logged %q", got)
	}
	setUp(t, dir, filepath.Join(rd, "hub.anetrec"), passA)
	if got := start(); strings.Contains(got, render("hub_recovery_setup_required", langEN, nil)) {
		t.Errorf("start after setup-recovery logged %q", got)
	}
	expectErr(t, idCLI(t, "en", typing(passA), "-data", hubDir(t), "identity", "rotate"), 1,
		sentenceOf("en", "hub_recovery_setup_required", nil))
}

// KEL L-3: a .new recovery file a crash left is renamed into place by the
// next setup-recovery or rotate when the identity commits to what it
// states, and removed when it does not; neither needs the passphrase.
func TestLeftoverNewRecoveryFile(t *testing.T) {
	rd := recDir(t)
	dir := hubDir(t)
	path := filepath.Join(rd, "hub.anetrec")
	setUp(t, dir, path, passA)
	good := fileOf(path)
	// The identity file was written, the rename was not.
	if err := os.Rename(path, path+".new"); err != nil {
		t.Fatal(err)
	}
	expectOut(t, idCLI(t, "en", nil, "-data", dir, "identity", "setup-recovery", "--recovery-file", path),
		sentenceOf("en", "hub_identity.recovery_already", nil))
	if !bytes.Equal(fileOf(path), good) || fileOf(path+".new") != nil {
		t.Fatal("the .new recovery file the identity commits to was not finished")
	}
	// The identity file was not written: the .new is removed.
	other := filepath.Join(rd, "other.anetrec")
	setUp(t, hubDir(t), other, passA)
	if err := os.WriteFile(path+".new", fileOf(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := idCLI(t, "en", typing(passA), "-data", dir, "identity", "rotate", "--recovery-file", path); r.code != 0 {
		t.Fatalf("rotate: %q", r.stderr)
	}
	if !bytes.Equal(fileOf(path), good) || fileOf(path+".new") != nil {
		t.Error("a .new recovery file the identity does not commit to was not removed")
	}
	// The first rotation of rotate --new-recovery stopped before the
	// identity file was written: a .new of this hub, sealed under the new
	// passphrase, committing the new seed's key. It is removed, and the
	// recovery file in place still opens with the passphrase in use.
	id := loadHub(t, dir)
	var rs [32]byte
	if _, err := rand.Read(rs[:]); err != nil {
		t.Fatal(err)
	}
	d, err := identity.NextDigest(rs, id.AID, id.Seq()+2)
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := identity.SealRecoveryFile(rs, id.AID, "", identity.Commit{Seq: id.Seq() + 2, Digest: d}, passB)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".new", stopped, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := idCLI(t, "en", typing(passA), "-data", dir, "identity", "rotate", "--recovery-file", path); r.code != 0 {
		t.Fatalf("rotate after a stopped --new-recovery: %q", r.stderr)
	}
	if !bytes.Equal(fileOf(path), good) || fileOf(path+".new") != nil {
		t.Error("a .new of this hub whose seed the identity does not commit to was not removed")
	}
}

// KEL L-3: a new recovery file replaces the old one only after the identity
// file that commits to its seed is written. When the identity file cannot
// be written, the old recovery file stays in place and still rotates the
// hub; the .new left beside it is removed by the next command.
func TestNewRecoveryFileReplacesTheOldOnlyAfterTheIdentity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a user that a read-only directory refuses (not root)")
	}
	rd := recDir(t)
	dir := hubDir(t)
	path := filepath.Join(rd, "hub.anetrec")
	setUp(t, dir, path, passA)
	good := fileOf(path)
	seq := loadHub(t, dir).Seq()
	// The identity file cannot be written: the data directory is read-only.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	r := idCLI(t, "en", typing(passA, passB, passB), "-data", dir, "identity", "rotate", "--new-recovery", "--recovery-file", path)
	if r.code != 1 {
		t.Fatalf("rotate --new-recovery with the identity file unwritable: exit %d %q", r.code, r.stdout)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileOf(path), good) || loadHub(t, dir).Seq() != seq {
		t.Fatal("the recovery file was replaced though the identity file was not written")
	}
	if r := idCLI(t, "en", typing(passA), "-data", dir, "identity", "rotate", "--recovery-file", path); r.code != 0 {
		t.Fatalf("the old recovery file no longer rotates the hub: %q", r.stderr)
	}
	if fileOf(path+".new") != nil {
		t.Error("the .new recovery file was left")
	}
}

// The recovery file rotate is given is checked before the passphrase is
// asked: missing, not a recovery file, or another hub's is refused with its
// sentence, exit 1, and nothing is changed.
func TestHubRecoveryFileRefusals(t *testing.T) {
	rd := recDir(t)
	dir := hubDir(t)
	path := filepath.Join(rd, "hub.anetrec")
	setUp(t, dir, path, passA)
	other := filepath.Join(rd, "other.anetrec")
	setUp(t, hubDir(t), other, passA)
	garbage := filepath.Join(rd, "garbage.anetrec")
	if err := os.WriteFile(garbage, []byte("anet-recovery v1\nnot a recovery file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(rd, "missing.anetrec")
	snap := snapshotDir(t, dir)
	for _, lang := range []string{"en", "zh"} {
		for _, tc := range []struct{ file, key string }{
			{missing, "hub_identity.recovery_file_missing"},
			{garbage, "hub_identity.recovery_file_invalid"},
			{other, "hub_identity.recovery_wrong_identity"},
		} {
			term := typing(passA)
			expectErr(t, idCLI(t, lang, term, "-data", dir, "identity", "rotate", "--recovery-file", tc.file), 1,
				sentenceOf(lang, tc.key, map[string]string{"path": tc.file}))
			if len(term.prompts) != 0 {
				t.Errorf("%s %s: the passphrase was asked", lang, tc.key)
			}
		}
	}
	if snapshotDir(t, dir) != snap || fileOf(missing) != nil {
		t.Error("a refused recovery file changed something")
	}
}
