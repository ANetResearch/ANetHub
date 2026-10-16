package main

// The hub identity subcommands (KEL §4.2 H-30 to H-33, §5.2; core G12):
//
//	anet-hub identity status [--recovery-file F]
//	anet-hub identity setup-recovery [--recovery-file F]
//	anet-hub identity rotate [--new-recovery] [--emergency] [--recovery-file F]
//
// The hub identity (hubid) is a hub's KEL, toad 0. Its icp commits a hot
// key that the hub's data directory holds until setup-recovery reveals it
// in the first rotation, committing the next key to a recovery seed (C-32,
// H-31): from then on no next key of the hub is in its data directory. The
// seed is kept in a recovery file outside it, sealed under a passphrase
// typed in a terminal (C-34), by default ~/.anet-recovery/<the AID's last 12
// characters>.anetrec, the same place anet keeps an identity's. Each later
// rotation reveals the key the seed derives (C-30); --new-recovery changes
// to a new seed and passphrase, and --emergency does as well and marks both
// rotations urgent (key 12) and replaces the secrets hubid.EmergencySecrets
// lists (H-33). Changing the seed always rotates twice (D-31a): after one
// rotation the current key would still be the old seed's.
//
// setup-recovery and rotate run while the hub is stopped (H-32): they take
// the data directory's lock the hub holds while it serves, and refuse with
// hub_running when they cannot. The rotation takes effect at the next start;
// peers and nodes pick it up within 10 minutes. A new recovery file is
// written in two phases around the identity file (KEL L-3): the .new file
// first, then the identity, then the rename; a .new left behind by a crash is
// finished or removed by the next of these commands, which compares it with
// the identity's commitment. status only reads.
//
// Every sentence is a row of text.go. The passphrase is read from the
// controlling terminal without echo, never from argv, the environment or
// stdin, and cleared once used (KEL L-1).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// terminal is where a passphrase is typed.
type terminal interface {
	// ReadSecret writes prompt and reads one line without echo.
	ReadSecret(prompt string) ([]byte, error)
	// Say writes one line.
	Say(line string)
	Close() error
}

// errNoTerminal is openTTY's error when the process has no controlling
// terminal.
var errNoTerminal = errors.New("no tty")

// ttyTerminal is the process's controlling terminal.
type ttyTerminal struct{ f *os.File }

// openTTY opens the controlling terminal (/dev/tty), or errNoTerminal.
func openTTY() (terminal, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errNoTerminal
	}
	if !term.IsTerminal(int(f.Fd())) {
		f.Close()
		return nil, errNoTerminal
	}
	return &ttyTerminal{f: f}, nil
}

func (t *ttyTerminal) ReadSecret(prompt string) ([]byte, error) {
	t.f.WriteString(prompt + " ")
	b, err := term.ReadPassword(int(t.f.Fd()))
	t.f.WriteString("\n")
	return b, err
}

func (t *ttyTerminal) Say(line string) { t.f.WriteString(line + "\n") }

func (t *ttyTerminal) Close() error { return t.f.Close() }

// text is the sentence of key in the console's language.
func (c *console) text(key string, args map[string]string) string { return render(key, c.lang, args) }

// identityUse is the usage line of anet-hub identity.
const identityUse = "anet-hub identity status [--recovery-file F] | setup-recovery [--recovery-file F] | " +
	"rotate [--new-recovery] [--emergency] [--recovery-file F]"

func runIdentity(c *console, data string, args []string) int {
	if len(args) == 0 {
		return c.usage(identityUse)
	}
	switch args[0] {
	case "status":
		return runIdentityStatus(c, data, args[1:])
	case "setup-recovery":
		return runSetupRecovery(c, data, args[1:])
	case "rotate":
		return runIdentityRotate(c, data, args[1:])
	}
	return c.usage(identityUse)
}

// refuseIdentity answers an error loading the hub identity: the sentence of
// a 0.2 identity file (hub_identity_v02, exit 1), or the error itself.
func (c *console) refuseIdentity(err error) int {
	if errors.Is(err, hubid.ErrIdentityV02) {
		return c.say("hub_identity_v02", nil)
	}
	return c.fail(err)
}

// lockForIdentity takes the hub data directory's lock for the identity
// operation action, creating the directory when it does not exist yet (the
// first setup-recovery of a new hub). A running hub holds the lock:
// hub_running.
func (c *console) lockForIdentity(dir, action string) (*hubid.DirLock, int) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, c.fail(err)
	}
	lock, err := hubid.Lock(dir)
	if errors.Is(err, hubid.ErrLocked) {
		return nil, c.say("hub_running", map[string]string{"action": action})
	}
	if err != nil {
		return nil, c.fail(err)
	}
	return lock, 0
}

// recoveryPath is where the recovery file of the hub identity aid is: the
// path given, or ~/.anet-recovery/<the AID's last 12 characters>.anetrec.
func recoveryPath(given, aid string) (string, error) {
	if given != "" {
		return filepath.Abs(given)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".anet-recovery", aid[max(len(aid)-12, 0):]+".anetrec"), nil
}

// finishNewRecovery deals with the .new recovery file a crash left beside
// path (KEL L-3): it is renamed over path when the identity commits to what
// it states (the identity file was written after it), and removed
// otherwise (the identity file was not). It needs no passphrase. The
// caller holds the data directory's lock.
func finishNewRecovery(path string, id *hubid.Identity) error {
	b, err := os.ReadFile(path + ".new")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, perr := identity.ParseRecoveryFile(b)
	if perr == nil && info.AID == id.AID && info.Commits.Seq == id.Seq()+1 &&
		bytes.Equal(info.Commits.Digest[:], id.Commitment()) {
		if err := os.Rename(path+".new", path); err != nil {
			return err
		}
		return hubid.SyncDir(filepath.Dir(path))
	}
	return os.Remove(path + ".new")
}

// terminalFor opens the terminal for action, or answers
// hub_identity.tty_required.
func (c *console) terminalFor(action string) (terminal, int) {
	t, err := c.openTerminal()
	if err != nil {
		return nil, c.say("hub_identity.tty_required", map[string]string{"action": action})
	}
	return t, 0
}

// refusePassphrase answers a passphrase identity.CheckPassphrase or
// OpenRecoveryFile refused for itself (C-34), or the error.
func (c *console) refusePassphrase(err error) int {
	switch {
	case errors.Is(err, identity.ErrPassphraseNotUTF8):
		return c.say("hub_passphrase_not_utf8", nil)
	case errors.Is(err, identity.ErrPassphraseTooShort):
		return c.say("hub_passphrase_too_short", nil)
	}
	return c.fail(err)
}

// newPassphrase asks for a new recovery passphrase twice, until both
// entries are the same. A passphrase that is too short or not UTF-8 is
// refused at once (exit 1) and nothing is written (C-34).
func (c *console) newPassphrase(t terminal) ([]byte, int) {
	for {
		p, err := t.ReadSecret(c.text("hub_identity.prompt.new_passphrase", nil))
		if err != nil {
			return nil, c.fail(err)
		}
		if err := identity.CheckPassphrase(p); err != nil {
			clear(p)
			return nil, c.refusePassphrase(err)
		}
		again, err := t.ReadSecret(c.text("hub_identity.prompt.again", nil))
		if err != nil {
			clear(p)
			return nil, c.fail(err)
		}
		same := bytes.Equal(p, again)
		clear(again)
		if same {
			return p, 0
		}
		clear(p)
		t.Say(c.text("hub_identity.prompt.mismatch", nil))
	}
}

// sealRecovery is the text of the recovery file of rs for the hub identity
// aid, committing commit, sealed under passphrase, with the note.
func (c *console) sealRecovery(rs [32]byte, aid string, commit identity.Commit, passphrase []byte) ([]byte, error) {
	b, err := identity.SealRecoveryFile(rs, aid, "", commit, passphrase)
	if err != nil {
		return nil, err
	}
	return identity.WithRecoveryNote(b, render("hub_identity.recovery_file_note", langZH, nil),
		render("hub_identity.recovery_file_note", langEN, nil))
}

// newSeed is a fresh recovery seed.
func newSeed() ([32]byte, error) {
	var rs [32]byte
	_, err := rand.Read(rs[:])
	return rs, err
}

// commitOf is the commitment rs makes for the key the event at seq reveals.
func commitOf(rs [32]byte, aid string, seq uint64) (identity.Commit, error) {
	d, err := identity.NextDigest(rs, aid, seq)
	return identity.Commit{Seq: seq, Digest: d}, err
}

// rotateOnce rotates the hub identity id of the data directory dir once:
// it reveals revealed (nil: the icp's hot key) and commits next, urgently
// when emergency. With newFile, the new recovery file at path, it is
// written in two phases around the identity file (KEL L-3): path.new
// first, then the identity file, then path.new renamed over path.
func rotateOnce(dir string, id *hubid.Identity, revealed ed25519.PrivateKey, next []byte, emergency bool,
	path string, newFile []byte) error {
	if newFile != nil {
		if err := hubid.WriteFileAtomic(path+".new", newFile, 0o600); err != nil {
			return err
		}
	}
	if err := id.Rotate(revealed, next, emergency, uint64(time.Now().UnixMilli())); err != nil {
		if newFile != nil {
			os.Remove(path + ".new")
		}
		return err
	}
	if err := id.Save(dir); err != nil {
		return err // path.new stays; the next command removes it
	}
	if newFile == nil {
		return nil
	}
	if err := os.Rename(path+".new", path); err != nil {
		return err
	}
	return hubid.SyncDir(filepath.Dir(path))
}

// ---- status ----

// runIdentityStatus prints what the hub identity of the data directory is,
// one line per value, tab-separated (data an operator checks, like
// anet-hub supply): its AID, its key number, whether its recovery
// passphrase is set and, when it is, where its recovery file is looked for.
// Until it is set, the sentence the hub says at every start follows. It
// writes nothing and may run beside a running hub.
func runIdentityStatus(c *console, data string, args []string) int {
	fs, dataDir := newSubFlags("identity status", data)
	file := fs.String("recovery-file", "", "the recovery file of this hub")
	if pos, err := parseArgs(fs, args); err != nil || len(pos) != 0 {
		return c.usage(identityUse)
	}
	if err := hubid.CheckFile(*dataDir); err != nil {
		return c.refuseIdentity(err)
	}
	if !hubid.Exists(*dataDir) {
		return c.say("data.missing", map[string]string{"path": *dataDir})
	}
	id, err := hubid.Load(*dataDir)
	if err != nil {
		return c.refuseIdentity(err)
	}
	line := func(fields ...string) { c.out.Write([]byte(strings.Join(fields, "\t") + "\n")) }
	line("aid", id.AID)
	line("key_seq", strconv.FormatUint(id.Seq(), 10))
	if !id.RecoverySet() {
		line("recovery", "unset")
		fmt.Fprintln(c.out, c.text("hub_recovery_setup_required", nil))
		return 0
	}
	line("recovery", "set")
	path, err := recoveryPath(*file, id.AID)
	if err != nil {
		return c.fail(err)
	}
	present := "present"
	if _, err := os.Stat(path); err != nil {
		present = "missing"
	}
	line("recovery_file", path, present)
	return 0
}

// ---- setup-recovery ----

// runSetupRecovery sets the hub's recovery passphrase (KEL H-31, C-32): a
// new recovery seed, sealed under it in a new recovery file, and the hub
// identity's first rotation, which reveals the icp's hot key and commits
// the seed's key for seq 2. A data directory without a hub identity gets
// one first (a new hub sets this up before its first start); it is written
// only once the passphrase is accepted, so a refusal leaves none behind.
func runSetupRecovery(c *console, data string, args []string) int {
	const action = "setup-recovery"
	fs, dataDir := newSubFlags("identity "+action, data)
	file := fs.String("recovery-file", "", "where to write the recovery file (default ~/.anet-recovery/)")
	if pos, err := parseArgs(fs, args); err != nil || len(pos) != 0 {
		return c.usage(identityUse)
	}
	dir := *dataDir
	lock, code := c.lockForIdentity(dir, action)
	if lock == nil {
		return code
	}
	defer lock.Release()
	if err := hubid.CheckFile(dir); err != nil {
		return c.refuseIdentity(err)
	}
	var id *hubid.Identity
	if hubid.Exists(dir) {
		loaded, err := hubid.Load(dir)
		if err != nil {
			return c.refuseIdentity(err)
		}
		if loaded.RecoverySet() {
			// A setup that stopped after the identity file was written
			// leaves its recovery file as .new; finish it.
			path, err := recoveryPath(*file, loaded.AID)
			if err != nil {
				return c.fail(err)
			}
			if err := finishNewRecovery(path, loaded); err != nil {
				return c.fail(err)
			}
			return c.say("hub_identity.recovery_already", nil)
		}
		id = loaded
	}
	if *file != "" {
		p, err := filepath.Abs(*file)
		if err != nil {
			return c.fail(err)
		}
		if _, err := os.Stat(p); err == nil {
			return c.say("hub_identity.recovery_file_exists", map[string]string{"path": p})
		}
	}
	t, code := c.terminalFor(action)
	if t == nil {
		return code
	}
	defer t.Close()
	newHub := id == nil
	if newHub {
		var err error
		if id, err = hubid.Incept(); err != nil {
			return c.fail(err)
		}
	}
	path, err := recoveryPath(*file, id.AID)
	if err != nil {
		return c.fail(err)
	}
	if err := finishNewRecovery(path, id); err != nil {
		return c.fail(err)
	}
	if _, err := os.Stat(path); err == nil {
		return c.say("hub_identity.recovery_file_exists", map[string]string{"path": path})
	}
	pass, code := c.newPassphrase(t)
	if pass == nil {
		return code
	}
	defer clear(pass)
	if newHub {
		// The new hub's identity is kept from here on: written before the
		// recovery file, so that a .new a crash leaves below is one the
		// next run can judge against it (finishNewRecovery).
		if err := id.Save(dir); err != nil {
			return c.fail(err)
		}
	}
	rs, err := newSeed()
	if err != nil {
		return c.fail(err)
	}
	defer clear(rs[:])
	commit, err := commitOf(rs, id.AID, 2) // C-31: the first rot (seq 1) commits the key of seq 2
	if err != nil {
		return c.fail(err)
	}
	file2, err := c.sealRecovery(rs, id.AID, commit, pass)
	if err != nil {
		return c.fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return c.fail(err)
	}
	from := id.Seq()
	if err := rotateOnce(dir, id, nil, commit.Digest[:], false, path, file2); err != nil {
		return c.fail(err)
	}
	c.say("hub_identity.recovery_written", map[string]string{"path": path})
	return c.say("hub_identity.rotated", map[string]string{"from": num(int64(from)), "to": num(int64(id.Seq()))})
}

// ---- rotate ----

// runIdentityRotate rotates the hub identity (KEL H-32): once, revealing
// the key the recovery seed derives for the next seq; or, with
// --new-recovery or --emergency, twice, to a new seed under a new
// passphrase (D-31a), the second rotation revealing the new seed's key.
// --emergency marks both rotations urgent (key 12: no grace for the keys
// they retire) and then replaces the secrets of hubid.EmergencySecrets
// (H-33).
func runIdentityRotate(c *console, data string, args []string) int {
	const action = "rotate"
	fs, dataDir := newSubFlags("identity "+action, data)
	file := fs.String("recovery-file", "", "the recovery file of this hub")
	newRecovery := fs.Bool("new-recovery", false, "change to a new recovery seed and passphrase (two rotations)")
	emergency := fs.Bool("emergency", false, "the data directory may have leaked: rotate urgently to a new seed and replace the hub's secrets")
	if pos, err := parseArgs(fs, args); err != nil || len(pos) != 0 {
		return c.usage(identityUse)
	}
	dir := *dataDir
	if !hubid.Exists(dir) {
		return c.say("data.missing", map[string]string{"path": dir})
	}
	lock, code := c.lockForIdentity(dir, action)
	if lock == nil {
		return code
	}
	defer lock.Release()
	id, err := hubid.Load(dir)
	if err != nil {
		return c.refuseIdentity(err)
	}
	if !id.RecoverySet() {
		return c.say("hub_recovery_setup_required", nil)
	}
	path, err := recoveryPath(*file, id.AID)
	if err != nil {
		return c.fail(err)
	}
	if err := finishNewRecovery(path, id); err != nil {
		return c.fail(err)
	}
	t, code := c.terminalFor(action)
	if t == nil {
		return code
	}
	defer t.Close()
	rs, code := c.openRecovery(t, path, id)
	if code != 0 {
		return code
	}
	defer clear(rs[:])
	j := id.Seq() + 1 // the seq of the rotation, whose key rs derives
	revealed, err := identity.RecoverySeed(rs, id.AID, j)
	if err != nil {
		return c.fail(err)
	}
	defer clear(revealed)
	from := id.Seq()
	if !*newRecovery && !*emergency {
		commit, err := commitOf(rs, id.AID, j+1)
		if err != nil {
			return c.fail(err)
		}
		if err := rotateOnce(dir, id, revealed, commit.Digest[:], false, path, nil); err != nil {
			return c.fail(err)
		}
		return c.say("hub_identity.rotated", map[string]string{"from": num(int64(from)), "to": num(int64(id.Seq()))})
	}
	pass, code := c.newPassphrase(t)
	if pass == nil {
		return code
	}
	defer clear(pass)
	rs2, err := newSeed()
	if err != nil {
		return c.fail(err)
	}
	defer clear(rs2[:])
	// First: reveal the old seed's key, commit the new seed's for j+1.
	commit, err := commitOf(rs2, id.AID, j+1)
	if err != nil {
		return c.fail(err)
	}
	newFile, err := c.sealRecovery(rs2, id.AID, commit, pass)
	if err != nil {
		return c.fail(err)
	}
	if err := rotateOnce(dir, id, revealed, commit.Digest[:], *emergency, path, newFile); err != nil {
		return c.fail(err)
	}
	// Second: reveal the new seed's key, so that the current key is the
	// new seed's alone (D-31a).
	revealed2, err := identity.RecoverySeed(rs2, id.AID, j+1)
	if err != nil {
		return c.fail(err)
	}
	defer clear(revealed2)
	if commit, err = commitOf(rs2, id.AID, j+2); err != nil {
		return c.fail(err)
	}
	if newFile, err = c.sealRecovery(rs2, id.AID, commit, pass); err != nil {
		return c.fail(err)
	}
	if err := rotateOnce(dir, id, revealed2, commit.Digest[:], *emergency, path, newFile); err != nil {
		return c.fail(err)
	}
	c.say("hub_identity.rotated", map[string]string{"from": num(int64(from)), "to": num(int64(id.Seq()))})
	c.say("hub_identity.recovery_written", map[string]string{"path": path})
	if !*emergency {
		return 0
	}
	replaced, byOperator, rerr := hubid.RegenerateEmergencySecrets(dir)
	if len(replaced) > 0 {
		c.say("hub_identity.secrets_regenerated", map[string]string{"list": strings.Join(replaced, ", ")})
	}
	if len(byOperator) > 0 {
		c.say("hub_identity.secrets_by_operator", map[string]string{"list": strings.Join(byOperator, ", ")})
	}
	if rerr != nil {
		return c.fail(rerr)
	}
	return 0
}

// openRecovery reads the recovery file at path for the hub identity id
// and opens it with the passphrase typed in t. It refuses (exit 1, nothing
// changed) a file that is missing, not a recovery file, another identity's,
// opened with the wrong passphrase, or one whose seed no longer derives the
// key the identity committed (the seed was changed since it was written).
func (c *console) openRecovery(t terminal, path string, id *hubid.Identity) ([32]byte, int) {
	var none [32]byte
	args := map[string]string{"path": path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return none, c.say("hub_identity.recovery_file_missing", args)
	}
	if err != nil {
		return none, c.fail(err)
	}
	info, err := identity.ParseRecoveryFile(b)
	switch {
	case errors.Is(err, identity.ErrRecoveryWrongIdentity):
		return none, c.say("hub_identity.recovery_wrong_identity", args)
	case err != nil || info.Unprotected:
		return none, c.say("hub_identity.recovery_file_invalid", args)
	case info.AID != id.AID:
		return none, c.say("hub_identity.recovery_wrong_identity", args)
	}
	pass, err := t.ReadSecret(c.text("hub_identity.prompt.passphrase", nil))
	if err != nil {
		return none, c.fail(err)
	}
	defer clear(pass)
	rs, aid, _, _, err := identity.OpenRecoveryFile(b, pass)
	switch {
	case errors.Is(err, identity.ErrPassphraseNotUTF8):
		return none, c.say("hub_passphrase_not_utf8", nil)
	case errors.Is(err, identity.ErrRecoveryPassphrase):
		return none, c.say("hub_identity.passphrase_wrong", nil)
	case errors.Is(err, identity.ErrRecoveryWrongIdentity) || err == nil && aid != id.AID:
		return none, c.say("hub_identity.recovery_wrong_identity", args)
	case err != nil:
		return none, c.say("hub_identity.recovery_file_invalid", args)
	}
	d, err := identity.NextDigest(rs, aid, id.Seq()+1)
	if err != nil || !bytes.Equal(d[:], id.Commitment()) {
		clear(rs[:])
		return none, c.say("hub_identity.recovery_stale", args)
	}
	return rs, 0
}

// ---- the hub's start ----

// startIdentity is what the hub does with its identity before it serves:
// it takes the data directory's lock for as long as it runs (KEL H-32;
// data.in_use when another anet-hub holds it), loads the identity (a 0.2
// identity file is hub_identity_v02), hands it to the store as the signer
// (H-36), drops the witness notices cached under a key it has rotated away
// from (H-35) and, until the recovery passphrase is set, says so in the log
// (H-31).
func startIdentity(c *console, dir string, store interface {
	SetHubKey(identity.Signer)
	ForgetNoticesOfAnotherKey() (int, error)
}, logf func(format string, args ...any)) (*hubid.Identity, *hubid.DirLock, int) {
	lock, err := hubid.Lock(dir)
	if errors.Is(err, hubid.ErrLocked) {
		return nil, nil, c.say("data.in_use", map[string]string{"path": dir})
	}
	if err != nil {
		return nil, nil, c.fail(err)
	}
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		lock.Release()
		return nil, nil, c.refuseIdentity(err)
	}
	store.SetHubKey(id.Ctrl)
	n, err := store.ForgetNoticesOfAnotherKey()
	if err != nil {
		lock.Release()
		return nil, nil, c.fail(err)
	}
	if n > 0 {
		logf("anet-hub: dropped %d witness notices signed before the hub identity rotated", n)
	}
	if !id.RecoverySet() {
		logf("%s", c.text("hub_recovery_setup_required", nil))
	}
	return id, lock, 0
}
