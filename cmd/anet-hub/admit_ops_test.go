package main

// The admission subcommands and the removed action flags (hub-payment-
// privacy PAY-A7, PAY-U1 to PAY-U4; core G12): what each prints is the
// text.go sentence for what happened, on stdout for a result and on
// stderr for a refusal, with exit 0, 1 or 2.

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// hubDir is a data directory a hub has run with.
func hubDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	s, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := hubid.LoadOrIncept(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// cli runs anet-hub with args as main would, up to serving, in lang ("en"
// or "zh"). served reports that it would have gone on to serve.
type cliResult struct {
	code           int
	served         bool
	stdout, stderr string
}

func cli(t *testing.T, lang string, args ...string) cliResult {
	t.Helper()
	l := "C"
	if lang == "zh" {
		l = "zh_CN.UTF-8"
	}
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", l)
	fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := defineFlags(fs)
	var out, errw bytes.Buffer
	if err := fs.Parse(args); err != nil {
		return cliResult{code: 2, stderr: err.Error()}
	}
	c := newConsole(&out, &errw)
	code, done := beforeServing(f, fs, c)
	return cliResult{code: code, served: !done, stdout: out.String(), stderr: errw.String()}
}

// sentenceOf is the sentence the command must have printed.
func sentenceOf(lang, key string, args map[string]string) string {
	l := langEN
	if lang == "zh" {
		l = langZH
	}
	return render(key, l, args) + "\n"
}

func newAID(t *testing.T) (*identity.Controller, string) {
	t.Helper()
	c, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	return c, c.AID()
}

// registerIn writes an agent row for c in dir, as a registration would.
func registerIn(t *testing.T, dir string, c *identity.Controller) {
	t.Helper()
	s, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	kel, _ := identity.MarshalKEL(c.KEL())
	if err := s.PutAgent(c.AID(), "n", nil, kel); err != nil {
		t.Fatal(err)
	}
}

// expectOut checks a result: exit 0, the sentence on stdout, nothing on
// stderr.
func expectOut(t *testing.T, r cliResult, want string) {
	t.Helper()
	if r.code != 0 || r.stdout != want || r.stderr != "" {
		t.Errorf("got exit %d, stdout %q, stderr %q; want exit 0, stdout %q", r.code, r.stdout, r.stderr, want)
	}
}

// expectErr checks a refusal: the exit code, the sentence on stderr,
// nothing on stdout.
func expectErr(t *testing.T, r cliResult, code int, want string) {
	t.Helper()
	if r.code != code || r.stderr != want || r.stdout != "" {
		t.Errorf("got exit %d, stdout %q, stderr %q; want exit %d, stderr %q", r.code, r.stdout, r.stderr, code, want)
	}
}

func TestAdmitTheSubcommand(t *testing.T) {
	for _, lang := range []string{"en", "zh"} {
		t.Run(lang, func(t *testing.T) {
			dir := hubDir(t)
			c, aid := newAID(t)
			expectOut(t, cli(t, lang, "-data", dir, "admit", aid), sentenceOf(lang, "admit.ok", map[string]string{"aid": aid}))
			// The flags may come after the AID, and --data inside.
			_, aid2 := newAID(t)
			expectOut(t, cli(t, lang, "admit", aid2, "--grant", "25", "--label", "bench", "--data", dir),
				sentenceOf(lang, "admit.ok.grant", map[string]string{"aid": aid2, "n": "25"}))
			registerIn(t, dir, c)
			expectOut(t, cli(t, lang, "-data", dir, "admit", aid, "--grant", "5"),
				sentenceOf(lang, "admit.ok.registered_grant", map[string]string{"aid": aid, "n": "5"}))
			expectOut(t, cli(t, lang, "-data", dir, "admit", aid, "--grant", "5"),
				sentenceOf(lang, "admit.already_granted", map[string]string{"aid": aid}))
			expectOut(t, cli(t, lang, "-data", dir, "admit", aid),
				sentenceOf(lang, "admit.ok.registered", map[string]string{"aid": aid}))
			// A prefix is not an AID.
			expectErr(t, cli(t, lang, "-data", dir, "admit", aid[:20]), 1,
				sentenceOf(lang, "admit.bad_aid", map[string]string{"value": aid[:20]}))
			expectErr(t, cli(t, lang, "-data", dir, "admit"), 2, "usage: "+admitUsage+"\n")
			expectErr(t, cli(t, lang, "-data", dir, "admit", aid, "--grant", "-1"), 2, "usage: "+admitUsage+"\n")
		})
	}
}

// admitUsage is runAdmit's usage line.
const admitUsage = "anet-hub admit <AID> [--grant N] [--label L] | --file F [--grant N] | --window <duration> --max N [--label L] | --window off"

func TestAdmitFromAFile(t *testing.T) {
	dir := hubDir(t)
	c, a := newAID(t)
	_, b := newAID(t)
	registerIn(t, dir, c)
	good := filepath.Join(t.TempDir(), "aids.txt")
	if err := os.WriteFile(good, []byte("# bench\n"+a+"\n\n"+b+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectOut(t, cli(t, "en", "-data", dir, "admit", "--file", good),
		sentenceOf("en", "admit.file_ok", map[string]string{"n": "2", "m": "1", "path": good}))
	bad := filepath.Join(t.TempDir(), "bad.txt")
	if err := os.WriteFile(bad, []byte(a+"\n"+b+"\nbafy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectErr(t, cli(t, "zh", "-data", dir, "admit", "--file", bad), 1,
		sentenceOf("zh", "admit.file_bad_line", map[string]string{"n": "3"}))
}

func TestAdmitAWindow(t *testing.T) {
	dir := hubDir(t)
	r := cli(t, "en", "-data", dir, "admit", "--window", "2h", "--max", "50", "--label", "campus")
	if r.code != 0 || !strings.HasPrefix(r.stdout, "The sign-up window is open until ") || !strings.Contains(r.stdout, "(at most 50;") {
		t.Fatalf("opening a window: %+v", r)
	}
	until := time.Now().Add(2 * time.Hour)
	c := newConsole(io.Discard, io.Discard)
	// The time is the window's end, local, minutes (it may tick over).
	if !strings.Contains(r.stdout, c.timeText(until)) && !strings.Contains(r.stdout, c.timeText(until.Add(-time.Minute))) {
		t.Errorf("the window's end is not %s: %s", c.timeText(until), r.stdout)
	}
	r = cli(t, "en", "-data", dir, "admit", "--window", "1h", "--max", "5")
	if r.code != 1 || r.stdout != "" || !strings.HasSuffix(r.stderr, "run anet-hub admit --window off first.\n") {
		t.Errorf("a second window: %+v", r)
	}
	expectOut(t, cli(t, "en", "-data", dir, "admit", "--window", "off"),
		sentenceOf("en", "admit.window_closed", map[string]string{"n": "0"}))
	// A window is counted in days up to its limit, so days are taken too.
	r = cli(t, "en", "-data", dir, "admit", "--window", "7d", "--max", "5")
	if r.code != 0 || !strings.HasPrefix(r.stdout, "The sign-up window is open until ") {
		t.Fatalf("a window of 7d: %+v", r)
	}
	expectOut(t, cli(t, "en", "-data", dir, "admit", "--window", "off"),
		sentenceOf("en", "admit.window_closed", map[string]string{"n": "0"}))
	for in, want := range map[string]time.Duration{"3d": 72 * time.Hour, "1d12h": 36 * time.Hour, "90m": 90 * time.Minute} {
		if d, err := parseWindowLength(in); err != nil || d != want {
			t.Errorf("parseWindowLength(%q) = %v, %v; want %v", in, d, err, want)
		}
	}
	for _, in := range []string{"d", "-1d", "+1d", "1d-1h", "1dd", "x1d", "1.5d"} {
		if d, err := parseWindowLength(in); err == nil {
			t.Errorf("parseWindowLength(%q) = %v, want an error", in, d)
		}
	}
	for _, args := range [][]string{{"--window", "169h", "--max", "5"}, {"--window", "8d", "--max", "5"}, {"--window", "1h", "--max", "10001"}, {"--window", "1h", "--max", "0"}} {
		expectErr(t, cli(t, "en", append([]string{"-data", dir, "admit"}, args...)...), 1,
			sentenceOf("en", "admit.window_too_big", nil))
	}
	for _, args := range [][]string{{"--window", "1h"}, {"--window", "soon", "--max", "5"}, {"--window", "off", "--max", "5"}} {
		if r := cli(t, "en", append([]string{"-data", dir, "admit"}, args...)...); r.code != 2 || !strings.HasPrefix(r.stderr, "usage: ") {
			t.Errorf("admit %v: %+v, want a usage line and exit 2", args, r)
		}
	}
}

func TestAdmissionsAndRevoke(t *testing.T) {
	dir := hubDir(t)
	c, a := newAID(t)
	_, b := newAID(t)
	_, stranger := newAID(t)
	cli(t, "en", "-data", dir, "admit", a, "--grant", "3", "--label", "first")
	cli(t, "en", "-data", dir, "admit", b)
	registerIn(t, dir, c)

	r := cli(t, "en", "-data", dir, "admissions")
	want := sentenceOf("en", "admission.closed", nil) + a + "\t3\tfirst\n" + b + "\t\t\n"
	if r.code != 0 || r.stdout != want {
		t.Errorf("admissions:\n%s\nwant\n%s", r.stdout, want)
	}
	r = cli(t, "en", "-data", dir, "admissions", "--json")
	var js aghub.Admissions
	if err := json.Unmarshal([]byte(r.stdout), &js); err != nil || js.Mode != "closed" || len(js.Admitted) != 2 || js.Window != nil {
		t.Errorf("admissions --json: %s %v", r.stdout, err)
	}

	expectOut(t, cli(t, "en", "-data", dir, "admissions", "revoke", b),
		sentenceOf("en", "admissions.revoked", map[string]string{"aid": b}))
	expectOut(t, cli(t, "zh", "-data", dir, "admissions", "revoke", a),
		sentenceOf("zh", "admissions.revoked_registered", map[string]string{"aid": a, "n": "0"}))
	expectErr(t, cli(t, "en", "-data", dir, "admissions", "revoke", stranger), 1,
		sentenceOf("en", "admissions.not_listed", map[string]string{"aid": stranger}))
	expectErr(t, cli(t, "en", "-data", dir, "admissions", "revoke", "nope"), 1,
		sentenceOf("en", "admit.bad_aid", map[string]string{"value": "nope"}))
	if r := cli(t, "en", "-data", dir, "admissions", "revoke"); r.code != 2 {
		t.Errorf("revoke without an AID: %+v", r)
	}
	s, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.KnowsAgent(a) {
		t.Error("the revoked AID is still registered")
	}
}

func TestAdmissionMode(t *testing.T) {
	dir := hubDir(t)
	expectOut(t, cli(t, "en", "-data", dir, "admission"), sentenceOf("en", "admission.closed", nil))
	expectOut(t, cli(t, "zh", "-data", dir, "admission", "open"), sentenceOf("zh", "admission.open", nil))
	expectOut(t, cli(t, "en", "-data", dir, "admission"), sentenceOf("en", "admission.open", nil))
	expectOut(t, cli(t, "en", "-data", dir, "admission", "closed"), sentenceOf("en", "admission.closed", nil))
	if r := cli(t, "en", "-data", dir, "admission", "ajar"); r.code != 2 {
		t.Errorf("an unknown mode: %+v", r)
	}
}

func TestGrantTheSubcommand(t *testing.T) {
	dir := hubDir(t)
	c, aid := newAID(t)
	_, stranger := newAID(t)
	registerIn(t, dir, c)
	expectOut(t, cli(t, "en", "-data", dir, "grant", aid, "--amount", "40"),
		sentenceOf("en", "grant.ok", map[string]string{"aid": aid, "n": "40", "name": "operator grant", "m": "40"}))
	expectOut(t, cli(t, "zh", "-data", dir, "grant", aid, "--amount", "2", "--reason", "pilot"),
		sentenceOf("zh", "grant.ok", map[string]string{"aid": aid, "n": "2", "name": "pilot", "m": "42"}))
	expectErr(t, cli(t, "en", "-data", dir, "grant", stranger, "--amount", "1"), 1,
		sentenceOf("en", "grant.unknown_aid", map[string]string{"aid": stranger}))
	for _, args := range [][]string{{"grant", aid}, {"grant", aid, "--amount", "0"}, {"grant", "--amount", "5"}} {
		if r := cli(t, "en", append([]string{"-data", dir}, args...)...); r.code != 2 || !strings.HasPrefix(r.stderr, "usage: ") {
			t.Errorf("%v: %+v", args, r)
		}
	}
}

// A subcommand pointed at a directory no hub ran with changes nothing and
// says so: it does not create an empty hub there and report success.
func TestASubcommandNeedsTheHubsData(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "elsewhere")
	_, aid := newAID(t)
	for _, args := range [][]string{{"admit", aid}, {"admissions"}, {"admission", "open"}, {"grant", aid, "--amount", "1"}} {
		expectErr(t, cli(t, "en", append([]string{"-data", dir}, args...)...), 1,
			sentenceOf("en", "data.missing", map[string]string{"path": dir}))
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the subcommands created %s", dir)
	}
	if r := cli(t, "en", "-data", dir, "ajar"); r.code != 2 || !strings.HasPrefix(r.stderr, "usage: ") {
		t.Errorf("an unknown subcommand: %+v", r)
	}
}

// The action flags of 0.2 are refused with the subcommand to run (core G12,
// PAY-U3, ux §1.4 L hub_flag_removed): exit 2, before anything is opened.
func TestARemovedFlagNamesItsSubcommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never")
	for _, c := range []struct {
		args []string
		flag string
		sub  string
	}{
		{[]string{"-grant", "x", "-amount", "5"}, "-grant", "grant"},
		{[]string{"-grant", ""}, "-grant", "grant"},
		{[]string{"--invite-required", "true"}, "-invite-required", "admission"},
		{[]string{"-invite-new", "-label", "bench"}, "-invite-new", "admit"},
		{[]string{"-invite-uses=3"}, "-invite-uses", "admit"},
		{[]string{"-invite-days", "2"}, "-invite-days", "admit"},
		{[]string{"-invite-list"}, "-invite-list", "admissions"},
		{[]string{"-invite-revoke", "abc"}, "-invite-revoke", "admissions revoke"},
		{[]string{"-label", "x"}, "-label", "admit"},
	} {
		for _, lang := range []string{"en", "zh"} {
			r := cli(t, lang, append([]string{"-data", dir}, c.args...)...)
			expectErr(t, r, 2, sentenceOf(lang, "hub_flag_removed", map[string]string{"flag": c.flag, "subcommand": c.sub}))
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("a removed flag opened the data directory")
	}
	// Serving is still anet-hub [flags].
	if r := cli(t, "en", "-addr", ":0", "-data", dir); !r.served || r.code != 0 || r.stderr != "" {
		t.Errorf("anet-hub with serving flags did not go on to serve: %+v", r)
	}
}
