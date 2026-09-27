package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runMainEnv makes the test binary run main() in place of the tests, so
// that a start-up refusal can be observed from outside as the process
// exit it is in production.
const runMainEnv = "ANET_HUB_ADMIN_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// startAdmin runs main() in a child process with ADMIN_TOKEN=token and
// the admin data directory data. The hub data directory holds no hub.db,
// so a start that passes the credential checks stops at opening the hub
// store; nothing listens in either case.
func startAdmin(t *testing.T, token, data string) (exitCode int, output string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-addr", "127.0.0.1:0", "-data", data, "-hub-data", t.TempDir())
	cmd.Env = append(os.Environ(), runMainEnv+"=1", "ADMIN_TOKEN="+token)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("running the admin binary: %v", err)
	}
	return ee.ExitCode(), string(out)
}

// A placeholder credential stops anet-hub-admin before it opens any store
// (A2A-DESIGN §9 row admin; deploy/anet-hub-admin.service ships
// ADMIN_TOKEN=CHANGE_ME). admin.PlaceholderToken decides what a
// placeholder is and is tested in internal/admin; this pins that main
// acts on it. A real token passes the check and fails later, at the
// missing hub.db, which is the control that shows the refusal is the
// credential's.
func TestTheAdminRefusesToStartWithAPlaceholderToken(t *testing.T) {
	for _, tok := range []string{"CHANGE_ME", "changeme", "<your token>", "xxxxxxxx"} {
		data := t.TempDir()
		code, out := startAdmin(t, tok, data)
		if code == 0 || !strings.Contains(out, "ADMIN_TOKEN is a placeholder") {
			t.Errorf("ADMIN_TOKEN=%q: exit %d, output %q; want a non-zero exit naming the placeholder", tok, code, out)
		}
		if _, err := os.Stat(filepath.Join(data, "admin.db")); !os.IsNotExist(err) {
			t.Errorf("ADMIN_TOKEN=%q: admin.db was created (%v); the refusal must come before any store is opened", tok, err)
		}
	}

	data := t.TempDir()
	code, out := startAdmin(t, "k7Qw2mZr9TfLpX4vN3sB", data)
	if code == 0 || strings.Contains(out, "placeholder") || !strings.Contains(out, "hub db") {
		t.Errorf("a real token: exit %d, output %q; want the start to pass the credential checks "+
			"and stop at the missing hub.db", code, out)
	}
	if _, err := os.Stat(filepath.Join(data, "admin.db")); err != nil {
		t.Errorf("a real token: admin.db was not created (%v), so the start did not get past the credential checks", err)
	}
}

// runAdmin runs main() in a child process with the given ADMIN_TOKEN and
// arguments.
func runAdmin(t *testing.T, token string, args ...string) (exitCode int, output string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1", "ADMIN_TOKEN="+token)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("running the admin binary: %v", err)
	}
	return ee.ExitCode(), string(out)
}

// -check-token answers the start-up question without starting: exit 1 for
// a credential the service would refuse, 0 for one it would accept, and
// the value itself is never printed. deploy/deploy-admin.sh runs it on the
// host before restarting the service, so the deployment check and the
// service cannot disagree about what a placeholder is.
func TestTheTokenCheckDecidesLikeTheStart(t *testing.T) {
	for _, tok := range []string{"", "CHANGE_ME", "changeme", "Change Me", "${ADMIN_TOKEN}", "00000000"} {
		code, out := runAdmin(t, tok, "-check-token")
		if code != 1 {
			t.Errorf("-check-token with ADMIN_TOKEN=%q: exit %d (%q), want 1", tok, code, out)
		}
		// The fixed refusal text names CHANGE_ME as an example; what must
		// not appear is the value outside that text.
		if rest := strings.ReplaceAll(out, tokenRefusal(tok), ""); tok != "" && strings.Contains(rest, tok) {
			t.Errorf("-check-token printed the token value %q: %q", tok, out)
		}
	}
	data := t.TempDir()
	for _, tok := range []string{"k7Qw2mZr9TfLpX4vN3sB", "anetpw2077"} {
		// anetpw2077 is a published default: the service warns about it
		// and starts, so the check must let it through as well.
		if code, out := runAdmin(t, tok, "-check-token", "-data", data); code != 0 {
			t.Errorf("-check-token with a token the service accepts: exit %d (%q), want 0", code, out)
		}
	}
	if _, err := os.Stat(filepath.Join(data, "admin.db")); !os.IsNotExist(err) {
		t.Errorf("-check-token opened the admin store (%v); it must only check", err)
	}
}

// deploy-admin.sh checks the host's effective token with the shipped
// binary before it restarts the service. It cannot be run from a test (it
// ssh's into production), so what is pinned is that the check is there,
// that it uses the binary rather than a literal comparison, and that it
// comes before the restart.
func TestTheDeployScriptChecksTheTokenBeforeTheRestart(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "deploy-admin.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	check := strings.Index(s, "/data/projs/anet-hub/bin/anet-hub-admin -check-token")
	restart := strings.Index(s, "systemctl restart anet-hub-admin")
	if check < 0 {
		t.Fatal("deploy-admin.sh does not run anet-hub-admin -check-token on the host")
	}
	if restart < 0 || check > restart {
		t.Errorf("the token check (at %d) must come before the restart (at %d)", check, restart)
	}
	if strings.Contains(s, `"ADMIN_TOKEN=CHANGE_ME" ]`) {
		t.Error("deploy-admin.sh still compares the token with the literal CHANGE_ME")
	}
}
