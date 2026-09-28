package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// F41 (ANet red team): the command the mint output teaches is what the joining machine runs, so it must
// not put the invite in anet's arguments (readable by every local user) — and the agent that often runs
// it for the operator executes the whole command as a shell's argument, prefix included, so the output
// also gives the agent's road: a private file and --token-file.
func TestMintedInviteIsNotTaughtOnACommandLine(t *testing.T) {
	store, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	out := captureStdout(t, func() {
		if err := runInviteOp(store, "", true, "bench", 1, 0, false, ""); err != nil {
			t.Fatal(err)
		}
	})
	tok := regexp.MustCompile(`anetinv_[A-Za-z0-9_-]+`).FindString(out)
	if tok == "" {
		t.Fatalf("no invite in the output:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "hub-register") && strings.Contains(line, tok) && !strings.Contains(line, "ANET_INVITE="+tok) {
			t.Fatalf("the invite is taught as an argument: %q", line)
		}
		if strings.Contains(line, "--token "+tok) || strings.Contains(line, "--token="+tok) {
			t.Fatalf("the invite is taught as --token: %q", line)
		}
	}
	if !strings.Contains(out, "--token-file") || !strings.Contains(out, "agent") {
		t.Fatalf("the output does not give an agent the file road:\n%s", out)
	}
}
