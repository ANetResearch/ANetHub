package aghub_test

import (
	"strings"
	"testing"
)

// The onboarding manual the hub serves is what an agent executes, so its
// Step 0 is pinned (A2A-DESIGN §13.2, [C40]): an installed anet is updated
// with `anet update`, which verifies the release with the key built into
// the binary; curl | sh is for a fresh machine only, and the verified
// alternative (install.sh.sig checked with ssh-keygen against the key
// published outside this host) is written next to it. Guest mode is gone
// and must not be offered.
func TestTheManualInstallsSafelyAndOffersNoGuestMode(t *testing.T) {
	srv := newHub(t)
	code, body := getJSON(t, srv.URL+"/llms.txt")
	if code != 200 {
		t.Fatalf("llms.txt: %d", code)
	}
	page := string(body)
	step0 := section(page, "## Step 0", "## Who you are")
	if step0 == "" {
		t.Fatal("the manual has no Step 0 section")
	}
	// The command itself, on a line of its own in a code block — a mention
	// in prose is not an instruction an agent executes.
	upd := strings.Index(step0, "\nanet update\n")
	curl := strings.Index(step0, "install.sh | sh")
	if upd < 0 || curl < 0 || upd > curl {
		t.Errorf("Step 0 must tell an installed node to run `anet update` before offering curl | sh "+
			"(anet update command at %d, curl | sh at %d)", upd, curl)
	}
	for _, want := range []string{"anet version", "install.sh.sig", "ssh-keygen -Y verify",
		"-n anet-release@agentnetwork.org.cn", "allowed_signers", "fresh machine",
		// anet before 0.2.0 has no update command; the page has to say
		// what to do there rather than leave the agent at an error.
		"has no `update` command"} {
		if !strings.Contains(step0, want) {
			t.Errorf("Step 0 does not contain %q", want)
		}
	}
	// Every curl in Step 0 is https-only, redirects included.
	for _, line := range strings.Split(step0, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "curl ") && !strings.Contains(line, "--proto '=https'") {
			t.Errorf("Step 0 fetches without --proto '=https': %s", line)
		}
	}
	lower := strings.ToLower(page)
	for _, gone := range []string{"{{hub_url}}/chat", "/chat`", "guest_messages", "--guest-messages", "guest quota"} {
		if strings.Contains(lower, gone) {
			t.Errorf("the manual still offers %q", gone)
		}
	}
	if strings.Count(lower, "guest") != 1 {
		t.Errorf("the manual mentions guest %d times; only the sentence stating there is none may",
			strings.Count(lower, "guest"))
	}
	// The hub's view of content is stated as the 0.2.0 target together
	// with what it still sees, not as an unconditional claim.
	if !strings.Contains(page, "target of anet 0.2.0") || !strings.Contains(page, "who sends to whom") {
		t.Error("the manual does not state what the hub can see as the 0.2.0 target with its limits")
	}
	if strings.Contains(page, "the Hub verifies the hashes") {
		t.Error("the manual still says the hub verifies content hashes of a review; it receives no content")
	}
}

// section returns the text from the line starting with from up to the
// line starting with to.
func section(page, from, to string) string {
	i := strings.Index(page, "\n"+from)
	if i < 0 {
		return ""
	}
	rest := page[i+1:]
	if j := strings.Index(rest, "\n"+to); j >= 0 {
		return rest[:j]
	}
	return rest
}

// Outside Step 0 the manual names the commands and tools of A2A-DESIGN
// §12–§13.1 and the completion model of §2/§4.2, and none of the ones they
// replaced (05-hub H10): `anet install --agent` became `anet agents wire`
// (the page said both, a few screens apart), the MCP tools are the §12
// names, and a text task is completed by its provider alone — "when both
// end" described a handshake the daemon no longer has, and the receipt is
// the provider's signature, not both sides'.
func TestTheManualNamesTheCurrentCommands(t *testing.T) {
	srv := newHub(t)
	code, body := getJSON(t, srv.URL+"/llms.txt")
	if code != 200 {
		t.Fatalf("llms.txt: %d", code)
	}
	page := string(body)
	for _, gone := range []string{"anet install --agent", "when both end",
		"once both sides agree", "both sides sign", "BOTH sides sign", "auto-proposes", "accept-end",
		"task_delegate", "agents_find", "task_message", "task_end", "task_results", "task_inbox",
		"credit_balance", "evidence_read"} {
		if strings.Contains(page, gone) {
			t.Errorf("the manual still says %q", gone)
		}
	}
	for _, want := range []string{"anet agents wire", "anet --id <codename> doctor",
		"anet --id <codename> init", "anet peers allow",
		"peers allow|trust", "list_agents", "send_message", "wait_task", "reply_task", "cancel_task",
		"UNVERIFIED", "signs the receipt"} {
		if !strings.Contains(page, want) {
			t.Errorf("the manual does not mention %q", want)
		}
	}
}
