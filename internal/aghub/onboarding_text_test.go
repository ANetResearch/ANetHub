package aghub_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// advertisedAnetVerbs are the top-level anet commands (ANet cmd/anet
// main.go) an onboarding page may tell somebody to type. A literal list for
// the reason TestTheJoinPageNamesAgentsThatExist gives: ANetHub does not
// depend on ANet, and this is the boundary the check is about. The older
// spellings anet still accepts only to explain what replaced them
// (`install`, `accept`, `accept-end`) are left out on purpose: a page that
// names one sends a newcomer to an error or to the v0.1 model.
var advertisedAnetVerbs = map[string]bool{
	"daemon": true, "up": true, "stop": true, "down": true, "id": true, "version": true, "mcp": true,
	"verify": true, "logs": true, "agents": true, "update": true, "init": true, "doctor": true,
	"audit": true, "help": true, "status": true, "hub-register": true, "p2p-advertise": true,
	"hub-leave": true, "peers": true, "inbound": true, "pay": true, "payments": true,
	"autoreply": true, "profile": true, "console": true, "find": true, "delegate": true, "inbox": true,
	"thread": true, "message": true, "pull": true, "end": true, "results": true,
	"x402-authorize": true, "reconcile": true, "audit-hub": true, "redeem": true, "balance": true,
	"visibility": true, "evidence": true, "review": true,
}

// anetCommand matches a command an onboarding text gives: `anet`, an
// optional `--id <name>`, and the verb — at a line start, after a quote,
// brace or space, or after a `\n` escape inside a JS string literal.
var anetCommand = regexp.MustCompile(`(?m)(?:^|\\n|[\s"'` + "`" + `{(])anet (?:--id \S+ )?([a-z][a-z0-9-]*)`)

// The join page's copy-paste blocks name only commands anet has. It once
// told every newcomer to run `anet whoami`, which anet never had, and to
// expect a did:key identity, which anet does not use.
func TestTheJoinPageNamesOnlyCommandsThatExist(t *testing.T) {
	raw, err := os.ReadFile("../../webui/src/components/JoinSection.tsx")
	if err != nil {
		t.Skipf("join page not present: %v", err)
	}
	page := string(raw)
	seen := 0
	for _, m := range anetCommand.FindAllStringSubmatch(page, -1) {
		seen++
		if !advertisedAnetVerbs[m[1]] {
			t.Errorf("the join page tells a newcomer to run `anet %s`, which anet does not have "+
				"(or keeps only as an older name)", m[1])
		}
	}
	if seen == 0 {
		t.Fatal("found no anet command on the join page: the pattern no longer matches it")
	}
	if strings.Contains(page, "did:key") {
		t.Error("the join page describes the identity as did:key; an anet AID is a KEL-derived CID")
	}
}

// The manual the hub serves describes anet >= 0.2.0, which it requires:
// its code blocks name commands anet has, and the task ends the v0.2 way
// (the provider completes; a requester's end asks it to). The v0.1
// two-sided end handshake, and an exec work dir that defaults to the data
// dir (v0.2 refuses one inside it), are gone.
func TestTheManualDescribesTheV02Node(t *testing.T) {
	srv := newHub(t)
	code, body := getJSON(t, srv.URL+"/llms.txt")
	if code != 200 {
		t.Fatalf("llms.txt: %d", code)
	}
	page := string(body)
	inCode, seen := false, 0
	for _, line := range strings.Split(page, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inCode = !inCode
			continue
		}
		if !inCode {
			continue
		}
		for _, m := range anetCommand.FindAllStringSubmatch(trimmed, -1) {
			seen++
			if !advertisedAnetVerbs[m[1]] {
				t.Errorf("the manual's code tells an agent to run `anet %s`: %s", m[1], trimmed)
			}
		}
	}
	if seen == 0 {
		t.Fatal("found no anet command in the manual's code blocks: the pattern no longer matches it")
	}
	lower := strings.ToLower(page)
	for _, stale := range []string{
		"when both end", "both sides agree", "propose ending", "auto-proposes",
		"defaults to the identity's data dir", "/console?hub=", "anet install --agent",
	} {
		if strings.Contains(lower, stale) {
			t.Errorf("the manual still says %q (anet 0.1)", stale)
		}
	}
	if !strings.Contains(page, "valid for 60 seconds") {
		t.Error("the manual hands the console URL back without saying it is single-use and short-lived")
	}
}
