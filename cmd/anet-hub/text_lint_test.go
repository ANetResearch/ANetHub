package main

// The operator sentences of anet-hub (text.go) keep the rules of ux §0 that
// the user sentences of anet keep (ux UX-T3, UX-T4; hub-payment-privacy
// PAY-U4, G-PAY-HUBTEXT-1):
//
//   - testdata/text.json is their machine-readable copy, row for row;
//   - every registered operator code (ANetCore wire/registry.json
//     reasons.hub_operator) has a row;
//   - a refusal declares what to do next and its sentence says it with that
//     kind's fixed phrase, in both languages;
//   - no internal word, no template longer than 120 characters in Chinese or
//     240 in English (placeholders not counted), full-width punctuation in
//     Chinese outside commands and placeholders, no Chinese in English;
//   - every placeholder is one the hub fills, and a missing value never
//     shows as a placeholder;
//   - no other file of this command carries a product sentence.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/ANetResearch/ANetCore/wire"
)

// textFile is the format of testdata/text.json.
type textFile struct {
	Format string        `json:"format"`
	About  string        `json:"about"`
	Rows   []textFileRow `json:"rows"`
}

type textFileRow struct {
	Key      string `json:"key"`
	Class    string `json:"class"`
	Exit     int    `json:"exit"`
	NextKind string `json:"next_kind,omitempty"`
	Next     string `json:"next,omitempty"`
	Zh       string `json:"zh"`
	En       string `json:"en"`
}

const textJSON = "testdata/text.json"

func textRowsAsFile() textFile {
	f := textFile{
		Format: "hub-text/1",
		About: "Every sentence anet-hub prints (cmd/anet-hub/text.go), in both languages, with its class " +
			"(C refusal, I result), exit code and next step. Regenerate with HUBTEXT_UPDATE=1 go test " +
			"-run TestHubTextJSON ./cmd/anet-hub and review the diff.",
	}
	for _, r := range hubText {
		f.Rows = append(f.Rows, textFileRow{Key: r.Key, Class: r.Class, Exit: r.Exit, NextKind: r.NextKind,
			Next: r.Next, Zh: r.Zh, En: r.En})
	}
	return f
}

// G-PAY-HUBTEXT-1: text.json is text.go, row for row.
func TestHubTextJSON(t *testing.T) {
	want := textRowsAsFile()
	if os.Getenv("HUBTEXT_UPDATE") != "" {
		b, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(textJSON, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(textJSON)
	if err != nil {
		t.Fatal(err)
	}
	var got textFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Format != want.Format {
		t.Errorf("%s: format %q, want %q", textJSON, got.Format, want.Format)
	}
	gotRows := map[string]textFileRow{}
	for _, r := range got.Rows {
		if _, dup := gotRows[r.Key]; dup {
			t.Errorf("%s: %s twice", textJSON, r.Key)
		}
		gotRows[r.Key] = r
	}
	for _, r := range want.Rows {
		g, ok := gotRows[r.Key]
		if !ok {
			t.Errorf("%s has no row %s (regenerate with HUBTEXT_UPDATE=1)", textJSON, r.Key)
			continue
		}
		if g != r {
			t.Errorf("%s: row %s differs from text.go:\n json %+v\n code %+v", textJSON, r.Key, g, r)
		}
		delete(gotRows, r.Key)
	}
	for k := range gotRows {
		t.Errorf("%s has a row %s that text.go does not", textJSON, k)
	}
	if len(got.Rows) == len(want.Rows) {
		for i := range got.Rows {
			if got.Rows[i].Key != want.Rows[i].Key {
				t.Errorf("%s: row %d is %s, text.go has %s there", textJSON, i, got.Rows[i].Key, want.Rows[i].Key)
				break
			}
		}
	}
}

// pendingOperatorCodes are registered operator codes whose rows the areas
// that own them add, in the order those work items land. Each goes when its
// row lands; a row present while still listed here fails.
var pendingOperatorCodes = map[string]string{
	"hub_recovery_setup_required": "v030-todo(KEL-7)",
	"hub_running":                 "v030-todo(KEL-7)",
	"hub_identity_v02":            "v030-todo(KEL-7)",
}

// UX-T2 for the L group: every registered operator code has a row, every
// key is unique, and every key without a dot is a registered code.
func TestHubTextCoversTheRegistry(t *testing.T) {
	r, err := wire.Load()
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, row := range hubText {
		if keys[row.Key] {
			t.Errorf("%s has two rows", row.Key)
		}
		keys[row.Key] = true
	}
	registered := map[string]bool{}
	for _, c := range r.ReasonCodes("hub_operator") {
		registered[c] = true
		todo, pending := pendingOperatorCodes[c]
		switch {
		case keys[c] && pending:
			t.Errorf("%s has its row now: drop its %s from pendingOperatorCodes", c, todo)
		case !keys[c] && pending:
			t.Logf("%s: no row yet (%s)", c, todo)
		case !keys[c]:
			t.Errorf("the registered operator code %s has no row in text.go", c)
		}
	}
	for k := range keys {
		if !strings.Contains(k, ".") && !registered[k] {
			t.Errorf("%s is a code (no dot) but not a registered operator code", k)
		}
		if strings.Contains(k, ".") && !registered[k[:strings.Index(k, ".")]] && !sentenceKeyGroups[k[:strings.Index(k, ".")]] {
			t.Errorf("%s: a sentence key's group is a registered code or one of %v", k, sortedSet(sentenceKeyGroups))
		}
	}
}

// sentenceKeyGroups are the dotted keys' groups that are not codes: the
// subcommands' result and refusal sentences (core CORE-K25).
var sentenceKeyGroups = map[string]bool{
	"admit": true, "admissions": true, "admission": true, "grant": true, "clear": true,
	"redemptions": true, "data": true,
}

func sortedSet(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// placeholderRe matches a placeholder.
var placeholderRe = regexp.MustCompile(`\{[a-z_]+\}`)

// hubPlaceholders are the placeholders the hub fills (ux UX-G8 and the
// operator rows' own: {flag}, {subcommand}, and {key}, the option of anet-hub
// quota a value belongs to).
var hubPlaceholders = map[string]bool{
	"{aid}": true, "{peer}": true, "{n}": true, "{m}": true, "{time}": true, "{path}": true,
	"{value}": true, "{name}": true, "{flag}": true, "{subcommand}": true, "{key}": true,
}

// placeholderValues are sample values of each placeholder, for the checks
// that look at a sentence with its values in.
var placeholderValues = map[string][]string{
	"{aid}":        {"bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"},
	"{peer}":       {"bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"},
	"{n}":          {"7"},
	"{m}":          {"3"},
	"{time}":       {"10-04 14:05"},
	"{path}":       {"/var/lib/anet-hub"},
	"{value}":      {"bafyrei"},
	"{name}":       {"operator grant"},
	"{flag}":       {"-grant", "-relay-send-rate"},
	"{subcommand}": subcommandValues(),
	"{key}":        {"--first-contacts-per-min", "--non-contact-mib"},
}

// subcommandValues are the subcommands a removed flag can name.
func subcommandValues() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range removedFlags {
		if r.fixed {
			continue
		}
		if !seen[r.subcommand] {
			seen[r.subcommand] = true
			out = append(out, r.subcommand)
		}
	}
	sort.Strings(out)
	return out
}

// lintLen is a template's length as UX-G7 counts it: placeholders do not
// count.
func lintLen(t string) int { return utf8.RuneCountInString(placeholderRe.ReplaceAllString(t, "")) }

// UX-G7: at most 120 characters in Chinese and 240 in English.
func TestHubTextLength(t *testing.T) {
	for _, r := range hubText {
		if n := lintLen(r.Zh); n > 120 {
			t.Errorf("%s: the Chinese template is %d characters, over 120", r.Key, n)
		}
		if n := lintLen(r.En); n > 240 {
			t.Errorf("%s: the English template is %d characters, over 240", r.Key, n)
		}
	}
}

// forbidden are the internal words of UX-G2. "grant" is not among them for
// the operator: it is the name of the operator's own subcommand and flag
// (anet-hub grant, admit --grant), not the delivery credential the word
// means in anet's sentences.
var forbidden = []string{"KEL", "KSN", "通告", "notice", "kid", "纪元", "epoch", "HPKE", "信封", "envelope",
	"dack", "会话 MAC", "seal", "首联", "邀请", "invite",
	"看不出是你", "看不出发件人", "cannot tell it is you", "cannot tell who sent"}

func containsWord(s, w string) bool {
	if strings.ContainsFunc(w, func(r rune) bool { return r > unicode.MaxASCII }) {
		return strings.Contains(s, w)
	}
	return regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(w) + `\b`).MatchString(s)
}

// UX-G2: no internal word, no unconditional anonymity promise. Invites are
// gone too: an operator sentence never sends anyone looking for one.
func TestHubTextUsesNoInternalWord(t *testing.T) {
	for _, r := range hubText {
		for _, s := range []string{r.Zh, r.En} {
			for _, w := range forbidden {
				if containsWord(s, w) {
					t.Errorf("%s: uses %q: %s", r.Key, w, s)
				}
			}
		}
	}
}

// commandRe matches the commands a sentence quotes, which keep their own
// punctuation.
var commandRe = regexp.MustCompile(`anet(-hub)? [a-z][a-z-]*( [^；。，（）]*)?`)

// UX-G7: a Chinese template uses full-width , ; : ( ) outside placeholders
// and commands, and ends with 。; an English one has no Chinese.
func TestHubTextPunctuation(t *testing.T) {
	for _, r := range hubText {
		zh := placeholderRe.ReplaceAllString(r.Zh, "")
		zh = commandRe.ReplaceAllString(zh, "")
		if i := strings.IndexAny(zh, ",;:()"); i >= 0 {
			t.Errorf("%s: half-width %q in Chinese: %s", r.Key, zh[i:i+1], r.Zh)
		}
		if !strings.HasSuffix(r.Zh, "。") {
			t.Errorf("%s: a Chinese sentence ends with 。: %s", r.Key, r.Zh)
		}
		for _, c := range r.En {
			if unicode.Is(unicode.Han, c) || strings.ContainsRune("，；：（）。", c) {
				t.Errorf("%s: %q in English: %s", r.Key, c, r.En)
				break
			}
		}
		if !strings.HasSuffix(r.En, ".") {
			t.Errorf("%s: an English sentence ends with a full stop: %s", r.Key, r.En)
		}
	}
}

// nextPhrases are the fixed phrases of each kind of next step (ux UX-G2).
var nextPhrases = map[string][2][]string{
	"none_needed":  {{"不需要操作"}, {"nothing to do"}},
	"auto":         {{"会自动"}, {"on its own"}},
	"retry_later":  {{"后再发", "后再试", "后重试", "后重发"}, {"again in", "again later", "again when"}},
	"change_input": {{"后重发", "后重试", "请换", "请改", "改用", "请加", "请减小", "请删"}, {"send again", "try again", "send it again", "use ", "add ", "remove "}},
	"contact":      {{"联系", "问对方", "请对方", "发给"}, {"contact", "ask "}},
	"start_over":   {{"新建任务", "重新发起"}, {"start a new task", "start the task again", "start it again", "start them again"}},
	"futile":       {{"重试无用"}, {"retrying will not help"}},
}

func hasPhrase(s string, phrases []string, english bool) bool {
	for _, p := range phrases {
		if !english {
			if strings.Contains(s, p) {
				return true
			}
			continue
		}
		if regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(p)).MatchString(s) {
			return true
		}
	}
	return false
}

// expandings is t with every combination of the sample values of the
// placeholders it holds.
func expandings(t string) []string {
	out := []string{t}
	for _, ph := range placeholderRe.FindAllString(t, -1) {
		vals := placeholderValues[ph]
		if len(vals) == 0 {
			continue
		}
		var next []string
		for _, s := range out {
			for _, v := range vals {
				next = append(next, strings.ReplaceAll(s, ph, v))
			}
		}
		out = next
	}
	return out
}

// UX-G2, UX-T3: a refusal (class C) declares a kind of next step and its
// sentence carries that kind's phrase in both languages; for kind command
// the sentence carries the command (with its placeholders filled the same
// way), and only kind command has one. A result (class I) declares none.
// Exit codes: a result 0, a refusal 1, a usage error 2.
func TestHubTextNextStep(t *testing.T) {
	for _, r := range hubText {
		switch r.Class {
		case classI:
			if r.NextKind != "" || r.Next != "" || r.Exit != 0 {
				t.Errorf("%s: a result has no next step and exits 0 (%q %q %d)", r.Key, r.NextKind, r.Next, r.Exit)
			}
			continue
		case classC:
		default:
			t.Errorf("%s: class %q is neither C nor I", r.Key, r.Class)
			continue
		}
		if r.Exit != 1 && r.Exit != 2 {
			t.Errorf("%s: a refusal exits 1, or 2 for a usage error; it says %d", r.Key, r.Exit)
		}
		if (r.NextKind == nextCommand) != (r.Next != "") {
			t.Errorf("%s: next_kind command if and only if there is a command (%q, %q)", r.Key, r.NextKind, r.Next)
		}
		if r.NextKind == nextCommand {
			for _, lang := range []string{r.Zh, r.En} {
				if !strings.Contains(lang, r.Next) && !strings.Contains(lang, "{next}") {
					t.Errorf("%s: the sentence does not carry its command %q: %s", r.Key, r.Next, lang)
				}
			}
			continue
		}
		ph, ok := nextPhrases[r.NextKind]
		if !ok {
			t.Errorf("%s: next_kind %q is not one of ux UX-G2's", r.Key, r.NextKind)
			continue
		}
		for _, zh := range expandings(r.Zh) {
			if !hasPhrase(zh, ph[0], false) {
				t.Errorf("%s: the Chinese sentence has no phrase of %s: %s", r.Key, r.NextKind, zh)
			}
		}
		for _, en := range expandings(r.En) {
			if !hasPhrase(en, ph[1], true) {
				t.Errorf("%s: the English sentence has no phrase of %s: %s", r.Key, r.NextKind, en)
			}
		}
	}
}

// UX-T4: every placeholder is one the hub fills; the two languages of a row
// use the same ones; with the values in, nothing of a placeholder is left;
// with a value missing, it shows as "—" and never as its name.
func TestHubTextPlaceholders(t *testing.T) {
	for _, r := range hubText {
		zh, en := placeholderRe.FindAllString(r.Zh, -1), placeholderRe.FindAllString(r.En, -1)
		sort.Strings(zh)
		sort.Strings(en)
		if strings.Join(zh, ",") != strings.Join(en, ",") {
			t.Errorf("%s: the two languages have different placeholders: %v and %v", r.Key, zh, en)
		}
		for _, p := range append(zh, placeholderRe.FindAllString(r.Next, -1)...) {
			if !hubPlaceholders[p] {
				t.Errorf("%s: %s is not a placeholder the hub fills", r.Key, p)
			}
		}
		args := map[string]string{}
		for p, vals := range placeholderValues {
			args[strings.Trim(p, "{}")] = vals[0]
		}
		for _, lang := range []textLang{langEN, langZH} {
			out := render(r.Key, lang, args)
			if strings.ContainsAny(out, "{}") {
				t.Errorf("%s: a placeholder is left: %s", r.Key, out)
			}
			bare := render(r.Key, lang, nil)
			if strings.ContainsAny(bare, "{}") || strings.Contains(bare, "()") || strings.Contains(bare, "（）") {
				t.Errorf("%s: with no values the sentence shows a placeholder or empty brackets: %s", r.Key, bare)
			}
		}
	}
}

// core G13: LC_ALL, then LC_MESSAGES, then LANG; zh… is Chinese.
func TestHubLanguage(t *testing.T) {
	for _, c := range []struct {
		all, msgs, lang string
		want            textLang
	}{
		{"", "", "", langEN},
		{"", "", "zh_CN.UTF-8", langZH},
		{"", "", "C", langEN},
		{"C", "", "zh_CN.UTF-8", langEN},
		{"zh_TW.UTF-8", "", "C", langZH},
		{"", "zh_CN.UTF-8", "en_US.UTF-8", langZH},
		{"", "en_US.UTF-8", "zh_CN.UTF-8", langEN},
	} {
		t.Setenv("LC_ALL", c.all)
		t.Setenv("LC_MESSAGES", c.msgs)
		t.Setenv("LANG", c.lang)
		if got := hubLanguage(); got != c.want {
			t.Errorf("LC_ALL=%q LC_MESSAGES=%q LANG=%q: %v, want %v", c.all, c.msgs, c.lang, got, c.want)
		}
	}
}

// sentenceRe matches a string literal that reads as prose: three words in a
// row.
var sentenceRe = regexp.MustCompile(`[A-Za-z]+[ ,;:]+[A-Za-z]+[ ,;:]+[A-Za-z]+`)

// printers are the calls whose literal arguments a person reads.
var printers = map[string]bool{
	"fmt.Print": true, "fmt.Printf": true, "fmt.Println": true,
	"fmt.Fprint": true, "fmt.Fprintf": true, "fmt.Fprintln": true,
	"fmt.Errorf": true, "fmt.Sprintf": true, "errors.New": true,
}

// sentencesOwedElsewhere are the functions of this command that still print
// their own sentences, each with the work item that moves them into
// text.go. A function listed here that no longer prints one fails the test.
var sentencesOwedElsewhere = map[string]string{
	"clearOwed":            "v030-todo(PAY-4)",
	"repairLedger":         "v030-todo(PAY-4)",
	"refuseEmptyModeFlags": "v030-todo(PAY-4)",
	"versionLine":          "", // the -version line is a version, not a sentence
}

// G-PAY-HUBTEXT-1: text.go is the only file of cmd/anet-hub with product
// sentences. Elsewhere a string literal carries no Chinese, and none that
// reads as prose is printed or made into an error, outside usage lines
// ("usage: …", ux UX-G1) and the functions in sentencesOwedElsewhere.
func TestNoSentenceOutsideTextGo(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	owed := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || name == "text.go" {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			fname := ""
			if fn != nil {
				fname = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					s, _ := strconv.Unquote(bl.Value)
					if strings.ContainsFunc(s, func(r rune) bool { return unicode.Is(unicode.Han, r) }) {
						t.Errorf("%s: Chinese outside text.go: %q", fset.Position(bl.Pos()), s)
					}
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || !printers[pkg.Name+"."+sel.Sel.Name] {
					return true
				}
				for _, a := range call.Args {
					ast.Inspect(a, func(m ast.Node) bool {
						bl, ok := m.(*ast.BasicLit)
						if !ok || bl.Kind != token.STRING {
							return true
						}
						s, _ := strconv.Unquote(bl.Value)
						if strings.HasPrefix(s, "usage: ") || !sentenceRe.MatchString(s) {
							return true
						}
						if _, ok := sentencesOwedElsewhere[fname]; ok {
							owed[fname] = true
							return true
						}
						t.Errorf("%s: a sentence outside text.go (in %s): %q", fset.Position(bl.Pos()), fname, s)
						return true
					})
				}
				return true
			})
		}
	}
	for fn, todo := range sentencesOwedElsewhere {
		if todo != "" && !owed[fn] {
			t.Errorf("%s prints no sentence of its own any more: drop it (%s) from sentencesOwedElsewhere", fn, todo)
		}
	}
}
