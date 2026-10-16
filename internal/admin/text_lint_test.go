package admin

// The operator sentences of anet-hub-admin (text.go) keep the rules of ux §0 that anet-hub's keep
// (ux UX-T3, UX-T4; hub-payment-privacy §5.4a, PAY-O6):
//
//   - the rows are the five of §5.4a and the two copies of anet-hub's refusals of a data directory,
//     and the copies are anet-hub's rows word for word (cmd/anet-hub/testdata/text.json, which
//     anet-hub's own lint holds equal to its text.go) and registered operator codes;
//   - a refusal declares what to do next and its sentence says it with that kind's fixed phrase, in
//     both languages; a result declares none;
//   - no internal word, no template longer than 120 characters in Chinese or 240 in English
//     (placeholders not counted), full-width punctuation in Chinese outside commands and
//     placeholders, no Chinese in English;
//   - every placeholder is one the admin plane fills, and a missing value never shows as a
//     placeholder.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/ANetResearch/ANetCore/wire"
)

// The rows of §5.4a and the copies.
var wantAdminKeys = []string{
	"admin.deleted", "admin.deleted.open", "admin.flag_removed.restore", "admin.flag_removed.prune",
	"admin.db_too_old", "hub_identity_v02", "hub_data_too_new",
}

func TestAdminTextKeys(t *testing.T) {
	var got []string
	seen := map[string]bool{}
	for _, r := range adminText {
		if seen[r.Key] {
			t.Errorf("%s has two rows", r.Key)
		}
		seen[r.Key] = true
		got = append(got, r.Key)
	}
	want := append([]string(nil), wantAdminKeys...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the rows are %v, want %v", got, want)
	}
}

// hubTextRow is a row of cmd/anet-hub/testdata/text.json.
type hubTextRow struct {
	Key      string `json:"key"`
	Class    string `json:"class"`
	Exit     int    `json:"exit"`
	NextKind string `json:"next_kind,omitempty"`
	Next     string `json:"next,omitempty"`
	Zh       string `json:"zh"`
	En       string `json:"en"`
}

// A key without a dot is a registered operator code, and its row is anet-hub's, word for word: the
// admin plane refuses a hub data directory with the sentence the hub gives for it.
func TestAdminTextCopiesAreTheHubs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "cmd", "anet-hub", "testdata", "text.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Rows []hubTextRow `json:"rows"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	hub := map[string]hubTextRow{}
	for _, r := range f.Rows {
		hub[r.Key] = r
	}
	reg, err := wire.Load()
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, c := range reg.ReasonCodes("hub_operator") {
		registered[c] = true
	}
	copies := 0
	for _, r := range adminText {
		if strings.Contains(r.Key, ".") {
			if !strings.HasPrefix(r.Key, "admin.") {
				t.Errorf("%s: a sentence key of the admin plane starts with admin.", r.Key)
			}
			continue
		}
		copies++
		if !registered[r.Key] {
			t.Errorf("%s is a code (no dot) but not a registered operator code", r.Key)
		}
		h, ok := hub[r.Key]
		if !ok {
			t.Errorf("%s: anet-hub has no such row", r.Key)
			continue
		}
		mine := hubTextRow{Key: r.Key, Class: r.Class, Exit: r.Exit, NextKind: r.NextKind, Next: r.Next, Zh: r.Zh, En: r.En}
		if mine != h {
			t.Errorf("%s differs from anet-hub's row:\n admin %+v\n hub   %+v", r.Key, mine, h)
		}
	}
	if copies != 2 {
		t.Errorf("%d copies of anet-hub's rows, want 2", copies)
	}
}

// adminPlaceholderRe matches a placeholder.
var adminPlaceholderRe = regexp.MustCompile(`\{[a-z_]+\}`)

// adminPlaceholders are the placeholders the admin plane fills, with a sample value.
var adminPlaceholders = map[string]string{
	"{aid}": "bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
	"{n}":   "7",
}

func adminLintLen(s string) int {
	return utf8.RuneCountInString(adminPlaceholderRe.ReplaceAllString(s, ""))
}

// UX-G7: at most 120 characters in Chinese and 240 in English.
func TestAdminTextLength(t *testing.T) {
	for _, r := range adminText {
		if n := adminLintLen(r.Zh); n > 120 {
			t.Errorf("%s: the Chinese template is %d characters, over 120", r.Key, n)
		}
		if n := adminLintLen(r.En); n > 240 {
			t.Errorf("%s: the English template is %d characters, over 240", r.Key, n)
		}
	}
}

// adminForbidden are the internal words of UX-G2, as anet-hub's lint lists them for the operator.
var adminForbidden = []string{"KEL", "KSN", "通告", "notice", "kid", "纪元", "epoch", "HPKE", "信封", "envelope",
	"dack", "会话 MAC", "seal", "首联", "邀请", "invite", "tombstone", "墓碑",
	"看不出是你", "看不出发件人", "cannot tell it is you", "cannot tell who sent"}

func containsAdminWord(s, w string) bool {
	if strings.ContainsFunc(w, func(r rune) bool { return r > unicode.MaxASCII }) {
		return strings.Contains(s, w)
	}
	return regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(w) + `\b`).MatchString(s)
}

// UX-G2: no internal word.
func TestAdminTextUsesNoInternalWord(t *testing.T) {
	for _, r := range adminText {
		for _, s := range []string{r.Zh, r.En} {
			for _, w := range adminForbidden {
				if containsAdminWord(s, w) {
					t.Errorf("%s: uses %q: %s", r.Key, w, s)
				}
			}
		}
	}
}

// adminCommandRe matches the commands and flags a sentence quotes, which keep their own
// punctuation.
var adminCommandRe = regexp.MustCompile(`anet(-hub)? [a-z][a-z-]*( [^；。，（）：]*)?|--[a-z][a-z-]*`)

// UX-G7: a Chinese template uses full-width , ; : ( ) outside placeholders and commands, and ends
// with 。; an English one has no Chinese and ends with a full stop.
func TestAdminTextPunctuation(t *testing.T) {
	for _, r := range adminText {
		zh := adminPlaceholderRe.ReplaceAllString(r.Zh, "")
		zh = adminCommandRe.ReplaceAllString(zh, "")
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

// adminNextPhrases are the fixed phrases of the kinds of next step the rows use (ux UX-G2).
var adminNextPhrases = map[string][2][]string{
	"change_input": {{"后重发", "后重试", "请换", "请改", "改用", "请加", "请减小", "请删"},
		{"send again", "try again", "send it again", "use ", "add ", "remove "}},
}

func hasAdminPhrase(s string, phrases []string, english bool) bool {
	for _, p := range phrases {
		if !english && strings.Contains(s, p) {
			return true
		}
		if english && regexp.MustCompile(`(?i)\b`+regexp.QuoteMeta(p)).MatchString(s) {
			return true
		}
	}
	return false
}

// UX-G2, UX-T3: a refusal (class C) declares a kind of next step and says it in both languages: the
// command for kind command (and only kind command has one), the kind's fixed phrase otherwise. A
// result (class I) declares none and exits 0. A refusal exits 1, or 2 for a usage error.
func TestAdminTextNextStep(t *testing.T) {
	for _, r := range adminText {
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
			for _, s := range []string{r.Zh, r.En} {
				if !strings.Contains(s, r.Next) {
					t.Errorf("%s: the sentence does not carry its command %q: %s", r.Key, r.Next, s)
				}
			}
			continue
		}
		ph, ok := adminNextPhrases[r.NextKind]
		if !ok {
			t.Errorf("%s: next_kind %q has no phrase list here", r.Key, r.NextKind)
			continue
		}
		if !hasAdminPhrase(render(r.Key, langZH, adminSamples()), ph[0], false) {
			t.Errorf("%s: the Chinese sentence has no phrase of %s: %s", r.Key, r.NextKind, r.Zh)
		}
		if !hasAdminPhrase(render(r.Key, langEN, adminSamples()), ph[1], true) {
			t.Errorf("%s: the English sentence has no phrase of %s: %s", r.Key, r.NextKind, r.En)
		}
	}
	// The flags removed with the restore and prune paths are usage errors.
	for _, k := range []string{"admin.flag_removed.restore", "admin.flag_removed.prune"} {
		if r := textRowFor(k); r.Exit != 2 {
			t.Errorf("%s exits %d, want 2", k, r.Exit)
		}
	}
}

func adminSamples() map[string]string {
	out := map[string]string{}
	for p, v := range adminPlaceholders {
		out[strings.Trim(p, "{}")] = v
	}
	return out
}

// UX-T4: every placeholder is one the admin plane fills; the two languages of a row use the same
// ones; with the values in, nothing of a placeholder is left; with a value missing, it shows as "—".
func TestAdminTextPlaceholders(t *testing.T) {
	for _, r := range adminText {
		zh, en := adminPlaceholderRe.FindAllString(r.Zh, -1), adminPlaceholderRe.FindAllString(r.En, -1)
		sort.Strings(zh)
		sort.Strings(en)
		if strings.Join(zh, ",") != strings.Join(en, ",") {
			t.Errorf("%s: the two languages have different placeholders: %v and %v", r.Key, zh, en)
		}
		for _, p := range zh {
			if _, ok := adminPlaceholders[p]; !ok {
				t.Errorf("%s: %s is not a placeholder the admin plane fills", r.Key, p)
			}
		}
		for _, lang := range []textLang{langEN, langZH} {
			if out := render(r.Key, lang, adminSamples()); strings.ContainsAny(out, "{}") {
				t.Errorf("%s: a placeholder is left: %s", r.Key, out)
			}
			if bare := render(r.Key, lang, nil); strings.ContainsAny(bare, "{}") {
				t.Errorf("%s: with no values the sentence shows a placeholder: %s", r.Key, bare)
			}
		}
	}
}

// core G13: LC_ALL, then LC_MESSAGES, then LANG; zh… is Chinese.
func TestAdminLanguage(t *testing.T) {
	for _, c := range []struct {
		all, msgs, lang string
		want            textLang
	}{
		{"", "", "", langEN},
		{"", "", "zh_CN.UTF-8", langZH},
		{"C", "", "zh_CN.UTF-8", langEN},
		{"zh_TW.UTF-8", "", "C", langZH},
		{"", "zh_CN.UTF-8", "en_US.UTF-8", langZH},
		{"", "en_US.UTF-8", "zh_CN.UTF-8", langEN},
	} {
		t.Setenv("LC_ALL", c.all)
		t.Setenv("LC_MESSAGES", c.msgs)
		t.Setenv("LANG", c.lang)
		if got := adminLanguage(); got != c.want {
			t.Errorf("LC_ALL=%q LC_MESSAGES=%q LANG=%q: %v, want %v", c.all, c.msgs, c.lang, got, c.want)
		}
	}
}
