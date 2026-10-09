package admin

// Every sentence the operator plane says to its operator is in this file
// (hub-payment-privacy §5.4a, PAY-O3 to PAY-O5; ux §1.4 L). Other files name
// a row by its key; text_lint_test.go checks the rows against the rules of
// ux §0 (UX-T3), as cmd/anet-hub's text_lint_test.go checks anet-hub's.
//
// A row is one of two kinds:
//
//   - class I, a result: the answer of an operator action (the delete);
//   - class C, a refusal: written to stderr by anet-hub-admin, exit 1, or 2
//     for a usage error (a flag that no longer exists). It says why and what
//     to do next: its next_kind names the kind of next step, and the
//     sentence carries that kind's fixed phrase (or the command, for kind
//     command).
//
// hub_identity_v02 and hub_data_too_new are copies of anet-hub's rows of the
// same key (cmd/anet-hub text.go): the admin plane refuses a hub data
// directory this release does not open with the sentence the hub itself
// gives, word for word, and the lint test holds the two copies equal.
//
// The language follows core G13: LC_ALL, then LC_MESSAGES, then LANG, the
// first one set; Chinese when it starts with "zh", English otherwise.

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// textRow is one sentence in both languages.
type textRow struct {
	// Key names the row. A dotted key is a sentence key of the admin plane;
	// a key without a dot is a registered operator code (registry
	// reasons.hub_operator) whose sentence is anet-hub's.
	Key string
	// Class is "C" (a refusal) or "I" (a result).
	Class string
	// Exit is the exit code that goes with a refusal.
	Exit int
	// NextKind is the kind of next step of a refusal (ux UX-G2).
	NextKind string
	// Next is the command of a command row.
	Next string
	// Zh and En are the sentence, with placeholders in braces.
	Zh string
	En string
}

// The classes and the kinds of next step.
const (
	classC = "C"
	classI = "I"

	nextCommand     = "command"
	nextChangeInput = "change_input"
)

// adminText is every sentence of the operator plane.
var adminText = []textRow{
	// DELETE /admin/api/agents/{aid} (PAY-O3): a delete is revoking the
	// admission and deregistering, as anet-hub admissions revoke is; on a
	// hub open to sign-ups the AID can come back through the gates.
	{Key: "admin.deleted", Class: classI,
		Zh: "已撤销 {aid} 的准入并注销它；余额 {n} credits 仍记在账上。要恢复，运行 anet-hub admit {aid}，对方的 anet 下次重新注册时就会回来。",
		En: "Revoked the admission of {aid} and deregistered it; its {n} credits stay on the ledger. To undo, run anet-hub admit {aid}; it comes back the next time its anet registers."},
	{Key: "admin.deleted.open", Class: classI,
		Zh: "已撤销 {aid} 的准入并注销它；余额 {n} credits 仍记在账上。本 hub 开放注册，它仍可以重新注册：删除不等于封禁。",
		En: "Revoked the admission of {aid} and deregistered it; its {n} credits stay on the ledger. This hub is open, so it can register again: deleting is not a ban."},

	// anet-hub-admin: the flags of the two paths that wrote old key
	// histories back into the registry (PAY-O4).
	{Key: "admin.flag_removed.restore", Class: classC, Exit: 2, NextKind: nextCommand, Next: "anet-hub restore",
		Zh: "--restore-agents-from 已删除：它会把旧的密钥历史写回注册表；要从备份恢复，请运行 anet-hub restore <备份目录>。",
		En: "--restore-agents-from was removed because it wrote old key histories back into the registry; to restore from a backup, run anet-hub restore <backup-dir>."},
	{Key: "admin.flag_removed.prune", Class: classC, Exit: 2, NextKind: nextCommand, Next: "anet-hub admissions revoke",
		Zh: "--keep-only-agents 已删除；要删除 agent，请在运营面删除，或运行 anet-hub admissions revoke <AID>。",
		En: "--keep-only-agents was removed; to remove an agent, delete it in the admin console or run anet-hub admissions revoke <AID>."},

	// anet-hub-admin: an admin.db of an earlier release (§3.4a). It is
	// refused, not converted.
	{Key: "admin.db_too_old", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "admin.db 来自 0.3.0 之前的版本，运营面没有启动；请换一个空的 --data 目录后重启。",
		En: "admin.db was written by a version before 0.3.0, so the admin console did not start; use an empty --data directory and restart."},

	// anet-hub-admin: a hub data directory this release does not open (core
	// CORE-V4). anet-hub's own sentences, copied.
	{Key: "hub_identity_v02", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "这是 0.2 的 hub 数据（身份文件或数据库），0.3.0 不迁移旧数据；请把 hub 数据目录移走后重试（会生成新身份）。",
		En: "This hub data (identity file or database) is from 0.2, and 0.3.0 does not migrate old data; move the hub data directory away and try again to create a new identity."},
	{Key: "hub_data_too_new", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "这个 hub 数据目录由更新版本的 anet-hub 写入，本版本打不开；请升级 anet-hub 后重试（不要删除这个目录）。",
		En: "This hub data directory was written by a newer anet-hub, which this version cannot open; upgrade anet-hub and try again (do not delete the directory)."},
}

// textLang is the language of the sentences.
type textLang int

const (
	langEN textLang = iota
	langZH
)

// adminLanguage picks the language by core G13.
func adminLanguage() textLang {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			if strings.HasPrefix(v, "zh") {
				return langZH
			}
			return langEN
		}
	}
	return langEN
}

// textRowFor finds a row; a key with no row is a bug of this package.
func textRowFor(key string) textRow {
	for _, r := range adminText {
		if r.Key == key {
			return r
		}
	}
	panic(fmt.Sprintf("admin: no sentence %q in text.go", key))
}

// render is the sentence of key in lang with args put in.
func render(key string, lang textLang, args map[string]string) string {
	r := textRowFor(key)
	t := r.En
	if lang == langZH {
		t = r.Zh
	}
	return fill(t, args)
}

// fill puts args into the placeholders of t. A placeholder without a value
// is written as "—", never as its name.
func fill(t string, args map[string]string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(t, '{')
		if i < 0 {
			b.WriteString(t)
			return b.String()
		}
		j := strings.IndexByte(t[i:], '}')
		if j < 0 {
			b.WriteString(t)
			return b.String()
		}
		b.WriteString(t[:i])
		if v, ok := args[t[i+1:i+j]]; ok && v != "" {
			b.WriteString(v)
		} else {
			b.WriteString("—")
		}
		t = t[i+j+1:]
	}
}

// Sentence is the sentence of key in the operator's language (core G13),
// with args put into its placeholders.
func Sentence(key string, args map[string]string) string {
	return render(key, adminLanguage(), args)
}

// Say writes the sentence of key on w, one line, and returns the exit code
// that goes with it (0 for a result).
func Say(w io.Writer, key string, args map[string]string) int {
	fmt.Fprintln(w, Sentence(key, args))
	return textRowFor(key).Exit
}
