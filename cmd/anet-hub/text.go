package main

// Every sentence anet-hub prints is in this file (hub-payment-privacy
// PAY-U4, core CORE-K24, ux §1.4 L). The other files of this command name a
// row by its key and pass the values of its placeholders; text_lint_test.go
// checks the rows against the rules of ux §0 (UX-T3) and against
// testdata/text.json, their machine-readable copy.
//
// A row is a sentence of one of three kinds:
//
//   - class I, a result: written to stdout, exit 0;
//   - class C, a refusal: written to stderr, exit 1, or 2 for a usage error
//     (a flag that no longer exists). A refusal says why and what to do
//     next: its next_kind names the kind of next step, and its sentence
//     carries that kind's fixed phrase (or the command, for kind command);
//   - class T, a terminal prompt: written to the terminal the passphrase is
//     typed in, never to stdout (anet-hub identity, identity_ops.go).
//
// The language follows core G13: LC_ALL, then LC_MESSAGES, then LANG, the
// first one set; Chinese when it starts with "zh", English otherwise.

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// textRow is one sentence in both languages.
type textRow struct {
	// Key names the row. A key without a dot is an operator code
	// (registry reasons.hub_operator); a dotted key is a sentence key and
	// exists only here (core CORE-K25).
	Key string
	// Class is "C" (a refusal), "I" (a result) or "T" (a terminal prompt).
	Class string
	// Exit is the exit code that goes with the sentence.
	Exit int
	// NextKind is the kind of next step of a refusal (ux UX-G2): command,
	// none_needed, auto, retry_later, change_input, contact, start_over or
	// futile. Empty for a result.
	NextKind string
	// Next is the command of a command row, with placeholders.
	Next string
	// Zh and En are the sentence, with placeholders in braces.
	Zh string
	En string
}

// The classes and the kinds of next step.
const (
	classC = "C"
	classI = "I"
	classT = "T"

	nextCommand     = "command"
	nextChangeInput = "change_input"
)

// hubText is every sentence of anet-hub.
//
//anet:wire reasons.hub_operator
var hubText = []textRow{
	// anet-hub admit (hub-payment-privacy §5.4)
	{Key: "admit.ok", Class: classI,
		Zh: "已准入 {aid}；对方运行 anet hub-register 后会自动完成注册。",
		En: "Admitted {aid}; it finishes joining on its own once it runs anet hub-register."},
	{Key: "admit.ok.grant", Class: classI,
		Zh: "已准入 {aid}；附赠 {n} credits 在它首次注册时到账。",
		En: "Admitted {aid}; the {n}-credit grant is paid when it first registers."},
	{Key: "admit.ok.registered", Class: classI,
		Zh: "{aid} 已在本 hub 注册，已准入并结束其见习期。",
		En: "{aid} is already registered here; it is now admitted and off probation."},
	{Key: "admit.ok.registered_grant", Class: classI,
		Zh: "{aid} 已在本 hub 注册，已准入并结束其见习期；附赠 {n} credits 已到账。",
		En: "{aid} is already registered here; it is now admitted and off probation, and the {n}-credit grant has been paid."},
	{Key: "admit.already_granted", Class: classI,
		Zh: "{aid} 的附赠已经发过，这次不再发放；准入保持不变。",
		En: "{aid} already received its grant, so none is paid this time; the admission stays."},
	{Key: "admit.file_ok", Class: classI,
		Zh: "已准入 {n} 个 AID（来自 {path}），其中 {m} 个已注册。",
		En: "Admitted {n} AIDs from {path}; {m} of them are already registered."},
	{Key: "admit.window_open", Class: classI,
		Zh: "报名窗口已开放到 {time}（至多 {n} 个；需要工作量证明，新账户有 72 小时见习期）。",
		En: "The sign-up window is open until {time} (at most {n}; proof of work required; new accounts are on probation for 72 hours)."},
	{Key: "admit.window_closed", Class: classI,
		Zh: "报名窗口已关闭（这次进来 {n} 个）。",
		En: "The sign-up window is closed ({n} joined through it)."},
	{Key: "admit.window_exists", Class: classC, Exit: 1, NextKind: nextCommand, Next: "anet-hub admit --window off",
		Zh: "已有开放中的报名窗口（到 {time}）；要换一个，请先运行 anet-hub admit --window off。",
		En: "A sign-up window is already open (until {time}); to replace it, run anet-hub admit --window off first."},
	{Key: "admit.bad_aid", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "不是合法的 AID：{value}；请复制对方 anet hub-register 打印的完整 AID 后重试。",
		En: "Not a valid AID: {value}; copy the full AID that anet hub-register printed on their side and try again."},
	{Key: "admit.file_bad_line", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "第 {n} 行不是合法的 AID，整个文件都没有导入；改正后重试。",
		En: "Line {n} is not a valid AID, so nothing from the file was imported; fix it and try again."},
	{Key: "admit.window_too_big", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "报名窗口至多 7 天、至多 10000 个；请缩小后重试。",
		En: "A sign-up window lasts at most 7 days and takes at most 10000; reduce it and try again."},

	// anet-hub admissions, admission
	{Key: "admissions.revoked", Class: classI,
		Zh: "已撤销 {aid} 的准入。",
		En: "Revoked the admission of {aid}."},
	{Key: "admissions.revoked_registered", Class: classI,
		Zh: "已撤销 {aid} 的准入并注销它；余额 {n} credits 仍记在账上。",
		En: "Revoked the admission of {aid} and deregistered it; its {n} credits stay on the ledger."},
	{Key: "admissions.not_listed", Class: classC, Exit: 1, NextKind: nextCommand, Next: "anet-hub admissions",
		Zh: "{aid} 不在准入名单里；用 anet-hub admissions 查看名单。",
		En: "{aid} is not on the admission list; see the list with anet-hub admissions."},
	{Key: "admission.open", Class: classI,
		Zh: "注册方式：开放（工作量证明 + 按网段的每日名额 + 72 小时见习）。",
		En: "Sign-up: open (proof of work, daily quota per network, 72-hour probation)."},
	{Key: "admission.closed", Class: classI,
		Zh: "注册方式：只接受准入名单（anet-hub admit）。",
		En: "Sign-up: admission list only (anet-hub admit)."},

	// anet-hub grant
	{Key: "grant.ok", Class: classI,
		Zh: "已给 {aid} 发放 {n} credits（原因：{name}），余额 {m}。",
		En: "Granted {n} credits to {aid} ({name}); balance now {m}."},
	{Key: "grant.unknown_aid", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "{aid} 没有在本 hub 注册，没有发放；请核对 AID 后重试。",
		En: "{aid} is not registered here, so nothing was granted; check the AID and try again."},

	// anet-hub clear (the subcommand comes with the ledger window work)
	{Key: "clear.ok", Class: classI,
		Zh: "已向 {peer} 结清 {n} credits；本 hub 仍欠它 {m}。",
		En: "Paid {n} credits to {peer}; this hub still owes it {m}."},
	{Key: "clear.over_due", Class: classC, Exit: 1, NextKind: nextCommand, Next: "anet-hub due",
		Zh: "本 hub 只欠 {peer} {m} credits，不能结清 {n}；请用 anet-hub due 查看。",
		En: "This hub owes {peer} only {m} credits, so {n} cannot be cleared; see anet-hub due."},

	// A flag that was an action is a subcommand now (core G12, ux §1.4 L).
	{Key: "hub_flag_removed", Class: classC, Exit: 2, NextKind: nextCommand, Next: "anet-hub {subcommand}",
		Zh: "{flag} 已改为子命令；请运行 anet-hub {subcommand}。",
		En: "{flag} is now a subcommand; run anet-hub {subcommand}."},
	{Key: "hub_flag_removed.fixed", Class: classC, Exit: 2, NextKind: nextChangeInput,
		Zh: "{flag} 已改为固定值；请删去这个参数后重新启动 anet-hub。",
		En: "{flag} is now a fixed value; remove it and start anet-hub again."},
	{Key: "hub_flag_removed.none", Class: classC, Exit: 2, NextKind: nextChangeInput,
		Zh: "{flag} 已删除，没有替代（账目只保留 14 天，不再有需要修复的缺口）；请删去这个参数。",
		En: "{flag} was removed with no replacement (the ledger keeps 14 days, so there is no gap to repair); remove it from the command."},

	// anet-hub quota (sealed-sender SSR-H22): a value below its default,
	// or one that is not a whole number up to 2^31 − 1 (a usage error).
	{Key: "quota_below_default", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "只能调高：{key} 不能低于缺省值 {value}；请改用不小于 {value} 的值。",
		En: "You can only raise it: {key} cannot be below the default {value}; use a value of at least {value}."},
	{Key: "quota_bad_value", Class: classC, Exit: 2, NextKind: nextChangeInput,
		Zh: "{key} 需要一个 1 到 2147483647 之间的整数；请改用这个范围内的整数。",
		En: "{key} needs a whole number from 1 to 2147483647; use a whole number in that range."},

	// anet-hub redemptions
	{Key: "redemptions.summary", Class: classI,
		Zh: "最近 14 天共 {n} 笔兑付，合计 {m} credits；更早的明细已删除，请在 14 天内处理。",
		En: "{n} redemptions in the last 14 days, {m} credits in total; older records are deleted, so handle each within 14 days."},

	// Every subcommand: the data directory holds no hub.
	{Key: "data.missing", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "{path} 里没有 hub 数据，什么都没有改；请用 --data 指向 anet-hub 运行时用的目录后重试。",
		En: "There is no hub data in {path}, so nothing was changed; point --data at the directory anet-hub runs with and try again."},

	// The hub and every subcommand: a data directory this release does not
	// open (core CORE-V4). Data of 0.2 is moved away; data a newer anet-hub
	// wrote is valid, so the next step is to upgrade and nothing is deleted.
	{Key: "hub_identity_v02", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "这是 0.2 的 hub 数据（身份文件或数据库），0.3.0 不迁移旧数据；请把 hub 数据目录移走后重试（会生成新身份）。",
		En: "This hub data (identity file or database) is from 0.2, and 0.3.0 does not migrate old data; move the hub data directory away and try again to create a new identity."},
	{Key: "hub_data_too_new", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "这个 hub 数据目录由更新版本的 anet-hub 写入，本版本打不开；请升级 anet-hub 后重试（不要删除这个目录）。",
		En: "This hub data directory was written by a newer anet-hub, which this version cannot open; upgrade anet-hub and try again (do not delete the directory)."},
	// The hub and anet-hub identity: another anet-hub process holds the
	// data directory (KEL H-32).
	{Key: "data.in_use", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "{path} 正被另一个 anet-hub 进程使用；请等它结束或先停止它后重试。",
		En: "{path} is in use by another anet-hub process; wait for it to finish or stop it, then try again."},

	// The hub identity (KEL §5.2, H-30 to H-33; identity_ops.go). The
	// hub says hub_recovery_setup_required at every start until the
	// recovery passphrase is set, and anet-hub identity status says it too.
	{Key: "hub_recovery_setup_required", Class: classC, Exit: 1, NextKind: nextCommand, Next: "anet-hub identity setup-recovery",
		Zh: "hub 的恢复口令还没设置：数据目录泄露时无法收回 hub 身份；请在 hub 停止时运行 anet-hub identity setup-recovery。",
		En: "The hub's recovery passphrase is not set: if the data directory leaks, the hub identity cannot be taken back; run anet-hub identity setup-recovery while the hub is stopped."},
	{Key: "hub_running", Class: classC, Exit: 1, NextKind: nextCommand, Next: "anet-hub identity {action}",
		Zh: "hub 正在运行；请先停止它，再运行 anet-hub identity {action}。",
		En: "The hub is running; stop it first, then run anet-hub identity {action}."},
	{Key: "hub_passphrase_too_short", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "口令至少要 12 个字符；请换一个更长的口令，例如 4 个以上的随机词。",
		En: "The passphrase needs at least 12 characters; use a longer one, such as four or more random words."},
	{Key: "hub_passphrase_not_utf8", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "口令里有无法识别的字符（终端不是 UTF-8 编码）；请把终端切换为 UTF-8（例如 LANG=C.UTF-8）后重试。",
		En: "The passphrase has characters that cannot be read (the terminal is not using UTF-8); switch the terminal to UTF-8 (for example LANG=C.UTF-8) and try again."},
	{Key: "hub_identity.rotated", Class: classI,
		Zh: "hub 身份已轮换：密钥序号 {from} → {to}；下次启动生效，对等 hub 与节点在 10 分钟内同步。",
		En: "The hub identity was rotated: key number {from} → {to}; it takes effect at the next start, and peers and nodes pick it up within 10 minutes."},
	{Key: "hub_identity.secrets_regenerated", Class: classI,
		Zh: "已重新生成：{list}。",
		En: "Regenerated: {list}."},
	{Key: "hub_identity.secrets_by_operator", Class: classI,
		Zh: "这些不在 hub 数据目录里，anet-hub 换不了，请自己更换：{list}。",
		En: "These are not in the hub data directory, so anet-hub cannot replace them; replace them yourself: {list}."},
	{Key: "hub_identity.recovery_written", Class: classI,
		Zh: "已写入恢复文件 {path}（口令加密）。请另存一份到别处。",
		En: "Recovery file written to {path} (passphrase-encrypted). Keep a copy somewhere else."},
	{Key: "hub_identity.recovery_file_note", Class: classI,
		Zh: "这份文件加上口令可以轮换这个 hub 的身份；单独这份文件无法使用。请另存一份到别处。",
		En: "With the passphrase, this file can rotate this hub's identity; on its own it is useless. Keep a copy somewhere else."},
	{Key: "hub_identity.recovery_already", Class: classI,
		Zh: "hub 的恢复口令已经设置过，不需要操作；要更换口令请运行 anet-hub identity rotate --new-recovery。",
		En: "The hub's recovery passphrase is already set, nothing to do; to change it, run anet-hub identity rotate --new-recovery."},
	{Key: "hub_identity.tty_required", Class: classC, Exit: 1, NextKind: nextCommand, Next: "anet-hub identity {action}",
		Zh: "这一步要在终端里输入恢复口令，什么都没有改；请在终端里运行 anet-hub identity {action}。",
		En: "This step reads the recovery passphrase from a terminal, so nothing was changed; run anet-hub identity {action} in a terminal."},
	{Key: "hub_identity.recovery_file_missing", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "找不到恢复文件 {path}，什么都没有改；请用 --recovery-file 指向 setup-recovery 写下的那份后重试。",
		En: "There is no recovery file at {path}, so nothing was changed; point --recovery-file at the one setup-recovery wrote and try again."},
	{Key: "hub_identity.recovery_file_invalid", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "{path} 不是一份完整的恢复文件，什么都没有改；请改用另存的那份副本后重试。",
		En: "{path} is not a whole recovery file, so nothing was changed; use the copy you kept elsewhere and try again."},
	{Key: "hub_identity.recovery_wrong_identity", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "{path} 不是这个 hub 身份的恢复文件（或者被改过），什么都没有改；请用 --recovery-file 指向本 hub 的恢复文件后重试。",
		En: "{path} is not the recovery file of this hub identity (or it was altered), so nothing was changed; point --recovery-file at this hub's recovery file and try again."},
	{Key: "hub_identity.recovery_stale", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "{path} 已经作废（之后又换过恢复口令），什么都没有改；请改用最近一次写下的恢复文件后重试。",
		En: "{path} no longer works (the recovery passphrase was changed after it was written), so nothing was changed; use the recovery file written last and try again."},
	{Key: "hub_identity.recovery_file_exists", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "{path} 已经有一份恢复文件，没有覆盖，什么都没有改；请用 --recovery-file 指定另一个位置后重试。",
		En: "There is already a recovery file at {path}; it was not overwritten and nothing was changed; choose another place with --recovery-file and try again."},
	{Key: "hub_identity.passphrase_wrong", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "恢复口令不对，什么都没有改；请输入设置这份恢复文件时用的口令后重试。",
		En: "The recovery passphrase is wrong, so nothing was changed; enter the passphrase this recovery file was set with and try again."},
	{Key: "hub_identity.prompt.passphrase", Class: classT,
		Zh: "恢复口令：",
		En: "Recovery passphrase:"},
	{Key: "hub_identity.prompt.new_passphrase", Class: classT,
		Zh: "新的恢复口令：",
		En: "New recovery passphrase:"},
	{Key: "hub_identity.prompt.again", Class: classT,
		Zh: "再输一次：",
		En: "Type it again:"},
	{Key: "hub_identity.prompt.mismatch", Class: classT,
		Zh: "两次输入不一致，请重新输入。",
		En: "The two entries differ; enter it again."},
}

// textLang is the language of the sentences.
type textLang int

const (
	langEN textLang = iota
	langZH
)

// hubLanguage picks the language by core G13.
func hubLanguage() textLang {
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

// textRowFor finds a row.
func textRowFor(key string) (textRow, bool) {
	for _, r := range hubText {
		if r.Key == key {
			return r, true
		}
	}
	return textRow{}, false
}

// render is the sentence of key in lang with args put in. An argument the
// sentence has no placeholder for is ignored; a placeholder without an
// argument is written as "—", never as its name.
func render(key string, lang textLang, args map[string]string) string {
	r, ok := textRowFor(key)
	if !ok {
		panic(fmt.Sprintf("anet-hub: no sentence %q in text.go", key))
	}
	t := r.En
	if lang == langZH {
		t = r.Zh
	}
	return fill(t, args)
}

// fill puts args into the placeholders of t.
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
		name := t[i+1 : i+j]
		if v, ok := args[name]; ok && v != "" {
			b.WriteString(v)
		} else {
			b.WriteString("—")
		}
		t = t[i+j+1:]
	}
}

// console is where a subcommand writes: results to out, refusals to errw.
// The passphrase of anet-hub identity is read from the terminal
// openTerminal opens, never from out's or errw's streams (identity_ops.go).
type console struct {
	out, errw    io.Writer
	lang         textLang
	now          func() time.Time
	openTerminal func() (terminal, error)
}

func newConsole(out, errw io.Writer) *console {
	return &console{out: out, errw: errw, lang: hubLanguage(), now: time.Now, openTerminal: openTTY}
}

// say writes the sentence of key, on stdout for a result and on stderr for
// a refusal, and returns the row's exit code.
func (c *console) say(key string, args map[string]string) int {
	r, ok := textRowFor(key)
	if !ok {
		panic(fmt.Sprintf("anet-hub: no sentence %q in text.go", key))
	}
	w := c.out
	if r.Class == classC {
		w = c.errw
	}
	fmt.Fprintln(w, render(key, c.lang, args))
	return r.Exit
}

// usage writes a usage line (ux UX-G1: usage lines are not sentences of the
// table) and returns the exit code of a usage error.
func (c *console) usage(line string) int {
	fmt.Fprintln(c.errw, "usage: "+line)
	return 2
}

// timeText is a time as ux UX-G8 writes {time}: local MM-DD HH:MM, with the
// year when it is more than a year from now.
func (c *console) timeText(t time.Time) string {
	now := c.now()
	d := t.Sub(now)
	if d < 0 {
		d = -d
	}
	if d > 365*24*time.Hour {
		return t.Local().Format("2006-01-02 15:04")
	}
	return t.Local().Format("01-02 15:04")
}

// num writes an integer placeholder value.
func num[T ~int | ~int64](v T) string { return strconv.FormatInt(int64(v), 10) }
