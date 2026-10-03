package main

// Every sentence anet-hub prints is in this file (hub-payment-privacy
// PAY-U4, core CORE-K24, ux §1.4 L). The other files of this command name a
// row by its key and pass the values of its placeholders; text_lint_test.go
// checks the rows against the rules of ux §0 (UX-T3) and against
// testdata/text.json, their machine-readable copy.
//
// A row is a sentence of one of two kinds:
//
//   - class I, a result: written to stdout, exit 0;
//   - class C, a refusal: written to stderr, exit 1, or 2 for a usage error
//     (a flag that no longer exists). A refusal says why and what to do
//     next: its next_kind names the kind of next step, and its sentence
//     carries that kind's fixed phrase (or the command, for kind command).
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
	// Class is "C" (a refusal) or "I" (a result).
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
	{Key: "hub_flag_removed.none", Class: classC, Exit: 2, NextKind: nextChangeInput,
		Zh: "{flag} 已删除，没有替代（账目只保留 14 天，不再有需要修复的缺口）；请删去这个参数。",
		En: "{flag} was removed with no replacement (the ledger keeps 14 days, so there is no gap to repair); remove it from the command."},

	// anet-hub redemptions
	{Key: "redemptions.summary", Class: classI,
		Zh: "最近 14 天共 {n} 笔兑付，合计 {m} credits；更早的明细已删除，请在 14 天内处理。",
		En: "{n} redemptions in the last 14 days, {m} credits in total; older records are deleted, so handle each within 14 days."},

	// Every subcommand: the data directory holds no hub.
	{Key: "data.missing", Class: classC, Exit: 1, NextKind: nextChangeInput,
		Zh: "{path} 里没有 hub 数据，什么都没有改；请用 --data 指向 anet-hub 运行时用的目录后重试。",
		En: "There is no hub data in {path}, so nothing was changed; point --data at the directory anet-hub runs with and try again."},
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
type console struct {
	out, errw io.Writer
	lang      textLang
	now       func() time.Time
}

func newConsole(out, errw io.Writer) *console {
	return &console{out: out, errw: errw, lang: hubLanguage(), now: time.Now}
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
