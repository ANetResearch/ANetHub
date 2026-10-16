package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// quotaLines is what anet-hub quota prints for these values.
func quotaLines(firstContacts, msgs, mib string) string {
	mark := func(v, def string) string {
		if v == def {
			return "(default)"
		}
		return "(default " + def + ")"
	}
	return "--first-contacts-per-min\t" + firstContacts + "\t" + mark(firstContacts, "30") + "\n" +
		"--non-contact-msgs\t" + msgs + "\t" + mark(msgs, "500") + "\n" +
		"--non-contact-mib\t" + mib + "\t" + mark(mib, "64") + "\n"
}

// TestQuotaCommand (sealed-sender SSR-H22): anet-hub quota <AID> shows the
// three values, one per line, marking each as the default or naming the
// default it was raised from; with options it raises only the values given
// and shows the result; a value below its default is refused with
// quota_below_default, exit 1, and changes nothing; a value equal to its
// default puts it back. What it writes is what the running hub reads; that
// the hub process reads it again within a minute is
// aghub.TestQuotaOnlyRises (its clock moves; this process's cannot).
func TestQuotaCommand(t *testing.T) {
	dir := hubDir(t)
	_, aid := newAID(t)
	hub, err := aghub.Open(dir) // the hub, running beside the command
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	if q := hub.QuotaFor(aid); q != aghub.DefaultQuota() {
		t.Fatalf("before: %+v", q)
	}

	expectOut(t, cli(t, "en", "-data", dir, "quota", aid), quotaLines("30", "500", "64"))
	expectOut(t, cli(t, "en", "-data", dir, "quota", aid, "--first-contacts-per-min", "120"), quotaLines("120", "500", "64"))
	expectOut(t, cli(t, "en", "quota", "--non-contact-mib=256", aid, "-data", dir), quotaLines("120", "500", "256"))
	expectOut(t, cli(t, "zh", "-data", dir, "quota", aid), quotaLines("120", "500", "256"))

	// What the hub reads.
	if q, err := hub.QuotaOf(aid); err != nil || q.FirstContactsPerMin != 120 || q.NonContactBytes != 256<<20 || q.NonContactMsgs != 500 {
		t.Fatalf("the hub reads %+v %v", q, err)
	}

	// Below a default: refused, exit 1, nothing changed, in both languages.
	for _, c := range []struct {
		args       []string
		key, value string
	}{
		{[]string{"--first-contacts-per-min", "10"}, "--first-contacts-per-min", "30"},
		{[]string{"--non-contact-msgs", "0"}, "--non-contact-msgs", "500"},
		{[]string{"--non-contact-mib", "-5"}, "--non-contact-mib", "64"},
		{[]string{"--non-contact-msgs", "900", "--non-contact-mib", "63"}, "--non-contact-mib", "64"},
	} {
		for _, lang := range []string{"en", "zh"} {
			r := cli(t, lang, append([]string{"-data", dir, "quota", aid}, c.args...)...)
			expectErr(t, r, 1, sentenceOf(lang, "quota_below_default", map[string]string{"key": c.key, "value": c.value}))
		}
	}
	expectOut(t, cli(t, "en", "-data", dir, "quota", aid), quotaLines("120", "500", "256"))

	// Equal to the default puts the default back.
	expectOut(t, cli(t, "en", "-data", dir, "quota", aid, "--first-contacts-per-min", "30", "--non-contact-mib", "64"),
		quotaLines("30", "500", "64"))
	if q, err := hub.QuotaOf(aid); err != nil || q != aghub.DefaultQuota() {
		t.Fatalf("after the reset the hub reads %+v %v", q, err)
	}

	// Not an AID, the wrong data directory, a malformed line.
	expectErr(t, cli(t, "en", "-data", dir, "quota", "bafyrei"), 1,
		sentenceOf("en", "admit.bad_aid", map[string]string{"value": "bafyrei"}))
	missing := filepath.Join(t.TempDir(), "nothing")
	expectErr(t, cli(t, "en", "-data", missing, "quota", aid), 1,
		sentenceOf("en", "data.missing", map[string]string{"path": missing}))
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Error("quota created a data directory")
	}
	for _, args := range [][]string{
		{"quota"},
		{"quota", aid, aid},
		{"quota", aid, "--quota", "5"},
	} {
		if r := cli(t, "en", append([]string{"-data", dir}, args...)...); r.code != 2 || !strings.HasPrefix(r.stderr, "usage: anet-hub quota") {
			t.Errorf("%v: %+v, want the usage line and exit 2", args, r)
		}
	}
}

// TestRemovedRelayFlagsRefuse (sealed-sender SSR-H20): the flags that tuned
// the per-sender send bucket and the federated key lookup, and the test
// switch that turned the lookup off, are gone. Given in any form, anet-hub
// refuses before it opens anything, with hub_flag_removed.fixed in the
// operator's language, exit 2.
func TestRemovedRelayFlagsRefuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never")
	for _, c := range []struct {
		args []string
		flag string
	}{
		{[]string{"-relay-send-rate", "5"}, "-relay-send-rate"},
		{[]string{"--relay-send-rate=2.5"}, "-relay-send-rate"},
		{[]string{"-relay-send-burst", "300"}, "-relay-send-burst"},
		{[]string{"-keys-lookup-rate", "60"}, "-keys-lookup-rate"},
		{[]string{"-keys-lookup-burst=30"}, "-keys-lookup-burst"},
		{[]string{"-test-no-fed-key-lookup"}, "-test-no-fed-key-lookup"},
		{[]string{"-test-no-fed-key-lookup=false"}, "-test-no-fed-key-lookup"},
		{[]string{"-addr", ":0", "-relay-send-rate", "5", "-relay-send-burst", "1"}, "-relay-send-rate"},
	} {
		for _, lang := range []string{"en", "zh"} {
			r := cli(t, lang, append([]string{"-data", dir}, c.args...)...)
			expectErr(t, r, 2, sentenceOf(lang, "hub_flag_removed.fixed", map[string]string{"flag": c.flag}))
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("a removed flag opened the data directory")
	}
	// The sentence names the flag and says what to do, with no placeholder
	// left.
	got := render("hub_flag_removed.fixed", langEN, map[string]string{"flag": "-relay-send-rate"})
	if got != "-relay-send-rate is now a fixed value; remove it and start anet-hub again." {
		t.Errorf("the English sentence: %q", got)
	}
}

// liveFlags are the flags anet-hub takes as settings. Sealed-sender adds none
// (SSR-H21): its numbers are fixed values, and the one thing an operator
// changes, one recipient's quota, is a subcommand (anet-hub quota). A change
// to this list is a change to what an operator can tune; make it here on
// purpose, and only with a sentence for each removed flag.
var liveFlags = []string{
	"addr", "data", "public-url",
	"register-burst", "register-rate", "relay-mailbox-bytes", "relay-mailbox-messages",
	"relay-max-envelope", "relay-poll-budget", "relay-ttl", "version",
}

// TestNoSealedSenderGlobalFlags (sealed-sender SSR-H21): the flag set of
// anet-hub is exactly liveFlags plus the removed flags, which only refuse;
// none names a sealed-sender setting (sessions, credentials, first contacts,
// strangers, quotas, the directory, revocation, the mailbox key).
func TestNoSealedSenderGlobalFlags(t *testing.T) {
	fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	defineFlags(fs)
	removed := map[string]bool{}
	for _, r := range removedFlags {
		removed[r.name] = true
	}
	var live []string
	fs.VisitAll(func(f *flag.Flag) {
		if !removed[f.Name] {
			live = append(live, f.Name)
		}
	})
	sort.Strings(live)
	want := append([]string(nil), liveFlags...)
	sort.Strings(want)
	if strings.Join(live, " ") != strings.Join(want, " ") {
		t.Errorf("anet-hub's flags are\n  %v\nwant\n  %v", live, want)
	}
	for _, name := range live {
		for _, w := range []string{"session", "cap", "credential", "first-contact", "stranger", "non-contact",
			"quota", "dir", "bucket", "revoke", "revocation", "mbox", "mailbox-key", "send-rate", "send-burst", "lookup"} {
			if strings.Contains(name, w) {
				t.Errorf("-%s looks like a sealed-sender setting; those are fixed values (SSR-H21)", name)
			}
		}
	}
}

// quota_bad_value (ux §1.4 L): a value that is not a whole number, or is
// above 2^31 − 1, is a usage error naming the option, exit 2, in the
// operator's language, and changes nothing; the line says what range the
// value has to be in. A value below its default is still
// quota_below_default (exit 1), and an unknown option the usage line.
func TestQuotaBadValueSentence(t *testing.T) {
	dir := hubDir(t)
	_, aid := newAID(t)
	before := quotaLines("30", "500", "64")
	expectOut(t, cli(t, "en", "-data", dir, "quota", aid), before)
	for _, c := range []struct {
		args []string
		key  string
	}{
		{[]string{"--non-contact-msgs", "many"}, "--non-contact-msgs"},
		{[]string{"--non-contact-msgs", "99999999999"}, "--non-contact-msgs"},
		{[]string{"--first-contacts-per-min", "2147483648"}, "--first-contacts-per-min"},
		{[]string{"--non-contact-mib=1.5"}, "--non-contact-mib"},
		{[]string{"--non-contact-mib", "9223372036854775808"}, "--non-contact-mib"},
		{[]string{"--non-contact-msgs", "900", "--non-contact-mib", "0x10"}, "--non-contact-mib"},
	} {
		for _, lang := range []string{"en", "zh"} {
			r := cli(t, lang, append([]string{"-data", dir, "quota", aid}, c.args...)...)
			expectErr(t, r, 2, sentenceOf(lang, "quota_bad_value", map[string]string{"key": c.key}))
		}
	}
	expectOut(t, cli(t, "en", "-data", dir, "quota", aid), before)
	// The largest value it takes is a raise like any other.
	expectOut(t, cli(t, "en", "-data", dir, "quota", aid, "--non-contact-msgs", "2147483647"),
		quotaLines("30", "2147483647", "64"))
	if got := render("quota_bad_value", langEN, map[string]string{"key": "--non-contact-msgs"}); got !=
		"--non-contact-msgs needs a whole number from 1 to 2147483647; use a whole number in that range." {
		t.Errorf("the English sentence: %q", got)
	}
}
