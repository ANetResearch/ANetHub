package main

import (
	"flag"
	"testing"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// Every §3.7 relay limit that is still a setting is a flag, each flag sets
// its own field, and with no flags the limits are the design defaults. The
// per-sender send bucket and the federated key lookup's bucket are fixed
// values (sealed-sender SSR-H20): their flags are refused
// (TestRemovedRelayFlagsRefuse) and the limits keep the defaults.
func TestTheRelayLimitFlagsSetTheirOwnLimits(t *testing.T) {
	fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
	f := defineFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if got := f.limits(); got != aghub.DefaultLimits() {
		t.Fatalf("limits without flags = %+v, want the defaults %+v", got, aghub.DefaultLimits())
	}
	fs = flag.NewFlagSet("anet-hub", flag.ContinueOnError)
	f = defineFlags(fs)
	if err := fs.Parse([]string{
		"-relay-max-envelope", "101",
		"-relay-mailbox-messages", "104", "-relay-mailbox-bytes", "105", "-relay-ttl", "106s",
		"-relay-poll-budget", "107", "-register-rate", "108", "-register-burst", "109",
	}); err != nil {
		t.Fatal(err)
	}
	want := aghub.Limits{
		MaxEnvelope: 101, MailboxMessages: 104, MailboxBytes: 105,
		UndeliveredTTL: 106 * time.Second, PollBudget: 107, RegisterPerMinute: 108, RegisterBurst: 109,
	}
	if got := f.limits(); got != want {
		t.Fatalf("limits from flags = %+v, want %+v", got, want)
	}
	if err := want.Validate(); err != nil {
		t.Fatalf("the flag values do not validate: %v", err)
	}
}
