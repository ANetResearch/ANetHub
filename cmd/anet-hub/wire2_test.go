package main

import (
	"bytes"
	"errors"
	"flag"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
)

// The kernel's relay refusals reach the federation forward handler as
// federation's own errors, which it answers with 507 and 400.
func TestStoreDeliveryMapsRelayRefusals(t *testing.T) {
	store, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetRelayQuota(1, 1<<20)
	c, _ := identity.Incept()
	kel, _ := identity.MarshalKEL(c.KEL())
	if err := store.PutAgent(c.AID(), "R", nil, kel); err != nil {
		t.Fatal(err)
	}
	env := func(ct string) []byte {
		b, err := (&seal.SealedEnvelope{V: 1, To: c.AID(), Suite: seal.SuiteX25519,
			KID: bytes.Repeat([]byte{7}, 16), Enc: bytes.Repeat([]byte{9}, 32), CT: []byte(ct)}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	d := storeDelivery{store}
	if _, err := d.Enqueue(c.AID(), []byte("plaintext")); !errors.Is(err, federation.ErrBadEnvelope) {
		t.Errorf("plaintext: %v, want federation.ErrBadEnvelope", err)
	}
	if _, err := d.Enqueue(c.AID(), env("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Enqueue(c.AID(), env("two")); !errors.Is(err, federation.ErrMailboxFull) {
		t.Errorf("over quota: %v, want federation.ErrMailboxFull", err)
	}
}

// Every §3.7 relay limit is a flag, each flag sets its own field, and with
// no flags the limits are the design defaults.
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
		"-relay-max-envelope", "101", "-relay-send-rate", "2.5", "-relay-send-burst", "103",
		"-relay-mailbox-messages", "104", "-relay-mailbox-bytes", "105", "-relay-ttl", "106s",
		"-relay-poll-budget", "107", "-register-rate", "108", "-register-burst", "109",
		"-keys-lookup-rate", "110", "-keys-lookup-burst", "111",
	}); err != nil {
		t.Fatal(err)
	}
	want := aghub.Limits{
		MaxEnvelope: 101, SendRate: 2.5, SendBurst: 103, MailboxMessages: 104, MailboxBytes: 105,
		UndeliveredTTL: 106 * time.Second, PollBudget: 107, RegisterPerMinute: 108, RegisterBurst: 109,
		KeysLookupPerMinute: 110, KeysLookupBurst: 111,
	}
	if got := f.limits(); got != want {
		t.Fatalf("limits from flags = %+v, want %+v", got, want)
	}
	if err := want.Validate(); err != nil {
		t.Fatalf("the flag values do not validate: %v", err)
	}
}
