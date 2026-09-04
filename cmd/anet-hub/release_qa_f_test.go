package main

// Tests for the operator command line: what the flags promise, and what
// they do with a value that is present but empty.

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// The -invite-required help said "(empty = report the current setting)".
// It cannot report anything: flag.Parse cannot distinguish
// -invite-required "" from the flag being absent, and the dispatch in
// main branches on the value being non-empty, so an empty one fell
// through to the normal startup path and started a hub. The flag that
// does report the setting is -invite-list, and the help now names it.
func TestInviteRequiredHelpDoesNotPromiseThatAnEmptyValueReports(t *testing.T) {
	fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
	defineFlags(fs)

	fl := fs.Lookup("invite-required")
	if fl == nil {
		t.Fatal("-invite-required is not defined")
	}
	if strings.Contains(fl.Usage, "empty") {
		t.Errorf("-invite-required still tells an operator what an empty value does, "+
			"which is a thing the dispatch cannot see: %q", fl.Usage)
	}
	if !strings.Contains(fl.Usage, "-invite-list") {
		t.Errorf("-invite-required does not name the flag that reports the setting: %q", fl.Usage)
	}
	// The help is only worth anything if what it names exists.
	if fs.Lookup("invite-list") == nil {
		t.Error("the help points at -invite-list, which is not defined")
	}
}

// An empty value for a flag that names what to act on is a mistake, most
// often an unset shell variable, and must not be read as "the flag was
// not given" — that reading starts a hub on the -data directory instead
// of reporting that nothing was named.
func TestAModeFlagGivenAnEmptyValueIsRefused(t *testing.T) {
	for _, args := range [][]string{
		{"-grant", ""},
		{"-invite-required", ""},
		{"-invite-revoke", ""},
		{"-clear", ""},
		{"-repair-ledger", ""},
	} {
		fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		defineFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		err := refuseEmptyModeFlags(fs)
		if err == nil {
			t.Errorf("%v was accepted; with the variable unset this starts a hub "+
				"rather than reporting that nothing was named", args)
			continue
		}
		if !strings.Contains(err.Error(), args[0]) {
			t.Errorf("%v: the message does not name the flag: %v", args, err)
		}
	}
}

// The guard must not fire on a flag that was not given, or on the flags
// whose empty value is a legitimate "not applicable" — otherwise every
// ordinary `anet-hub` start would fail.
func TestTheEmptyValueGuardLeavesOrdinaryStartupsAlone(t *testing.T) {
	cases := []struct {
		what string
		args []string
	}{
		{"a plain start with no flags", nil},
		{"a plain start with the flags a service unit passes", []string{"-addr", ":8088", "-data", "/srv/hub"}},
		// -payee and -peer-endpoint are optional by design: a discharge
		// arranged out of band corresponds to no hub_due row and has
		// nowhere to be delivered.
		{"a discharge with the optional halves left empty",
			[]string{"-clear", "did:anet:peer", "-amount", "5", "-payee", "", "-peer-endpoint", ""}},
		{"a mode flag with a real value", []string{"-grant", "did:anet:someone", "-amount", "5"}},
		// An empty label is caught where it means something, by
		// runInviteOp, and with a message about the listing rather than
		// about shell variables.
		{"an empty -label", []string{"-invite-new", "-label", ""}},
	}
	for _, c := range cases {
		fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		defineFlags(fs)
		if err := fs.Parse(c.args); err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if err := refuseEmptyModeFlags(fs); err != nil {
			t.Errorf("%s was refused: %v", c.what, err)
		}
	}
}

// Revoking an invite twice is something an operator does — from a
// runbook, or from a second terminal after being told a code leaked. The
// second run must not exit non-zero claiming the id does not exist, while
// -invite-list goes on showing that same id as revoked.
func TestRevokingAnInviteTwiceFromTheCommandLineIsIdempotent(t *testing.T) {
	store, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, v, err := store.NewInvite("leaked", 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	first := captureStdout(t, func() {
		if err := revokeOp(store, v.ID); err != nil {
			t.Fatalf("first revoke: %v", err)
		}
	})
	if !strings.Contains(first, "revoked") {
		t.Errorf("the first revoke said %q", first)
	}

	second := captureStdout(t, func() {
		// A non-nil error here is what main turns into a non-zero exit.
		if err := revokeOp(store, v.ID); err != nil {
			t.Fatalf("re-revoking an invite that is already revoked failed: %v", err)
		}
	})
	if !strings.Contains(second, "already revoked") {
		t.Errorf("the second revoke did not say the invite was already revoked: %q", second)
	}

	// The idempotency must not swallow a mistyped id. If it did, the two
	// cases would be indistinguishable again, in the other direction.
	if err := revokeOp(store, "no-such-id"); err == nil {
		t.Error("revoking an id that does not exist reported success")
	}
}

// revokeOp is the -invite-revoke path through runInviteOp, with the
// arguments the other modes take left at the values main passes when they
// were not given.
func revokeOp(store *aghub.Store, id string) error {
	return runInviteOp(store, "", false, "", 1, 0, false, id)
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() {
		os.Stdout = saved
		w.Close()
		r.Close()
	}()
	fn()
	w.Close()
	os.Stdout = saved
	return <-done
}
