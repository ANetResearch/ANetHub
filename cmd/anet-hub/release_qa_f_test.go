package main

// Tests for the operator command line: what the flags promise, and what
// they do with a value that is present but empty.

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// An empty value for a flag that names what to act on is a mistake, most
// often an unset shell variable, and must not be read as "the flag was
// not given" — that reading starts a hub on the -data directory instead
// of reporting that nothing was named.
func TestAModeFlagGivenAnEmptyValueIsRefused(t *testing.T) {
	for _, args := range [][]string{
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
		{"a mode flag with a real value", []string{"-clear", "did:anet:peer", "-amount", "5"}},
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
