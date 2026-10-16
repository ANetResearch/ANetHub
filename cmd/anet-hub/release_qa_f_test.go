package main

// Tests for the operator command line: what the flags promise, and what
// they do with a value that is present but empty.

import (
	"path/filepath"
	"testing"
)

// An empty value for a flag that named what to act on is a mistake, most
// often an unset shell variable, and must not be read as "the flag was not
// given": that reading started a hub on the -data directory instead of
// reporting that nothing was named. The action flags are subcommands now
// (core G12), and a removed flag is answered as removed whatever its value,
// before anything is opened.
func TestAnActionFlagGivenAnEmptyValueIsStillRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never")
	for _, c := range []struct {
		args []string
		key  string
		vars map[string]string
	}{
		{[]string{"-clear", ""}, "hub_flag_removed", map[string]string{"flag": "-clear", "subcommand": "clear"}},
		{[]string{"-repair-ledger", ""}, "hub_flag_removed.none", map[string]string{"flag": "-repair-ledger"}},
		{[]string{"-payee", "", "-peer-endpoint", ""}, "hub_flag_removed", map[string]string{"flag": "-payee", "subcommand": "clear"}},
	} {
		r := cli(t, "en", append([]string{"-data", dir}, c.args...)...)
		if r.served {
			t.Errorf("%v started a hub", c.args)
		}
		expectErr(t, r, 2, sentenceOf("en", c.key, c.vars))
	}
}

// A plain start goes on to serve: no removed flag, no subcommand.
func TestOrdinaryStartupsServe(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-addr", ":8088", "-data", "/srv/hub"},
		{"-addr", ":0", "-public-url", "https://hub.example.org", "-relay-ttl", "24h"},
	} {
		if r := cli(t, "en", args...); !r.served || r.code != 0 || r.stderr != "" || r.stdout != "" {
			t.Errorf("%v: %+v, want it to go on to serve", args, r)
		}
	}
}
