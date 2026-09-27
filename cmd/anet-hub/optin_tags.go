package main

import "strings"

// optInMounts are the hub modules that are built only with an additive
// tag (-tags <name>) rather than removed with a subtractive one
// (-tags no_<name>).
//
// No build tag on this file, on purpose. A subtracted module is silent
// because it was removed; an opt-in module is silent because it was never
// added, and the two silences send an operator to different flags. The
// names therefore have to survive in a build that has none of the code, so
// the startup log can say which opt-in modules this build lacks.
//
// taskboard is opt-in because a board stores caller-supplied titles and
// notes and serves them to anyone (A2A-DESIGN §2 row taskboard).
var optInMounts = []string{"taskboard"}

// notBuilt lists the opt-in modules missing from wired, space-prefixed,
// or " none".
func notBuilt(wired []string) string {
	have := map[string]bool{}
	for _, w := range wired {
		have[w] = true
	}
	var out []string
	for _, o := range optInMounts {
		if !have[o] {
			out = append(out, o)
		}
	}
	if len(out) == 0 {
		return " none"
	}
	return " " + strings.Join(out, " ")
}
