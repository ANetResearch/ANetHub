// Package version is the single source of truth for the anet release
// version, shared by both binaries (anet and anet-hub) so they always
// report the same number.
package version

// V is the current anet release version.
//
// Hand-maintained, and therefore says nothing about which build is
// running: every binary cut between two releases reports the same string.
// That is fine for "which release is this" and useless for "is the thing
// I just deployed the thing that is running", which is the question that
// actually comes up.
//
// 0.2.0 is the first hub release that speaks hub wire 2 (aghub.WireVersion):
// the relay carries only sealed envelopes, every signed endpoint uses
// relayauth v2, and nodes older than anet 0.2.0 are refused with 426
// (A2A-DESIGN §3.7, §18). It ships together with anet 0.2.0, which is why
// the two numbers are the same. The first start of a 0.2.0 hub on a
// wire-1 database migrates it irreversibly: see ANet docs/notes/0027 for
// the upgrade procedure.
//
// 0.2.1 is a patch release of the same wire (ANet docs/RELEASE-NOTES-0.2.1.md):
// hub.db transactions take the write lock when they begin, so a relay write
// no longer fails "database is locked" under concurrent polls, and the
// federation dedupe window is pruned through an index. It still requires anet
// >= 0.2.0 (RequiredAnet); nodes and hubs of 0.2.0 and 0.2.1 interoperate.
const V = "0.2.1"

// Commit and BuiltAt are stamped at build time:
//
//	go build -ldflags "-X <this package>.Commit=$(git rev-parse --short HEAD) \
//	                   -X <this package>.BuiltAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// Unstamped builds report "unknown" rather than a plausible-looking
// default. A wrong commit is worse than an absent one: it would let a
// check comparing versions pass while comparing two fabrications.
var (
	Commit  = "unknown"
	BuiltAt = "unknown"
)

// Full is the version as a service reports it.
func Full() map[string]string {
	return map[string]string{
		"version":  V,
		"commit":   Commit,
		"built_at": BuiltAt,
	}
}
