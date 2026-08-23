package aghub

import (
	"database/sql"
	"fmt"
	"time"
)

// Whether an agent is still collecting its mail.
//
// `anet hub-leave` made moving clean. It did nothing for dying, and the
// hole is the same one: a node whose machine was shut down, whose process
// was killed, whose operator wandered off, stays in the directory and
// stays deliverable-to. Work addressed to it is accepted, queued, and
// waits for a poll that is never coming. Nothing errors. The requester
// waits.
//
// The signal is the poll. Not the registration, which is a claim made
// once and never re-examined; not a heartbeat endpoint, which is a second
// thing that can be true while the first is false. A node that collects
// its mail is a node that will do the work — that is the only liveness
// this hub actually cares about, and it is already happening, so nothing
// new has to be built for a node to prove it.
//
// What this deliberately does NOT do is delete anything. A network hiccup
// is not a deregistration, and a hub that evicted agents for going quiet
// would turn every outage into a mass unregistration — with every agent's
// reviews and balance orphaned behind it. Quiet is a fact that gets
// reported, not a sentence that gets carried out. Leaving stays the
// agent's own signed act.

// QuietAfter is how long without collecting mail before an agent is
// reported as quiet.
//
// An hour, which is generous against the five-second default poll: a node
// that has not asked for its mail in seven hundred poll intervals is not
// having a bad minute. Short enough that a requester finds out before
// waiting all day for an answer.
const QuietAfter = time.Hour

// AbandonedAfter is how long before an agent stops being listed by
// default.
//
// Thirty days, and the gap between this and QuietAfter is the point.
// Quiet is worth telling a caller about; absent for a month is worth
// keeping out of a directory people browse. Still not deleted — the row,
// the reviews and the balance stay, so an operator who comes back after a
// long holiday finds their agent where they left it and one poll away
// from being listed again.
const AbandonedAfter = 30 * 24 * time.Hour

// SeenPolling records that an agent collected its mail.
//
// Best-effort on purpose: a failure here must never fail the poll. The
// agent is doing exactly the right thing and refusing to hand over its
// mail because we could not write a timestamp would be an absurd trade.
func (s *Store) SeenPolling(aid string) {
	if _, err := s.db.Exec(
		`UPDATE agent SET last_seen_at=? WHERE aid=?`,
		time.Now().UTC().Format(time.RFC3339Nano), aid); err != nil {
		// Not logged: a poll happens every few seconds per agent, and a
		// broken column would produce a line per poll per agent. The
		// symptom an operator would see is every agent reported quiet,
		// which is loud enough.
		_ = err
	}
}

// Liveness is what this hub knows about an agent still being there.
type Liveness struct {
	// LastSeen is when it last collected its mail, RFC3339. Empty means
	// never since this was recorded — which includes every agent that
	// registered before the column existed, and is why empty must read as
	// "unknown" rather than "dead".
	LastSeen string `json:"last_seen,omitempty"`
	// Quiet is true when nothing has been collected for QuietAfter.
	Quiet bool `json:"quiet,omitempty"`
	// QuietFor is how long, human-readable, when Quiet.
	QuietFor string `json:"quiet_for,omitempty"`
}

// LivenessOf reports whether an agent is still collecting.
func (s *Store) LivenessOf(aid string) (Liveness, error) {
	var seen sql.NullString
	err := s.db.QueryRow(`SELECT last_seen_at FROM agent WHERE aid=?`, aid).Scan(&seen)
	if err == sql.ErrNoRows {
		return Liveness{}, fmt.Errorf("hub: %s is not registered here", aid)
	}
	if err != nil {
		return Liveness{}, err
	}
	return livenessFrom(seen.String, time.Now()), nil
}

// livenessFrom is the arithmetic, separated so it can be tested without a
// database and without waiting an hour.
func livenessFrom(lastSeen string, now time.Time) Liveness {
	if lastSeen == "" {
		// Unknown, not dead. An agent that registered before this hub
		// recorded polls has no timestamp, and reporting it quiet would
		// be this hub asserting something it does not know.
		return Liveness{}
	}
	t, err := time.Parse(time.RFC3339Nano, lastSeen)
	if err != nil {
		return Liveness{LastSeen: lastSeen}
	}
	out := Liveness{LastSeen: t.UTC().Format(time.RFC3339)}
	if d := now.Sub(t); d > QuietAfter {
		out.Quiet = true
		out.QuietFor = roundDuration(d)
	}
	return out
}

// roundDuration renders a gap the way a person reads it.
func roundDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
}

// SetLastSeenForTest backdates an agent's last poll.
//
// Exported for tests, which otherwise could only exercise the quiet and
// abandoned paths by waiting an hour and a month. Named so nobody
// mistakes it for something the hub does on its own.
func (s *Store) SetLastSeenForTest(aid string, when time.Time) error {
	_, err := s.db.Exec(`UPDATE agent SET last_seen_at=? WHERE aid=?`,
		when.UTC().Format(time.RFC3339Nano), aid)
	return err
}
